const express = require('express');
const cors = require('cors');
const path = require('node:path');
const fs = require('node:fs');
const { config, validateConfig, getSanitizedConfig, safeTimingCompare } = require('./config');
const {
    generateLicenseKey,
    hashKey,
    getKeyLast4,
    isValidKeyFormat,
    verifyPassword,
    generateToken,
    RateLimiter
} = require('./auth');
const db = require('./db');

const app = express();
const PORT = config.port;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Rate limiters
const activateLimiter = new RateLimiter(30, 60 * 1000); // 30 req/min
const adminLoginLimiter = new RateLimiter(15, 60 * 1000); // 15 req/min

function getClientIp(req) {
    return req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
}

// Admin Auth Middleware
async function requireAdmin(req, res, next) {
    const authHeader = req.headers.authorization;
    let token = null;

    if (authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.substring(7).trim();
    } else if (req.headers['x-admin-token']) {
        token = String(req.headers['x-admin-token']).trim();
    }

    if (!token) {
        return res.status(401).json({ success: false, error: 'UNAUTHORIZED', message: 'Missing authentication token.' });
    }

    const session = await db.getAdminSession(token);
    if (!session) {
        return res.status(401).json({ success: false, error: 'SESSION_EXPIRED', message: 'Session expired or invalid.' });
    }

    req.admin = session;
    next();
}

// -------------------------------------------------------------
// Real-Time Server-Sent Events (SSE) Engine
// -------------------------------------------------------------
const sseClients = new Set();

function broadcastAdminEvent(eventType, payload = {}) {
    const dataString = `data: ${JSON.stringify({ type: eventType, payload, timestamp: new Date().toISOString() })}\n\n`;
    for (const client of sseClients) {
        try {
            client.res.write(dataString);
        } catch (err) {
            sseClients.delete(client);
        }
    }
}

// Keepalive heartbeat for SSE proxies
setInterval(() => {
    for (const client of sseClients) {
        try {
            client.res.write(':keepalive\n\n');
        } catch (err) {
            sseClients.delete(client);
        }
    }
}, 15000).unref();

app.get('/api/admin/events', async (req, res) => {
    let token = req.query.token;
    if (!token && req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
        token = req.headers.authorization.slice(7).trim();
    }
    const session = token ? await db.getAdminSession(token) : null;
    if (!session) {
        return res.status(401).json({ success: false, message: 'Unauthorized' });
    }

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    if (typeof res.flushHeaders === 'function') res.flushHeaders();

    const client = { id: Date.now() + Math.random(), res, adminId: session.admin_id };
    sseClients.add(client);

    res.write(`data: ${JSON.stringify({ type: 'CONNECTED', message: 'SSE Stream active' })}\n\n`);

    req.on('close', () => {
        sseClients.delete(client);
    });
});

// -------------------------------------------------------------
// System & Health Endpoints
// -------------------------------------------------------------
app.get('/api/health', (req, res) => {
    res.json({
        status: 'ok',
        service: 'Zexora License Authority',
        developedBy: 'MADARA FF',
        copyright: '© Developed by MADARA FF',
        serverTime: new Date().toISOString()
    });
});

// -------------------------------------------------------------
// Admin Authentication Endpoints
// -------------------------------------------------------------

// Admin Initial Setup or Reset
// Allows setting up initial admin credentials if no admins exist or with setup key
async function handleAdminSetup(req, res) {
    try {
        const { username = 'admin', password = 'admin123', email = 'admin@rootoptimizer.com', secret } = req.body;
        const existingAdmin = await db.getAdminByUsername(username);

        // Allow setup if no admin exists, or if valid ADMIN_SECRET is provided
        const requiredSecret = config.adminSecret;
        if (existingAdmin && (!secret || !safeTimingCompare(secret, requiredSecret))) {
            return res.status(403).json({
                success: false,
                message: 'Admin account already exists. Please log in with your credentials.'
            });
        }

        if (existingAdmin) {
            await db.updateAdminPassword(existingAdmin.id, password);
            return res.json({
                success: true,
                message: `Admin account "${username}" password updated successfully.`
            });
        } else {
            await db.createAdmin(username, password, email, 'superadmin');
            return res.json({
                success: true,
                message: `Admin account "${username}" initialized successfully.`
            });
        }
    } catch (err) {
        console.error('Admin setup error:', err);
        res.status(500).json({ success: false, message: 'Failed to complete admin setup: ' + err.message });
    }
}
app.post('/api/auth/admin/setup', handleAdminSetup);
app.post('/api/admin/setup', handleAdminSetup);

// Admin Login
async function handleAdminLogin(req, res) {
    const ip = getClientIp(req);
    if (adminLoginLimiter.isRateLimited(ip)) {
        return res.status(429).json({ success: false, error: 'RATE_LIMITED', message: 'Too many login attempts. Please wait.' });
    }

    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Username and password required.' });
    }

    try {
        const admin = await db.getAdminByUsername(username);
        if (!admin || !verifyPassword(password, admin.salt, admin.password_hash)) {
            await db.logAuditEvent('ADMIN_LOGIN_FAILED', { username }, ip);
            return res.status(401).json({ success: false, message: 'Invalid admin credentials.' });
        }

        const token = generateToken();
        const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days session
        await db.createAdminSession(admin.id, token, expiresAt);
        await db.logAuditEvent('ADMIN_LOGIN_SUCCESS', { username }, ip);

        res.json({
            success: true,
            token,
            admin: {
                id: admin.id,
                username: admin.username,
                email: admin.email,
                role: admin.role
            },
            expires_at: expiresAt.toISOString()
        });
    } catch (err) {
        console.error('Admin login error:', err);
        res.status(500).json({ success: false, message: 'Server error during login: ' + err.message });
    }
}
app.post('/api/auth/admin/login', handleAdminLogin);
app.post('/api/admin/login', handleAdminLogin);

// Current Admin Info
app.get('/api/auth/admin/me', requireAdmin, (req, res) => {
    res.json({
        success: true,
        admin: {
            id: req.admin.admin_id,
            username: req.admin.username,
            email: req.admin.email,
            role: req.admin.role
        }
    });
});

// Admin Logout
async function handleAdminLogout(req, res) {
    const authHeader = req.headers.authorization;
    const token = authHeader?.startsWith('Bearer ') ? authHeader.substring(7) : req.headers['x-admin-token'];
    if (token) {
        await db.deleteAdminSession(token);
    }
    res.json({ success: true, message: 'Logged out successfully.' });
}
app.post('/api/auth/admin/logout', handleAdminLogout);
app.post('/api/admin/logout', handleAdminLogout);

// -------------------------------------------------------------
// Products
// -------------------------------------------------------------
app.get('/api/products', requireAdmin, async (req, res) => {
    try {
        const products = await db.getAllProducts();
        res.json({ success: true, products });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.post('/api/products', requireAdmin, async (req, res) => {
    try {
        const { name, description } = req.body;
        if (!name) return res.status(400).json({ success: false, message: 'Product name required' });
        const product = await db.getOrCreateProduct(name, description);
        res.json({ success: true, product });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// -------------------------------------------------------------
// Dashboard Statistics
// -------------------------------------------------------------
async function handleDashboardStats(req, res) {
    try {
        const stats = await db.getDashboardStats();
        res.json({ success: true, stats });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
}
app.get('/api/dashboard/stats', requireAdmin, handleDashboardStats);
app.get('/api/admin/stats', requireAdmin, handleDashboardStats);

// -------------------------------------------------------------
// Key Management Endpoints
// -------------------------------------------------------------

// Generate new activation key(s)
async function handleKeyGeneration(req, res) {
    const ip = getClientIp(req);
    const {
        product_name = 'Zexora',
        duration_hours = null,
        duration_days = null,
        max_devices = 1,
        customer_name = null,
        notes = '',
        count = 1,
        prefix = 'MADARA-FF'
    } = req.body;

    try {
        // Calculate duration in hours: ONLY 1h (1), 1d (24), 7d (168), 30d (720) are allowed
        let effectiveHours = 720; // default 30 days
        if (duration_hours !== null && duration_hours !== undefined) {
            effectiveHours = parseInt(duration_hours, 10);
        } else if (duration_days !== null && duration_days !== undefined) {
            const d = parseInt(duration_days, 10);
            effectiveHours = d === 1 ? 24 : d === 7 ? 168 : d === 30 ? 720 : d * 24;
        }

        const ALLOWED_DURATIONS = [1, 24, 168, 720];
        if (!ALLOWED_DURATIONS.includes(effectiveHours)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid duration. Only 1h (1 hour), 1d (24 hours), 7d (7 days), and 30d (30 days) keys can be generated.'
            });
        }

        const product = await db.getOrCreateProduct(product_name);
        const generatedKeys = [];
        const limitCount = Math.min(Math.max(parseInt(count, 10) || 1, 1), 50);

        for (let i = 0; i < limitCount; i++) {
            let rawKey = generateLicenseKey(prefix || 'MADARA-FF');
            let attempts = 0;
            while (attempts < 5 && ((await db.getKeyByIdOrString(rawKey)) || (await db.isKeyDeleted(hashKey(rawKey))))) {
                rawKey = generateLicenseKey(prefix || 'MADARA-FF');
                attempts++;
            }

            const keyRecord = await db.createActivationKey({
                keyString: rawKey,
                productId: product.id,
                durationHours: effectiveHours,
                maxDevices: parseInt(max_devices, 10) || 1,
                customerName: customer_name,
                notes: notes
            });

            generatedKeys.push({
                id: keyRecord.id,
                key: rawKey,
                product: product.name,
                duration_hours: effectiveHours,
                is_permanent: effectiveHours === -1,
                created_at: keyRecord.created_at,
                expires_at: keyRecord.expires_at,
                status: 'UNUSED',
                max_devices: keyRecord.max_devices,
                customer_name: keyRecord.customer_name,
                notes: keyRecord.notes
            });
        }

        await db.logAuditEvent('KEYS_GENERATED', { count: limitCount, product: product.name, duration_hours: effectiveHours }, ip);
        broadcastAdminEvent('KEY_CREATED', { count: limitCount, keys: generatedKeys });

        if (limitCount === 1) {
            res.json({
                success: true,
                message: 'Key generated successfully',
                ...generatedKeys[0]
            });
        } else {
            res.json({
                success: true,
                message: `${limitCount} keys generated successfully`,
                keys: generatedKeys
            });
        }
    } catch (err) {
        console.error('Key generation error:', err);
        res.status(500).json({ success: false, message: 'Failed to generate key: ' + err.message });
    }
}
app.post('/api/keys/generate', requireAdmin, handleKeyGeneration);
app.post('/api/admin/licenses/generate', requireAdmin, handleKeyGeneration);

// Bulk import / Sync keys
app.post('/api/keys/import', requireAdmin, async (req, res) => {
    try {
        const { keys = [] } = req.body;
        if (!Array.isArray(keys) || keys.length === 0) {
            return res.json({ success: true, message: 'No keys to import', count: 0 });
        }
        const imported = await db.importSeedKeys(keys);
        res.json({ success: true, message: `Successfully imported / synchronized ${imported} keys`, count: imported });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// Helper: Forward key deletion to Cloud Server immediately (development only)
async function deleteKeyFromCloud(keyIdentifier) {
    if (config.isRender || !config.autoSyncCloud) return;
    try {
        const cloudUrl = config.cloudServerUrl;
        const adminUser = config.adminUsername;
        const adminPass = config.adminPassword;
        
        const loginRes = await fetch(`${cloudUrl}/api/auth/admin/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: adminUser, password: adminPass })
        });
        const loginData = await loginRes.json();
        if (!loginData.success || !loginData.token) return;

        let targetId = keyIdentifier;
        if (typeof keyIdentifier === 'string' && keyIdentifier.startsWith('MADARA-FF')) {
            const listRes = await fetch(`${cloudUrl}/api/keys?search=${encodeURIComponent(keyIdentifier)}`, {
                headers: { 'Authorization': `Bearer ${loginData.token}` }
            });
            const listData = await listRes.json();
            if (listData.keys && listData.keys.length > 0) {
                const found = listData.keys.find(k => k.key_display === keyIdentifier);
                if (found) targetId = found.id;
            }
        }

        const delRes = await fetch(`${cloudUrl}/api/keys/${targetId}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${loginData.token}` }
        });
        const delData = await delRes.json();
        console.log(`[SYNC] Forwarded deletion of key ${keyIdentifier} to cloud:`, delData.message || delRes.status);
    } catch (e) {
        console.warn(`[SYNC] Failed to forward deletion of ${keyIdentifier} to cloud:`, e.message);
    }
}

// Helper: Forward key edit / update to Cloud Server immediately (development only)
async function updateKeyOnCloud(keyIdentifier, updatePayload) {
    if (config.isRender || !config.autoSyncCloud) return;
    try {
        const cloudUrl = config.cloudServerUrl;
        const adminUser = config.adminUsername;
        const adminPass = config.adminPassword;
        
        const loginRes = await fetch(`${cloudUrl}/api/auth/admin/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: adminUser, password: adminPass })
        });
        const loginData = await loginRes.json();
        if (!loginData.success || !loginData.token) return;

        let targetId = keyIdentifier;
        if (typeof keyIdentifier === 'string' && keyIdentifier.startsWith('MADARA-FF')) {
            const listRes = await fetch(`${cloudUrl}/api/keys?search=${encodeURIComponent(keyIdentifier)}`, {
                headers: { 'Authorization': `Bearer ${loginData.token}` }
            });
            const listData = await listRes.json();
            if (listData.keys && listData.keys.length > 0) {
                const found = listData.keys.find(k => k.key_display === keyIdentifier);
                if (found) targetId = found.id;
            }
        }

        const patchRes = await fetch(`${cloudUrl}/api/keys/${targetId}`, {
            method: 'PATCH',
            headers: {
                'Authorization': `Bearer ${loginData.token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(updatePayload)
        });
        const patchData = await patchRes.json();
        console.log(`[SYNC] Forwarded update of key ${keyIdentifier} to cloud:`, patchData.message || patchRes.status);
    } catch (e) {
        console.warn(`[SYNC] Failed to forward update of ${keyIdentifier} to cloud:`, e.message);
    }
}

// Cloud Synchronization
async function syncWithCloudServer() {
    if (config.isRender) {
        return { success: true, message: 'Running on Render Cloud; external sync skipped.' };
    }
    const cloudUrl = config.cloudServerUrl;
    const adminUser = config.adminUsername;
    const adminPass = config.adminPassword;

    // Step 1: Login to Cloud Server
    const loginRes = await fetch(`${cloudUrl}/api/auth/admin/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: adminUser, password: adminPass })
    });
    const loginData = await loginRes.json();
    if (!loginData.success || !loginData.token) {
        throw new Error(loginData.message || 'Cloud authentication failed');
    }

    const cloudToken = loginData.token;

    // Step 2: Fetch remote keys from Cloud Server
    const cloudKeysRes = await fetch(`${cloudUrl}/api/keys?limit=250`, {
        headers: { 'Authorization': `Bearer ${cloudToken}` }
    });
    const cloudKeysData = await cloudKeysRes.json();
    let importedLocally = 0;
    let purgedFromCloud = 0;

    // Step 3: Purge any locally deleted keys from Cloud Server
    const localDeleted = await db.getAllDeletedKeys();
    const localDeletedHashes = new Set(localDeleted.map(d => d.key_hash));
    const localDeletedDisplays = new Set(localDeleted.filter(d => d.key_display).map(d => d.key_display.trim().toUpperCase()));

    if (cloudKeysData.success && Array.isArray(cloudKeysData.keys)) {
        const remainingCloudKeys = [];
        for (const ck of cloudKeysData.keys) {
            const ckDisplay = (ck.key_display || '').trim().toUpperCase();
            const ckHash = ck.key_hash || hashKey(ckDisplay);
            if (localDeletedHashes.has(ckHash) || localDeletedDisplays.has(ckDisplay)) {
                // Key is deleted locally - delete from Cloud as well!
                try {
                    await fetch(`${cloudUrl}/api/keys/${ck.id}`, {
                        method: 'DELETE',
                        headers: { 'Authorization': `Bearer ${cloudToken}` }
                    });
                    purgedFromCloud++;
                    console.log(`[SYNC] Purged deleted key from cloud: ${ckDisplay} (ID ${ck.id})`);
                } catch (delErr) {
                    console.warn(`[SYNC] Failed to delete key ${ck.id} from cloud:`, delErr.message);
                }
            } else {
                remainingCloudKeys.push(ck);
            }
        }

        // Try to fetch remote deleted keys from Cloud Server (if endpoint exists)
        try {
            const remoteDeletedRes = await fetch(`${cloudUrl}/api/admin/deleted-keys`, {
                headers: { 'Authorization': `Bearer ${cloudToken}` }
            });
            if (remoteDeletedRes.ok) {
                const remoteDeletedData = await remoteDeletedRes.json();
                if (remoteDeletedData.success && Array.isArray(remoteDeletedData.deletedKeys)) {
                    for (const rk of remoteDeletedData.deletedKeys) {
                        const rkHash = rk.key_hash;
                        const rkDisplay = rk.key_display;
                        if (!(await db.isKeyDeleted(rkHash))) {
                            await db.deleteKey(rkDisplay || rkHash, 'cloud-sync', 'Synced deletion from cloud');
                        }
                    }
                }
            }
        } catch (e) {
            // Cloud endpoint might not exist yet on older deployed build
        }

        // Import active/valid keys from Cloud to local database
        if (remainingCloudKeys.length > 0) {
            importedLocally = await db.importSeedKeys(remainingCloudKeys);
        }
    }

    // Step 4: Export local valid keys and sync to Cloud Server
    const localSeedKeys = await db.exportSeedKeys();
    const pushRes = await fetch(`${cloudUrl}/api/keys/import`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${cloudToken}`
        },
        body: JSON.stringify({ keys: localSeedKeys })
    });
    const pushData = await pushRes.json();

    return {
        success: true,
        message: 'Bidirectional Cloud Synchronization Successful',
        cloudUrl,
        importedLocally,
        purgedFromCloud,
        pushedToCloud: pushData.count || localSeedKeys.length
    };
}

app.post('/api/admin/sync-cloud', requireAdmin, async (req, res) => {
    try {
        const result = await syncWithCloudServer();
        await db.logAuditEvent('CLOUD_SYNC_TRIGGERED', result, getClientIp(req));
        res.json(result);
    } catch (err) {
        console.error('Cloud sync error:', err.message);
        res.status(500).json({ success: false, message: 'Cloud sync failed: ' + err.message });
    }
});

app.get('/api/admin/deleted-keys', requireAdmin, async (req, res) => {
    try {
        const deletedKeys = await db.getAllDeletedKeys();
        res.json({ success: true, deletedKeys });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// List keys with search and filter
async function handleListKeys(req, res) {
    try {
        const search = req.query.search || '';
        const status = req.query.status || 'ALL';
        const limit = parseInt(req.query.limit, 10) || 150;

        const keys = await db.getAllKeys({ search, status, limit });
        res.json({ success: true, keys });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
}
app.get('/api/keys', requireAdmin, handleListKeys);
app.get('/api/admin/licenses', requireAdmin, handleListKeys);

// Get single key details & activations
app.get('/api/keys/:id', requireAdmin, async (req, res) => {
    try {
        const key = await db.getKeyByIdOrString(req.params.id);
        if (!key) return res.status(404).json({ success: false, message: 'Key not found' });
        const activations = await db.getKeyActivations(key.id);
        res.json({ success: true, key, activations });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// Update / Edit key (key code, status, duration, expiry, customer name, max devices, notes)
async function handleUpdateKey(req, res) {
    try {
        const key = await db.getKeyByIdOrString(req.params.id);
        if (!key) return res.status(404).json({ success: false, message: 'Key not found' });
        const {
            notes,
            customer_name, customerName,
            max_devices, maxDevices,
            status,
            key_display, keyDisplay, key: newKeyStr,
            duration_hours, durationHours,
            expires_at, expiresAt,
            activated_at, activatedAt
        } = req.body;

        const rawDuration = duration_hours !== undefined ? duration_hours : durationHours;
        let finalDuration = undefined;
        if (rawDuration !== undefined && rawDuration !== null) {
            finalDuration = parseInt(rawDuration, 10);
            const ALLOWED_DURATIONS = [-1, 1, 24, 168, 720];
            if (!ALLOWED_DURATIONS.includes(finalDuration)) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid duration. Only 1h (1 hour), 1d (24 hours), 7d (7 days), 30d (30 days), and Lifetime (-1) are allowed.'
                });
            }
        }
        const updated = await db.updateKeyDetails(key.id, {
            notes,
            customerName: customer_name !== undefined ? customer_name : customerName,
            maxDevices: max_devices !== undefined ? max_devices : maxDevices,
            status,
            keyDisplay: key_display || keyDisplay || newKeyStr,
            durationHours: finalDuration,
            expiresAt: expires_at !== undefined ? expires_at : expiresAt,
            activatedAt: activated_at !== undefined ? activated_at : activatedAt
        });
        await db.logAuditEvent('KEY_UPDATED', { key_id: key.id, key_display: updated ? updated.key_display : key.key_display, changes: req.body }, getClientIp(req));
        broadcastAdminEvent('KEY_UPDATED', { key: updated });

        // Sync with Render Cloud if running in local environment
        if (!process.env.RENDER) {
            updateKeyOnCloud(updated ? (updated.key_display || updated.id) : key.id, req.body).catch(() => {});
        }

        res.json({ success: true, message: 'Key updated successfully on server', key: updated });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
}
app.patch('/api/keys/:id', requireAdmin, handleUpdateKey);
app.put('/api/keys/:id', requireAdmin, handleUpdateKey);

// Extend key expiry
async function handleExtendKey(req, res) {
    try {
        const id = req.params.id;
        const { extension_hours = 24, hours, days } = req.body;
        let extHours = 24;
        if (hours !== undefined) extHours = parseInt(hours, 10);
        else if (days !== undefined) extHours = parseInt(days, 10) * 24;
        else if (extension_hours !== undefined) extHours = parseInt(extension_hours, 10);

        if (isNaN(extHours) || extHours <= 0) {
            return res.status(400).json({ success: false, message: 'Invalid extension hours' });
        }

        const key = await db.getKeyByIdOrString(id);
        if (!key) return res.status(404).json({ success: false, message: 'Key not found' });
        if (key.status === 'REVOKED') {
            return res.status(400).json({ success: false, message: 'Revoked keys cannot be extended. Generate a new key if access is needed.' });
        }

        const updated = await db.extendKeyExpiry(key.id, extHours);
        await db.logAuditEvent('KEY_EXPIRY_EXTENDED', { key_id: key.id, extension_hours: extHours, new_expires_at: updated.expires_at }, getClientIp(req));
        broadcastAdminEvent('KEY_EXTENDED', { key: updated });

        res.json({ success: true, message: `Key validity extended by ${extHours} hours`, key: updated });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
}
app.post('/api/keys/:id/extend', requireAdmin, handleExtendKey);

// Revoke key
app.post('/api/keys/:id/revoke', requireAdmin, async (req, res) => {
    try {
        const key = await db.getKeyByIdOrString(req.params.id);
        if (!key) return res.status(404).json({ success: false, message: 'Key not found' });
        const updated = await db.updateKeyStatus(key.id, 'REVOKED');
        await db.logAuditEvent('KEY_REVOKED', { key_id: key.id, key_display: key.key_display }, getClientIp(req));
        broadcastAdminEvent('KEY_REVOKED', { key: updated });
        res.json({ success: true, message: 'Key revoked successfully', key: updated });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// Suspend / Pause key
async function handleSuspendKey(req, res) {
    try {
        const key = await db.getKeyByIdOrString(req.params.id);
        if (!key) return res.status(404).json({ success: false, message: 'Key not found' });
        if (key.status === 'REVOKED') {
            return res.status(400).json({ success: false, message: 'Revoked key cannot be paused' });
        }
        const updated = await db.updateKeyStatus(key.id, 'PAUSED');
        await db.logAuditEvent('KEY_PAUSED', { key_id: key.id, key_display: key.key_display }, getClientIp(req));
        broadcastAdminEvent('KEY_PAUSED', { key: updated });
        res.json({ success: true, message: 'Key paused/suspended successfully', key: updated });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
}
app.post('/api/keys/:id/suspend', requireAdmin, handleSuspendKey);
app.post('/api/keys/:id/pause', requireAdmin, handleSuspendKey);

// Reactivate / Resume key
async function handleReactivateKey(req, res) {
    try {
        const key = await db.getKeyByIdOrString(req.params.id);
        if (!key) return res.status(404).json({ success: false, message: 'Key not found' });

        if (key.status === 'REVOKED') {
            return res.status(400).json({ 
                success: false, 
                message: 'A revoked key must never be reactivated; generate a new key if access is needed again.' 
            });
        }
        if (key.status === 'EXPIRED') {
            return res.status(400).json({
                success: false,
                message: 'Expired key cannot be resumed. Please extend key expiry instead.'
            });
        }

        // If it was unused, keep unused; otherwise activate
        const targetStatus = key.activated_at ? 'ACTIVE' : 'UNUSED';
        const updated = await db.updateKeyStatus(key.id, targetStatus);
        await db.logAuditEvent('KEY_REACTIVATED', { key_id: key.id, key_display: key.key_display }, getClientIp(req));
        broadcastAdminEvent('KEY_RESUMED', { key: updated });
        res.json({ success: true, message: 'Key resumed/reactivated successfully', key: updated });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
}
app.post('/api/keys/:id/reactivate', requireAdmin, handleReactivateKey);
app.post('/api/keys/:id/resume', requireAdmin, handleReactivateKey);

// Delete key
async function handleDeleteKey(req, res) {
    try {
        const id = req.params.id || req.params.keyId;
        if (id === 'all' || id === 'ALL') {
            const count = await db.clearAllKeys();
            await db.logAuditEvent('ALL_KEYS_PURGED', { count }, getClientIp(req));
            broadcastAdminEvent('KEYS_PURGED', { count });
            return res.json({ success: true, message: `Successfully purged all ${count} keys from server`, count });
        }
        const key = await db.getKeyByIdOrString(id);
        if (!key) return res.status(404).json({ success: false, message: 'Key not found or already deleted' });
        
        const adminUsername = req.admin?.username || 'admin';
        await db.deleteKey(key.id, adminUsername);
        await db.logAuditEvent('KEY_DELETED', { 
            key_id: key.id, 
            key_display: key.key_display, 
            customer_name: key.customer_name,
            deleted_by: adminUsername 
        }, getClientIp(req));
        
        broadcastAdminEvent('KEY_DELETED', { id: key.id });

        // Propagate deletion to Cloud Server immediately
        deleteKeyFromCloud(key.key_display || key.id).catch(err => {
            console.warn('[SYNC] Cloud delete forward deferred:', err.message);
        });

        res.json({ 
            success: true, 
            message: 'Key deleted successfully. Associated customer sessions have been revoked.',
            key_id: key.id 
        });
    } catch (err) {
        console.error('Key deletion error:', err);
        res.status(500).json({ success: false, message: 'Failed to delete key: ' + err.message });
    }
}
app.delete('/api/keys/:id', requireAdmin, handleDeleteKey);
app.delete('/api/admin/keys/:id', requireAdmin, handleDeleteKey);
app.delete('/api/admin/keys/:keyId', requireAdmin, handleDeleteKey);
app.post('/api/keys/:id/delete', requireAdmin, handleDeleteKey);
app.post('/api/admin/keys/:id/delete', requireAdmin, handleDeleteKey);

// Clear all expired keys
app.post('/api/keys/clear-expired', requireAdmin, async (req, res) => {
    try {
        const count = await db.clearExpiredKeys();
        await db.logAuditEvent('EXPIRED_KEYS_CLEARED', { count }, getClientIp(req));
        res.json({ success: true, message: `Successfully cleared ${count} expired keys`, count });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// Purge / Remove all keys & sessions
async function handleClearAllKeys(req, res) {
    try {
        const count = await db.clearAllKeys();
        await db.logAuditEvent('ALL_KEYS_PURGED', { count }, getClientIp(req));

        // Also purge remote keys on Render Cloud if in development and auto-sync is explicitly enabled
        if (!config.isRender && config.autoSyncCloud) {
            try {
                const cloudUrl = config.cloudServerUrl;
                const adminUser = config.adminUsername;
                const adminPass = config.adminPassword;
                const loginRes = await fetch(`${cloudUrl}/api/auth/admin/login`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: adminUser, password: adminPass })
                });
                const loginData = await loginRes.json();
                if (loginData.token) {
                    await fetch(`${cloudUrl}/api/keys/clear-all`, {
                        method: 'POST',
                        headers: { 'Authorization': `Bearer ${loginData.token}` }
                    });
                    console.log('[SYNC] Purged all keys and sessions on Render Cloud as well');
                }
            } catch (cloudErr) {
                console.warn('[SYNC] Could not purge remote cloud keys:', cloudErr.message);
            }
        }

        res.json({ success: true, message: `Successfully removed all ${count} keys from server and signed out all sessions`, count });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
}
app.post('/api/keys/clear-all', requireAdmin, handleClearAllKeys);
app.delete('/api/keys', requireAdmin, handleClearAllKeys);

// Clear / Delete all active keys and terminate connected active apps
async function handleClearActiveKeys(req, res) {
    try {
        const count = await db.deleteActiveKeys('admin', 'Revoked and cleared by Administrator');
        await db.logAuditEvent('ACTIVE_KEYS_DELETED', { count }, getClientIp(req));

        if (!config.isRender && config.autoSyncCloud) {
            try {
                const cloudUrl = config.cloudServerUrl;
                const adminUser = config.adminUsername;
                const adminPass = config.adminPassword;
                const loginRes = await fetch(`${cloudUrl}/api/auth/admin/login`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: adminUser, password: adminPass })
                });
                const loginData = await loginRes.json();
                if (loginData.token) {
                    await fetch(`${cloudUrl}/api/keys/clear-active`, {
                        method: 'POST',
                        headers: { 'Authorization': `Bearer ${loginData.token}` }
                    });
                    console.log('[SYNC] Purged active keys on Render Cloud as well');
                }
            } catch (cloudErr) {
                console.warn('[SYNC] Could not purge active keys on Render Cloud:', cloudErr.message);
            }
        }

        res.json({ success: true, message: `Successfully deleted ${count} active keys and revoked active app sessions`, count });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
}
app.post('/api/keys/clear-active', requireAdmin, handleClearActiveKeys);
app.delete('/api/keys/active', requireAdmin, handleClearActiveKeys);


// -------------------------------------------------------------
// Customer Activation Flow Endpoints
// -------------------------------------------------------------

// Customer Activate Endpoint
async function handleCustomerActivate(req, res) {
    const ip = getClientIp(req);
    if (activateLimiter.isRateLimited(ip)) {
        return res.status(429).json({
            success: false,
            error: 'RATE_LIMITED',
            message: 'Too many activation attempts. Please wait a moment and try again.'
        });
    }

    const rawKey = req.body.key || req.body.license_key;
    const deviceId = req.body.device_id || req.body.deviceId;
    const deviceModel = req.body.device_model || req.body.deviceModel || 'Android Device';
    const appIdentifier = req.body.app_identifier || 'com.example.rootoptimizer';
    const customerName = req.body.customer_name || null;
    const platform = req.body.platform || 'Android';

    // 1. Validate inputs
    if (!rawKey || !deviceId) {
        return res.status(400).json({
            success: false,
            error: 'MISSING_FIELDS',
            message: 'Activation key and Device ID are required.'
        });
    }

    // 2. Validate key format locally
    const formattedKey = rawKey.trim().toUpperCase();
    if (!isValidKeyFormat(formattedKey)) {
        await db.logAuditEvent('ACTIVATION_REJECTED', { reason: 'Malformed key format', key: formattedKey, device_id: deviceId }, ip);
        return res.status(400).json({
            success: false,
            error: 'INVALID_FORMAT',
            message: 'Invalid activation key'
        });
    }

    try {
        // 3. Server checks whether key exists via SHA-256 hash
        const keyHash = hashKey(formattedKey);

        // Check if key was deleted/revoked by admin
        if (await db.isKeyDeleted(keyHash)) {
            await db.logAuditEvent('ACTIVATION_REJECTED_DELETED_KEY', { key: formattedKey, device_id: deviceId }, ip);
            return res.status(403).json({
                success: false,
                valid: false,
                error: 'KEY_DELETED',
                errorCode: 'KEY_DELETED',
                title: 'Access Revoked',
                message: 'Your activation key has been deleted by the administrator. Your session has been terminated, and access to the Z E X O app has been revoked. Please contact the administrator if you believe this action was taken by mistake.'
            });
        }

        let keyRecord = await db.getKeyByHash(keyHash);

        if (!keyRecord) {
            const allMatch = await db.getAllKeys({ search: formattedKey, limit: 1 });
            if (allMatch && allMatch.length > 0 && allMatch[0].key_display === formattedKey) {
                keyRecord = allMatch[0];
            }
        }

        if (!keyRecord) {
            if (await db.isKeyDeleted(keyHash)) {
                await db.logAuditEvent('ACTIVATION_REJECTED_DELETED_KEY', { key: formattedKey, device_id: deviceId }, ip);
                return res.status(403).json({
                    success: false,
                    valid: false,
                    error: 'KEY_DELETED',
                    errorCode: 'KEY_DELETED',
                    title: 'Access Revoked',
                    message: 'Your activation key has been deleted by the administrator. Your session has been terminated, and access to the Z E X O app has been revoked. Please contact the administrator if you believe this action was taken by mistake.'
                });
            }

            await db.logAuditEvent('ACTIVATION_FAILED', { reason: 'Key not found in key manager', key: formattedKey, device_id: deviceId }, ip);
            return res.status(404).json({
                success: false,
                valid: false,
                error: 'INVALID_KEY',
                errorCode: 'INVALID_KEY',
                message: 'Invalid activation key'
            });
        }

        // 4. Check whether key is revoked
        if (keyRecord.status === 'REVOKED') {
            await db.logAuditEvent('ACTIVATION_FAILED', { reason: 'Key revoked', key: formattedKey, device_id: deviceId }, ip);
            return res.status(403).json({
                success: false,
                valid: false,
                error: 'KEY_REVOKED',
                errorCode: 'KEY_REVOKED',
                title: 'Access Revoked',
                message: 'Your activation key has been deleted by the administrator. Your session has been terminated, and access to the Z E X O app has been revoked. Please contact the administrator if you believe this action was taken by mistake.'
            });
        }

        // 5. Check whether key is suspended / paused
        if (keyRecord.status === 'SUSPENDED' || keyRecord.status === 'PAUSED') {
            await db.logAuditEvent('ACTIVATION_FAILED', { reason: 'Key paused', key: formattedKey, device_id: deviceId }, ip);
            return res.status(403).json({
                success: false,
                valid: false,
                error: 'KEY_PAUSED',
                message: 'Access has been paused by user, contact seller'
            });
        }

        // 6. Check whether key is expired
        if (keyRecord.status === 'EXPIRED') {
            await db.logAuditEvent('ACTIVATION_FAILED', { reason: 'Key expired', key: formattedKey, device_id: deviceId }, ip);
            return res.status(403).json({
                success: false,
                valid: false,
                error: 'KEY_EXPIRED',
                errorCode: 'KEY_EXPIRED',
                message: 'Activation key has expired'
            });
        }
        const now = Date.now();
        if (keyRecord.duration_hours !== -1 && keyRecord.expires_at) {
            const expiryTime = new Date(keyRecord.expires_at).getTime();
            if (now > expiryTime) {
                await db.updateKeyStatus(keyRecord.id, 'EXPIRED');
                await db.logAuditEvent('ACTIVATION_FAILED', { reason: 'Key expired', key: formattedKey, device_id: deviceId }, ip);
                return res.status(403).json({
                    success: false,
                    valid: false,
                    error: 'KEY_EXPIRED',
                    errorCode: 'KEY_EXPIRED',
                    message: 'Activation key has expired'
                });
            }
        }

        // 7. Customer & Device record registration
        const customer = await db.getOrCreateCustomer(keyRecord.customer_name || customerName || `user_${deviceId.slice(0, 8)}`, customerName);
        const device = await db.getOrCreateDevice(customer.id, deviceId, deviceModel, appIdentifier, platform);

        // Check if device is already activated on this key
        let existingActivation = await db.findActivation(keyRecord.id, device.id);
        if (!existingActivation) {
            existingActivation = await db.queryOne(`
                SELECT a.*, d.device_identifier, d.device_model
                FROM activations a
                JOIN devices d ON a.device_id = d.id
                WHERE (a.key_id = ? OR a.license_id = ?) AND d.device_identifier = ?
            `, [keyRecord.id, keyRecord.id, deviceId]);
        }
        const isPermanent = keyRecord.duration_hours === -1;
        if (existingActivation) {
            if (existingActivation.status === 'SUSPENDED' || existingActivation.status === 'PAUSED') {
                return res.status(403).json({ success: false, error: 'KEY_PAUSED', message: 'Access has been paused by user, contact seller' });
            }
            if (existingActivation.status === 'REVOKED') {
                return res.status(403).json({ success: false, error: 'KEY_REVOKED', message: 'Access has been revoked by the administrator' });
            }

            const token = existingActivation.session_token || generateToken();
            await db.updateActivationLastSeen(existingActivation.id, token);
            await db.query("UPDATE activations SET status = 'ACTIVE', is_active = 1 WHERE id = ?", [existingActivation.id]);
            if (keyRecord.status === 'UNUSED') {
                await db.updateKeyStatus(keyRecord.id, 'ACTIVE');
                keyRecord.status = 'ACTIVE';
            }

            let effectiveExpiresAt = keyRecord.expires_at || existingActivation.expires_at;
            let remainingSeconds = -1;
            if (!isPermanent) {
                if (!effectiveExpiresAt && keyRecord.duration_hours > 0) {
                    const actTime = keyRecord.activated_at ? new Date(keyRecord.activated_at).getTime() : now;
                    effectiveExpiresAt = new Date(actTime + keyRecord.duration_hours * 3600 * 1000).toISOString();
                    await db.query("UPDATE activation_keys SET expires_at = ? WHERE id = ?", [effectiveExpiresAt, keyRecord.id]);
                }
                if (effectiveExpiresAt) {
                    remainingSeconds = Math.max(0, Math.floor((new Date(effectiveExpiresAt).getTime() - Date.now()) / 1000));
                }
            } else {
                effectiveExpiresAt = null;
            }

            const effectiveDurationDays = isPermanent ? -1 : Math.max(1, Math.round((keyRecord.duration_hours || 720) / 24));

            return res.json({
                success: true,
                message: 'Activation Successful',
                product: keyRecord.product_name || 'Zexora',
                developer: 'MADARA FF',
                copyright: '© Developed by MADARA FF',
                status: 'ACTIVE',
                activated_at: keyRecord.activated_at || existingActivation.activated_at,
                expires_at: effectiveExpiresAt,
                remaining_seconds: remainingSeconds,
                is_permanent: isPermanent,
                duration_hours: keyRecord.duration_hours,
                session_token: token,
                device_registered: true,
                license: {
                    key: keyRecord.key_display,
                    product: keyRecord.product_name || 'Zexora',
                    developer: 'MADARA FF',
                    status: 'ACTIVE',
                    activated_at: keyRecord.activated_at || existingActivation.activated_at,
                    expires_at: effectiveExpiresAt,
                    remaining_seconds: remainingSeconds,
                    is_permanent: isPermanent,
                    duration_days: effectiveDurationDays,
                    max_activations: keyRecord.max_devices
                }
            });
        }

        // 8. Check device activation limits
        const activeCount = await db.getActiveActivationsCount(keyRecord.id);
        if (activeCount >= keyRecord.max_devices) {
            await db.logAuditEvent('ACTIVATION_FAILED', { reason: 'Device limit reached', key: formattedKey, activeCount, max: keyRecord.max_devices }, ip);
            return res.status(403).json({
                success: false,
                error: 'DEVICE_LIMIT_REACHED',
                message: 'Device activation limit reached'
            });
        }

        // 9. Calculate expiration date on activation:
        // Timer activates ONLY AFTER activated by the user!
        const durationHours = (keyRecord.duration_hours !== undefined && keyRecord.duration_hours !== null) ? keyRecord.duration_hours : 720;
        let finalExpiresAt = null;
        let remainingSeconds = -1;

        if (!isPermanent) {
            const hours = durationHours > 0 ? durationHours : 720;
            if (!keyRecord.expires_at) {
                finalExpiresAt = new Date(now + hours * 60 * 60 * 1000).toISOString();
            } else {
                finalExpiresAt = keyRecord.expires_at;
            }
            remainingSeconds = Math.max(0, Math.floor((new Date(finalExpiresAt).getTime() - now) / 1000));
        }

        const activatedAtIso = keyRecord.activated_at || new Date(now).toISOString();

        // 10. Update key status to ACTIVE and save activation
        const sessionToken = generateToken();
        await db.recordActivation({
            keyId: keyRecord.id,
            customerId: customer.id,
            deviceId: device.id,
            expiresAt: finalExpiresAt,
            sessionToken
        });

        // Set key to ACTIVE and record activated_at and expires_at
        await db.query(`
            UPDATE activation_keys 
            SET status = 'ACTIVE', activated_at = COALESCE(activated_at, ?), expires_at = ?
            WHERE id = ?
        `, [activatedAtIso, finalExpiresAt, keyRecord.id]);

        await db.logAuditEvent('DEVICE_ACTIVATED', { key: formattedKey, device_id: deviceId, model: deviceModel }, ip);

        const returnDurationDays = isPermanent ? -1 : Math.max(1, Math.round((durationHours || 720) / 24));

        // 11. Return activation success
        return res.json({
            success: true,
            message: 'Activation Successful',
            product: keyRecord.product_name || 'Zexora',
            developer: 'MADARA FF',
            copyright: '© Developed by MADARA FF',
            status: 'ACTIVE',
            activated_at: activatedAtIso,
            expires_at: finalExpiresAt,
            remaining_seconds: remainingSeconds,
            is_permanent: isPermanent,
            duration_hours: durationHours,
            session_token: sessionToken,
            device_registered: true,
            license: {
                key: keyRecord.key_display,
                product: keyRecord.product_name || 'Zexora',
                developer: 'MADARA FF',
                status: 'ACTIVE',
                activated_at: activatedAtIso,
                expires_at: finalExpiresAt,
                remaining_seconds: remainingSeconds,
                is_permanent: isPermanent,
                duration_days: returnDurationDays,
                max_activations: keyRecord.max_devices
            }
        });
    } catch (err) {
        console.error('Activation execution error:', err);
        res.status(500).json({ success: false, message: 'Server activation error: ' + err.message });
    }
}
app.post('/api/activate', handleCustomerActivate);
app.post('/api/license/activate', handleCustomerActivate);

// Customer Deactivate Endpoint
app.post('/api/deactivate', async (req, res) => {
    const rawKey = req.body.key || req.body.license_key;
    const deviceId = req.body.device_id || req.body.deviceId;

    if (!rawKey || !deviceId) {
        return res.status(400).json({ success: false, message: 'Key and device_id required' });
    }

    try {
        const keyHash = hashKey(rawKey.trim().toUpperCase());
        const keyRecord = await db.getKeyByHash(keyHash);
        if (!keyRecord) return res.status(404).json({ success: false, message: 'Key not found' });

        const device = await db.queryOne('SELECT id FROM devices WHERE device_identifier = ?', [deviceId]);
        if (device) {
            await db.deactivateDevice(keyRecord.id, device.id);
        }

        res.json({ success: true, message: 'Device deactivated successfully' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// Periodic Validation / Activation Status Endpoint
async function handleActivationStatus(req, res) {
    const ip = getClientIp(req);
    const rawKey = req.body.key || req.body.license_key || req.query.key;
    const deviceId = req.body.device_id || req.body.deviceId || req.query.device_id;
    const sessionToken = req.body.session_token || req.query.session_token;

    if (!rawKey || !deviceId) {
        return res.status(400).json({ success: false, error: 'MISSING_FIELDS', message: 'Key and Device ID required' });
    }

    try {
        const formattedKey = rawKey.trim().toUpperCase();
        const keyHash = hashKey(formattedKey);

        // Check if key was deleted by administrator
        if (await db.isKeyDeleted(keyHash)) {
            return res.status(403).json({
                success: false,
                valid: false,
                error: 'KEY_DELETED',
                errorCode: 'KEY_DELETED',
                title: 'Access Revoked',
                message: 'Your activation key has been deleted by the administrator. Your session has been terminated, and access to the Z E X O app has been revoked. Please contact the administrator if you believe this action was taken by mistake.'
            });
        }

        let keyRecord = await db.getKeyByHash(keyHash);

        if (!keyRecord) {
            const allMatch = await db.getAllKeys({ search: formattedKey, limit: 1 });
            if (allMatch && allMatch.length > 0 && allMatch[0].key_display === formattedKey) {
                keyRecord = allMatch[0];
            }
        }

        if (!keyRecord && (deviceId || sessionToken)) {
            keyRecord = await db.getKeyByDeviceOrSession(deviceId, sessionToken);
        }

        if (!keyRecord) {
            await db.logAuditEvent('VALIDATION_REJECTED_UNKNOWN_KEY', { key: formattedKey, device_id: deviceId }, ip);
            return res.status(404).json({
                success: false,
                valid: false,
                error: 'KEY_NOT_FOUND',
                errorCode: 'KEY_NOT_FOUND',
                title: 'License Not Found',
                message: 'Your activation key was not found in the license registry. Please verify your activation key or check server synchronization.'
            });
        }

        if (keyRecord.status === 'REVOKED') {
            return res.status(403).json({
                success: false,
                valid: false,
                error: 'KEY_REVOKED',
                errorCode: 'KEY_REVOKED',
                title: 'Access Revoked',
                message: 'Your activation key has been deleted by the administrator. Your session has been terminated, and access to the Z E X O app has been revoked. Please contact the administrator if you believe this action was taken by mistake.'
            });
        }

        if (keyRecord.status === 'SUSPENDED' || keyRecord.status === 'PAUSED') {
            return res.status(403).json({ success: false, valid: false, error: 'KEY_PAUSED', errorCode: 'KEY_PAUSED', message: 'Access has been paused by user, contact seller' });
        }

        if (keyRecord.status === 'EXPIRED') {
            return res.status(403).json({
                success: false,
                valid: false,
                error: 'KEY_EXPIRED',
                errorCode: 'KEY_EXPIRED',
                message: 'Activation key has expired'
            });
        }

        if (keyRecord.status === 'UNUSED') {
            return res.status(403).json({
                success: false,
                valid: false,
                error: 'DEVICE_NOT_ACTIVATED',
                errorCode: 'DEVICE_NOT_ACTIVATED',
                message: 'Activation key is not currently activated on this device'
            });
        }

        const isPermanent = keyRecord.duration_hours === -1;
        if (!isPermanent && keyRecord.expires_at && new Date(keyRecord.expires_at).getTime() <= Date.now()) {
            await db.updateKeyStatus(keyRecord.id, 'EXPIRED');
            return res.status(403).json({
                success: false,
                valid: false,
                error: 'KEY_EXPIRED',
                errorCode: 'KEY_EXPIRED',
                message: 'Activation key has expired'
            });
        }

        let device = await db.queryOne('SELECT id, customer_id FROM devices WHERE device_identifier = ?', [deviceId]);
        const activeCount = await db.getActiveActivationsCount(keyRecord.id);

        if (device) {
            await db.query(`
                UPDATE devices 
                SET device_model = COALESCE(?, device_model),
                    app_identifier = COALESCE(?, app_identifier),
                    last_seen_at = CURRENT_TIMESTAMP
                WHERE id = ?
            `, [req.body.device_model || null, req.body.app_identifier || 'com.example.rootoptimizer', device.id]);
        } else {
            // Self-healing: if key is active or within limit, auto-register device
            if (activeCount < keyRecord.max_devices) {
                const custName = keyRecord.customer_name || `user_${deviceId.slice(0, 8)}`;
                const customer = await db.getOrCreateCustomer(custName);
                device = await db.getOrCreateDevice(customer.id, deviceId, req.body.device_model || 'Android Device', req.body.app_identifier || 'com.example.rootoptimizer', req.body.platform || 'Android');
                const sessionTok = sessionToken || generateToken();
                await db.recordActivation({
                    keyId: keyRecord.id,
                    customerId: customer.id,
                    deviceId: device.id,
                    expiresAt: keyRecord.expires_at,
                    sessionToken: sessionTok
                });
            } else {
                return res.status(403).json({ success: false, valid: false, error: 'DEVICE_NOT_ACTIVATED', message: 'Device not registered' });
            }
        }

        let activation = await db.findActivation(keyRecord.id, device.id);
        if (activation) {
            if (activation.status === 'SUSPENDED' || activation.status === 'PAUSED') {
                return res.status(403).json({ success: false, valid: false, error: 'KEY_PAUSED', errorCode: 'KEY_PAUSED', message: 'Access has been paused by user, contact seller' });
            }
            if (activation.status === 'REVOKED') {
                return res.status(403).json({
                    success: false,
                    valid: false,
                    error: 'KEY_REVOKED',
                    errorCode: 'KEY_REVOKED',
                    title: 'Access Revoked',
                    message: 'Your activation key has been deleted by the administrator. Your session has been terminated, and access to the Z E X O app has been revoked. Please contact the administrator if you believe this action was taken by mistake.'
                });
            }
            if (activation.status === 'EXPIRED') {
                return res.status(403).json({
                    success: false,
                    valid: false,
                    error: 'KEY_EXPIRED',
                    errorCode: 'KEY_EXPIRED',
                    message: 'Activation key has expired'
                });
            }
            if (activation.status !== 'ACTIVE') {
                await db.query("UPDATE activations SET status = 'ACTIVE', is_active = 1 WHERE id = ?", [activation.id]);
            }
        } else {
            // Self-healing: restore active activation if key allows
            if (activeCount < keyRecord.max_devices) {
                const sessionTok = sessionToken || generateToken();
                await db.recordActivation({
                    keyId: keyRecord.id,
                    customerId: device.customer_id,
                    deviceId: device.id,
                    expiresAt: keyRecord.expires_at,
                    sessionToken: sessionTok
                });
                activation = await db.findActivation(keyRecord.id, device.id);
            } else {
                return res.status(403).json({ success: false, valid: false, error: 'DEVICE_NOT_ACTIVATED', message: 'Device is not active on this key' });
            }
        }

        if (!keyRecord.activated_at) {
            const nowIso = new Date().toISOString();
            await db.query("UPDATE activation_keys SET activated_at = ? WHERE id = ?", [nowIso, keyRecord.id]);
            keyRecord.activated_at = nowIso;
        }

        // Ensure non-permanent key has expires_at set and verified
        if (!isPermanent && !keyRecord.expires_at) {
            const hours = (keyRecord.duration_hours && keyRecord.duration_hours > 0) ? keyRecord.duration_hours : 720;
            const actEpoch = keyRecord.activated_at ? new Date(keyRecord.activated_at).getTime() : Date.now();
            const expIso = new Date(actEpoch + hours * 3600 * 1000).toISOString();
            await db.query("UPDATE activation_keys SET expires_at = ? WHERE id = ?", [expIso, keyRecord.id]);
            keyRecord.expires_at = expIso;
        }

        if (!isPermanent && keyRecord.expires_at && new Date(keyRecord.expires_at).getTime() <= Date.now()) {
            await db.updateKeyStatus(keyRecord.id, 'EXPIRED');
            return res.status(403).json({
                success: false,
                valid: false,
                error: 'KEY_EXPIRED',
                errorCode: 'KEY_EXPIRED',
                message: 'Activation key has expired'
            });
        }

        await db.updateActivationLastSeen(activation.id, sessionToken || activation.session_token);

        const remainingSeconds = isPermanent ? -1 : (keyRecord.expires_at ? Math.max(0, Math.floor((new Date(keyRecord.expires_at).getTime() - Date.now()) / 1000)) : null);
        const effectiveDurationDays = isPermanent ? -1 : Math.max(1, Math.round((keyRecord.duration_hours || 720) / 24));

        res.json({
            success: true,
            valid: true,
            status: keyRecord.status,
            key: keyRecord.key_display,
            license_key: keyRecord.key_display,
            product: keyRecord.product_name || 'Zexora',
            developer: 'MADARA FF',
            copyright: '© Developed by MADARA FF',
            activated_at: keyRecord.activated_at,
            expires_at: keyRecord.expires_at,
            remaining_seconds: remainingSeconds,
            is_permanent: isPermanent,
            duration_days: effectiveDurationDays
        });
    } catch (err) {
        res.status(500).json({ success: false, valid: false, message: err.message });
    }
}
app.all('/api/activation/status', handleActivationStatus);
app.post('/api/license/validate', handleActivationStatus);

// -------------------------------------------------------------
// In-App APK Update Endpoints
// -------------------------------------------------------------
function getAppUpdateConfig() {
    const versionFile = path.join(__dirname, 'public', 'downloads', 'version.json');
    let dynamicConfig = {};
    if (fs.existsSync(versionFile)) {
        try {
            dynamicConfig = JSON.parse(fs.readFileSync(versionFile, 'utf8'));
        } catch (e) {
            console.error('Error reading version.json:', e);
        }
    }

    const zexoraApk = path.join(__dirname, 'public', 'downloads', 'Zexora.apk');
    const legacyApk = path.join(__dirname, 'public', 'downloads', 'RootOptimizer.apk');
    const localApkPath = fs.existsSync(zexoraApk) ? zexoraApk : legacyApk;
    let fileSize = dynamicConfig.file_size_bytes || 8388608;
    if (fs.existsSync(localApkPath)) {
        try {
            fileSize = fs.statSync(localApkPath).size;
        } catch (e) {}
    }

    return {
        latest_version: dynamicConfig.latest_version || config.appLatestVersion || '1.3.6',
        version_code: parseInt(dynamicConfig.version_code || config.appVersionCode || '38', 10),
        min_version: dynamicConfig.min_version || config.appMinVersion || '1.0.0',
        title: dynamicConfig.title || 'Z E X O Update Available',
        release_notes: (dynamicConfig.release_notes !== undefined) ? dynamicConfig.release_notes : '',
        apk_filename: dynamicConfig.apk_filename || (fs.existsSync(zexoraApk) ? 'Zexora.apk' : 'RootOptimizer.apk'),
        download_url: dynamicConfig.download_url || config.appDownloadUrl || '/api/app/download',
        file_size_bytes: fileSize
    };
}

app.get(['/api/app/update', '/api/app/version'], (req, res) => {
    const appConfig = getAppUpdateConfig();
    const currentCode = parseInt(req.query.version_code || req.query.code || '1', 10);
    const updateAvailable = currentCode < appConfig.version_code;

    let directUrl = appConfig.download_url;
    if (directUrl.startsWith('/')) {
        const host = req.get('host');
        const proto = req.secure || req.headers['x-forwarded-proto'] === 'https' ? 'https' : 'http';
        directUrl = `${proto}://${host}${directUrl}`;
    }

    res.json({
        success: true,
        update_available: updateAvailable,
        force_update: updateAvailable,
        mandatory: updateAvailable,
        latest_version: appConfig.latest_version,
        version_code: appConfig.version_code,
        min_version: appConfig.min_version,
        release_notes: appConfig.release_notes,
        download_url: directUrl,
        file_size_bytes: appConfig.file_size_bytes
    });
});

app.post(['/api/app/publish', '/api/admin/app/publish'], express.json(), (req, res) => {
    let secret = req.headers['x-admin-key'] || req.query.admin_key || req.body?.admin_key;
    if (!secret && req.headers['authorization']?.startsWith('Bearer ')) {
        secret = req.headers['authorization'].slice(7).trim();
    }
    const expectedSecret = config.adminSecret;
    if (!secret || !safeTimingCompare(secret, expectedSecret)) {
        return res.status(401).json({ success: false, error: 'Unauthorized' });
    }

    const { latest_version, version_code, release_notes, min_version, download_url } = req.body || {};
    const versionFile = path.join(__dirname, 'public', 'downloads', 'version.json');
    let currentConfig = {};
    if (fs.existsSync(versionFile)) {
        try { currentConfig = JSON.parse(fs.readFileSync(versionFile, 'utf8')); } catch (e) {}
    }

    const updatedConfig = {
        ...currentConfig,
        latest_version: latest_version || currentConfig.latest_version || '1.0.1',
        version_code: parseInt(version_code || currentConfig.version_code || '2', 10),
        min_version: min_version || currentConfig.min_version || '1.0.0',
        release_notes: release_notes || currentConfig.release_notes || '',
        download_url: download_url || currentConfig.download_url || '/api/app/download',
        updated_at: new Date().toISOString()
    };

    fs.mkdirSync(path.dirname(versionFile), { recursive: true });
    fs.writeFileSync(versionFile, JSON.stringify(updatedConfig, null, 2));

    res.json({ success: true, message: 'Update configuration published successfully', config: updatedConfig });
});

app.get(['/api/app/download', '/download/app-release.apk', '/download/Zexora.apk', '/download/RootOptimizer.apk'], (req, res) => {
    const zexoraApk = path.join(__dirname, 'public', 'downloads', 'Zexora.apk');
    const legacyApk = path.join(__dirname, 'public', 'downloads', 'RootOptimizer.apk');
    const localApkPath = fs.existsSync(zexoraApk) ? zexoraApk : legacyApk;
    const downloadName = fs.existsSync(zexoraApk) ? 'Zexora.apk' : 'RootOptimizer.apk';

    if (fs.existsSync(localApkPath)) {
        return res.download(localApkPath, downloadName, {
            headers: {
                'Content-Type': 'application/vnd.android.package-archive'
            }
        });
    }

    const builtZexoraApk = path.join(__dirname, '..', 'RootOptimizer', 'app', 'build', 'outputs', 'apk', 'debug', 'app-debug.apk');
    if (fs.existsSync(builtZexoraApk)) {
        return res.download(builtZexoraApk, downloadName, {
            headers: {
                'Content-Type': 'application/vnd.android.package-archive'
            }
        });
    }

    if (config.appDownloadUrl && !config.appDownloadUrl.startsWith('/')) {
        return res.redirect(config.appDownloadUrl);
    }

    res.status(404).json({
        success: false,
        message: 'No APK file uploaded to server yet.'
    });
});

// -------------------------------------------------------------
// Protected Configuration Status & Health Check
// -------------------------------------------------------------
app.get('/api/config/status', requireAdmin, (req, res) => {
    const sanitized = getSanitizedConfig(config);
    const validation = validateConfig(config);
    res.json({
        success: true,
        config: sanitized,
        validation: {
            valid: validation.valid,
            warnings: validation.warnings
        }
    });
});

// -------------------------------------------------------------
// Web Dashboard Serving
// -------------------------------------------------------------
app.get(['/', '/admin', '/login'], (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Centralized Production-Safe Error Handler
app.use((err, req, res, next) => {
    console.error('[SERVER ERROR]', err.message || err);
    if (res.headersSent) return next(err);
    res.status(err.status || 500).json({
        success: false,
        error: config.isProduction ? 'INTERNAL_ERROR' : (err.code || 'SERVER_ERROR'),
        message: config.isProduction ? 'An unexpected server error occurred.' : (err.message || 'Server error')
    });
});

// Keep-alive pinger to prevent Render free-tier 15-minute inactivity spin-down
function startKeepAlive() {
    if (!config.isRender && !process.env.ENABLE_KEEP_ALIVE) return;
    const KEEP_ALIVE_INTERVAL = 8 * 60 * 1000; // 8 minutes
    setInterval(async () => {
        try {
            const cloudUrl = config.cloudServerUrl;
            const pingUrl = process.env.SELF_URL || `${cloudUrl}/api/health`;
            const res = await fetch(pingUrl, {
                headers: { 'User-Agent': 'ZexoKeepAlive/1.0' }
            });
            if (res.ok) {
                console.log(`[KEEP-ALIVE] Heartbeat ping successful to ${pingUrl} at ${new Date().toISOString()}`);
            }
        } catch (e) {
            console.warn('[KEEP-ALIVE] Heartbeat ping deferred:', e.message);
        }
    }, KEEP_ALIVE_INTERVAL).unref();

    // Initial ping shortly after server start
    setTimeout(async () => {
        try {
            const cloudUrl = config.cloudServerUrl;
            const pingUrl = process.env.SELF_URL || `${cloudUrl}/api/health`;
            await fetch(pingUrl, { headers: { 'User-Agent': 'ZexoKeepAlive/1.0' } });
            console.log(`[KEEP-ALIVE] Initial keep-alive ping dispatched to ${pingUrl}`);
        } catch (e) {}
    }, 15000).unref();
}

// Pre-flight configuration validation & server startup
if (require.main === module) {
    const validation = validateConfig(config);
    if (!validation.valid) {
        console.error('[CONFIG FATAL] Deployment stopped: Configuration validation failed:');
        for (const err of validation.errors) {
            console.error(`  - ${err}`);
        }
        process.exit(1);
    }

    for (const warn of validation.warnings) {
        console.warn(`[CONFIG WARNING] ${warn}`);
    }

    db.initDatabase().then(() => {
        app.listen(config.port, config.host, () => {
            console.log(`[SERVER] Z E X O License Server running on port ${config.port} (${config.nodeEnv})`);
            startKeepAlive();
            // Background sync only if explicitly enabled in local development
            if (!config.isRender && config.autoSyncCloud) {
                setTimeout(async () => {
                    try {
                        console.log('[SYNC] Starting background sync with Render cloud...');
                        const syncRes = await syncWithCloudServer();
                        console.log('[SYNC] Background sync finished:', syncRes.message);
                    } catch (e) {
                        console.log('[SYNC] Background cloud sync deferred:', e.message);
                    }
                }, 3000);
            }
        });
    }).catch(err => {
        console.error('[SERVER] Failed to start:', err.message || err);
        process.exit(1);
    });
}

module.exports = {
    app,
    syncWithCloudServer,
    deleteKeyFromCloud
};
