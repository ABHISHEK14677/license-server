const express = require('express');
const cors = require('cors');
const path = require('node:path');
const fs = require('node:fs');
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
const PORT = process.env.PORT || 5000;

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
// System & Health Endpoints
// -------------------------------------------------------------
app.get('/api/health', (req, res) => {
    res.json({
        status: 'ok',
        service: 'Optimizer License Activation System',
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

        // Allow setup if no admin exists, or if valid ADMIN_SECRET_KEY is provided
        const requiredSecret = process.env.ADMIN_SECRET_KEY || 'rootoptimizer_secret_2026';
        if (existingAdmin && secret !== requiredSecret) {
            return res.status(403).json({
                success: false,
                message: 'Admin account already exists. Please log in with your credentials.'
            });
        }

        if (existingAdmin) {
            await db.updateAdminPassword(existingAdmin.id, password);
            return res.json({
                success: true,
                message: `Admin account "${username}" password updated successfully!`
            });
        } else {
            await db.createAdmin(username, password, email, 'superadmin');
            return res.json({
                success: true,
                message: `Admin account "${username}" initialized successfully! Password: "${password}"`
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
        product_name = 'Optimizer',
        duration_hours = null,
        duration_days = null,
        max_devices = 1,
        customer_name = null,
        notes = '',
        count = 1,
        prefix = 'MADARA-FF'
    } = req.body;

    try {
        // Calculate duration in hours (-1 means permanent / lifetime)
        let effectiveHours = 720; // default 30 days
        if (req.body.permanent === true || duration_hours === -1 || duration_days === -1) {
            effectiveHours = -1;
        } else if (duration_hours !== null && duration_hours !== undefined) {
            effectiveHours = parseInt(duration_hours, 10);
        } else if (duration_days !== null && duration_days !== undefined) {
            effectiveHours = parseInt(duration_days, 10) * 24;
        }

        const product = await db.getOrCreateProduct(product_name);
        const generatedKeys = [];
        const limitCount = Math.min(Math.max(parseInt(count, 10) || 1, 1), 50);

        for (let i = 0; i < limitCount; i++) {
            const rawKey = generateLicenseKey(prefix || 'MADARA-FF');
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

// Cloud Synchronization
async function syncWithCloudServer() {
    const cloudUrl = process.env.CLOUD_SERVER_URL || 'https://optimizer-stzd.onrender.com';
    const adminUser = process.env.ADMIN_USERNAME || 'MADARA-FF';
    const adminPass = process.env.ADMIN_PASSWORD || 'ABHISHEK!';

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
    if (cloudKeysData.success && Array.isArray(cloudKeysData.keys)) {
        importedLocally = await db.importSeedKeys(cloudKeysData.keys);
    }

    // Step 3: Export local keys and sync to Cloud Server
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

// Update / Edit key (notes, customer name, max devices, status)
async function handleUpdateKey(req, res) {
    try {
        const key = await db.getKeyByIdOrString(req.params.id);
        if (!key) return res.status(404).json({ success: false, message: 'Key not found' });
        const { notes, customer_name, customerName, max_devices, maxDevices, status } = req.body;
        const updated = await db.updateKeyDetails(key.id, {
            notes,
            customerName: customer_name || customerName,
            maxDevices: max_devices || maxDevices,
            status
        });
        await db.logAuditEvent('KEY_UPDATED', { key_id: key.id, key_display: key.key_display, changes: req.body }, getClientIp(req));
        res.json({ success: true, message: 'Key updated successfully', key: updated });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
}
app.patch('/api/keys/:id', requireAdmin, handleUpdateKey);
app.put('/api/keys/:id', requireAdmin, handleUpdateKey);

// Revoke key
app.post('/api/keys/:id/revoke', requireAdmin, async (req, res) => {
    try {
        const key = await db.getKeyByIdOrString(req.params.id);
        if (!key) return res.status(404).json({ success: false, message: 'Key not found' });
        const updated = await db.updateKeyStatus(key.id, 'REVOKED');
        await db.logAuditEvent('KEY_REVOKED', { key_id: key.id, key_display: key.key_display }, getClientIp(req));
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
        const updated = await db.updateKeyStatus(key.id, 'SUSPENDED');
        await db.logAuditEvent('KEY_SUSPENDED', { key_id: key.id, key_display: key.key_display }, getClientIp(req));
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

        // If it was unused, keep unused; otherwise activate
        const targetStatus = key.activated_at ? 'ACTIVE' : 'UNUSED';
        const updated = await db.updateKeyStatus(key.id, targetStatus);
        await db.logAuditEvent('KEY_REACTIVATED', { key_id: key.id, key_display: key.key_display }, getClientIp(req));
        res.json({ success: true, message: 'Key resumed/reactivated successfully', key: updated });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
}
app.post('/api/keys/:id/reactivate', requireAdmin, handleReactivateKey);
app.post('/api/keys/:id/resume', requireAdmin, handleReactivateKey);

// Delete key
app.delete('/api/keys/:id', requireAdmin, async (req, res) => {
    try {
        const key = await db.getKeyByIdOrString(req.params.id);
        if (!key) return res.status(404).json({ success: false, message: 'Key not found' });
        await db.deleteKey(key.id);
        await db.logAuditEvent('KEY_DELETED', { key_id: key.id, key_display: key.key_display }, getClientIp(req));
        res.json({ success: true, message: 'Key deleted successfully' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

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
        let keyRecord = await db.getKeyByHash(keyHash);

        // Fallback: check by key_display if legacy key
        if (!keyRecord) {
            const allMatch = await db.getAllKeys({ search: formattedKey, limit: 1 });
            if (allMatch && allMatch.length > 0 && allMatch[0].key_display === formattedKey) {
                keyRecord = allMatch[0];
            }
        }

        // Self-healing: if server restarted with fresh container and mobile sends valid key
        if (!keyRecord) {
            await db.importSeedKeys();
            keyRecord = await db.getKeyByHash(keyHash);
        }

        if (!keyRecord && isValidKeyFormat(formattedKey)) {
            const product = await db.getOrCreateProduct('Optimizer');
            const dur = req.body.duration_days ? (parseInt(req.body.duration_days, 10) === -1 ? -1 : parseInt(req.body.duration_days, 10) * 24) : -1;
            keyRecord = await db.createActivationKey({
                keyString: formattedKey,
                productId: product.id,
                durationHours: dur,
                maxDevices: 1,
                customerName: customerName || `user_${deviceId.slice(0, 8)}`,
                notes: 'Auto-restored from mobile device activation'
            });
            console.log(`[SELF-HEAL] Recreated missing key from mobile activation: ${formattedKey}`);
        }

        if (!keyRecord) {
            await db.logAuditEvent('ACTIVATION_FAILED', { reason: 'Key not found', key: formattedKey, device_id: deviceId }, ip);
            return res.status(404).json({
                success: false,
                error: 'INVALID_KEY',
                message: 'Invalid activation key'
            });
        }

        // 4. Check whether key is revoked
        if (keyRecord.status === 'REVOKED') {
            await db.logAuditEvent('ACTIVATION_FAILED', { reason: 'Key revoked', key: formattedKey, device_id: deviceId }, ip);
            return res.status(403).json({
                success: false,
                error: 'KEY_REVOKED',
                message: 'Activation key has been revoked'
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
        const now = Date.now();
        if (keyRecord.expires_at) {
            const expiryTime = new Date(keyRecord.expires_at).getTime();
            if (now > expiryTime) {
                await db.updateKeyStatus(keyRecord.id, 'EXPIRED');
                await db.logAuditEvent('ACTIVATION_FAILED', { reason: 'Key expired', key: formattedKey, device_id: deviceId }, ip);
                return res.status(403).json({
                    success: false,
                    error: 'KEY_EXPIRED',
                    message: 'Activation key has expired'
                });
            }
        }

        // 7. Customer & Device record registration
        const customer = await db.getOrCreateCustomer(keyRecord.customer_name || customerName || `user_${deviceId.slice(0, 8)}`, customerName);
        const device = await db.getOrCreateDevice(customer.id, deviceId, deviceModel, appIdentifier, platform);

        // Check if device is already activated on this key
        const existingActivation = await db.findActivation(keyRecord.id, device.id);
        const isPermanent = keyRecord.duration_hours === -1;
        if (existingActivation && existingActivation.status === 'ACTIVE') {
            const token = existingActivation.session_token || generateToken();
            await db.updateActivationLastSeen(existingActivation.id, token);

            const remainingSeconds = isPermanent ? -1 : (keyRecord.expires_at ? Math.max(0, Math.floor((new Date(keyRecord.expires_at).getTime() - Date.now()) / 1000)) : null);

            return res.json({
                success: true,
                message: 'Activation Successful',
                product: keyRecord.product_name || 'Optimizer',
                developer: 'MADARA FF',
                copyright: '© Developed by MADARA FF',
                status: 'ACTIVE',
                activated_at: keyRecord.activated_at || existingActivation.activated_at,
                expires_at: keyRecord.expires_at,
                remaining_seconds: remainingSeconds,
                is_permanent: isPermanent,
                duration_hours: keyRecord.duration_hours,
                session_token: token,
                device_registered: true,
                license: {
                    key: keyRecord.key_display,
                    product: keyRecord.product_name || 'Optimizer',
                    developer: 'MADARA FF',
                    status: 'ACTIVE',
                    activated_at: keyRecord.activated_at || existingActivation.activated_at,
                    expires_at: keyRecord.expires_at,
                    remaining_seconds: remainingSeconds,
                    is_permanent: isPermanent,
                    duration_days: isPermanent ? -1 : Math.round((keyRecord.duration_hours || 720) / 24),
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
        const durationHours = keyRecord.duration_hours;
        let finalExpiresAt = null;
        let remainingSeconds = -1;

        if (!isPermanent) {
            const hours = durationHours && durationHours > 0 ? durationHours : 720;
            if (keyRecord.status === 'UNUSED' || !keyRecord.activated_at || !keyRecord.expires_at) {
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
        if (keyRecord.status === 'UNUSED' || !keyRecord.activated_at) {
            await db.query(`
                UPDATE activation_keys 
                SET status = 'ACTIVE', activated_at = CURRENT_TIMESTAMP, expires_at = ?
                WHERE id = ?
            `, [finalExpiresAt, keyRecord.id]);
        }

        await db.logAuditEvent('DEVICE_ACTIVATED', { key: formattedKey, device_id: deviceId, model: deviceModel }, ip);

        // 11. Return activation success
        return res.json({
            success: true,
            message: 'Activation Successful',
            product: keyRecord.product_name || 'Optimizer',
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
                product: keyRecord.product_name || 'Optimizer',
                developer: 'MADARA FF',
                status: 'ACTIVE',
                activated_at: activatedAtIso,
                expires_at: finalExpiresAt,
                remaining_seconds: remainingSeconds,
                is_permanent: isPermanent,
                duration_days: isPermanent ? -1 : Math.round((durationHours || 720) / 24),
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
    const rawKey = req.body.key || req.body.license_key || req.query.key;
    const deviceId = req.body.device_id || req.body.deviceId || req.query.device_id;
    const sessionToken = req.body.session_token || req.query.session_token;

    if (!rawKey || !deviceId) {
        return res.status(400).json({ success: false, error: 'MISSING_FIELDS', message: 'Key and Device ID required' });
    }

    try {
        const keyHash = hashKey(rawKey.trim().toUpperCase());
        let keyRecord = await db.getKeyByHash(keyHash);

        if (!keyRecord) {
            // Check if seed keys restore it
            await db.importSeedKeys();
            keyRecord = await db.getKeyByHash(keyHash);
        }

        // Self-heal: if server restarted with fresh container and mobile sends valid key
        if (!keyRecord && isValidKeyFormat(rawKey)) {
            const product = await db.getOrCreateProduct('Optimizer');
            const dur = req.body.duration_days ? (parseInt(req.body.duration_days, 10) === -1 ? -1 : parseInt(req.body.duration_days, 10) * 24) : -1;
            keyRecord = await db.createActivationKey({
                keyString: rawKey.trim().toUpperCase(),
                productId: product.id,
                durationHours: dur,
                maxDevices: 1,
                customerName: req.body.customer_name || 'Self-Healed Device User',
                notes: 'Auto-restored from mobile client status heartbeat'
            });
            console.log(`[SELF-HEAL] Recreated missing key from mobile status check: ${rawKey}`);
        }

        if (!keyRecord) {
            return res.status(404).json({ success: false, valid: false, error: 'INVALID_KEY', message: 'Invalid activation key' });
        }

        if (keyRecord.status === 'REVOKED') {
            return res.status(403).json({ success: false, valid: false, error: 'KEY_REVOKED', message: 'Activation key has been revoked' });
        }

        if (keyRecord.status === 'SUSPENDED' || keyRecord.status === 'PAUSED') {
            return res.status(403).json({ success: false, valid: false, error: 'KEY_PAUSED', message: 'Access has been paused by user, contact seller' });
        }

        const isPermanent = keyRecord.duration_hours === -1;
        if (!isPermanent && keyRecord.expires_at && new Date(keyRecord.expires_at).getTime() < Date.now()) {
            await db.updateKeyStatus(keyRecord.id, 'EXPIRED');
            return res.status(403).json({ success: false, valid: false, error: 'KEY_EXPIRED', message: 'Activation key has expired' });
        }

        let device = await db.queryOne('SELECT id, customer_id FROM devices WHERE device_identifier = ?', [deviceId]);
        const activeCount = await db.getActiveActivationsCount(keyRecord.id);

        if (!device) {
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
                if (keyRecord.status === 'UNUSED') {
                    await db.updateKeyStatus(keyRecord.id, 'ACTIVE');
                    keyRecord.status = 'ACTIVE';
                }
            } else {
                return res.status(403).json({ success: false, valid: false, error: 'DEVICE_NOT_ACTIVATED', message: 'Device not registered' });
            }
        }

        let activation = await db.findActivation(keyRecord.id, device.id);
        if (!activation || activation.status !== 'ACTIVE') {
            if (activation && (activation.status === 'SUSPENDED' || activation.status === 'PAUSED')) {
                return res.status(403).json({ success: false, valid: false, error: 'KEY_PAUSED', message: 'Access has been paused by user, contact seller' });
            }
            if (activation && activation.status === 'REVOKED') {
                return res.status(403).json({ success: false, valid: false, error: 'KEY_REVOKED', message: 'Activation key has been revoked' });
            }
            // Self-healing: restore active activation if key allows
            if (activeCount < keyRecord.max_devices) {
                const sessionTok = sessionToken || (activation ? activation.session_token : null) || generateToken();
                await db.recordActivation({
                    keyId: keyRecord.id,
                    customerId: device.customer_id,
                    deviceId: device.id,
                    expiresAt: keyRecord.expires_at,
                    sessionToken: sessionTok
                });
                activation = await db.findActivation(keyRecord.id, device.id);
                if (keyRecord.status === 'UNUSED') {
                    await db.updateKeyStatus(keyRecord.id, 'ACTIVE');
                    keyRecord.status = 'ACTIVE';
                }
            } else {
                return res.status(403).json({ success: false, valid: false, error: 'DEVICE_NOT_ACTIVATED', message: 'Device is not active on this key' });
            }
        }

        if (keyRecord.status === 'UNUSED') {
            await db.updateKeyStatus(keyRecord.id, 'ACTIVE');
            keyRecord.status = 'ACTIVE';
        }
        if (!keyRecord.activated_at) {
            const nowIso = new Date().toISOString();
            await db.query("UPDATE activation_keys SET activated_at = ? WHERE id = ?", [nowIso, keyRecord.id]);
            keyRecord.activated_at = nowIso;
        }

        await db.updateActivationLastSeen(activation.id, sessionToken || activation.session_token);

        const remainingSeconds = isPermanent ? -1 : (keyRecord.expires_at ? Math.max(0, Math.floor((new Date(keyRecord.expires_at).getTime() - Date.now()) / 1000)) : null);

        res.json({
            success: true,
            valid: true,
            status: keyRecord.status,
            product: keyRecord.product_name || 'Optimizer',
            developer: 'MADARA FF',
            copyright: '© Developed by MADARA FF',
            activated_at: keyRecord.activated_at,
            expires_at: keyRecord.expires_at,
            remaining_seconds: remainingSeconds,
            is_permanent: isPermanent,
            duration_days: isPermanent ? -1 : Math.round((keyRecord.duration_hours || 720) / 24)
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
const APP_UPDATE_CONFIG = {
    latest_version: process.env.APP_LATEST_VERSION || '1.0.1',
    version_code: parseInt(process.env.APP_VERSION_CODE || '2', 10),
    min_version: '1.0.0',
    title: 'Optimizer Update Available',
    release_notes: '• Fixed key persistence across Render server restarts\n• Real-time cloud synchronization & self-healing\n• In-app seamless APK updating\n• Performance and memory retention improvements',
    apk_filename: 'RootOptimizer.apk',
    download_url: process.env.APP_DOWNLOAD_URL || '/api/app/download'
};

app.get(['/api/app/update', '/api/app/version'], (req, res) => {
    const currentCode = parseInt(req.query.version_code || req.query.code || '1', 10);
    const updateAvailable = currentCode < APP_UPDATE_CONFIG.version_code;

    let directUrl = APP_UPDATE_CONFIG.download_url;
    if (directUrl.startsWith('/')) {
        const host = req.get('host');
        const proto = req.secure || req.headers['x-forwarded-proto'] === 'https' ? 'https' : 'http';
        directUrl = `${proto}://${host}${directUrl}`;
    }

    res.json({
        success: true,
        update_available: updateAvailable,
        latest_version: APP_UPDATE_CONFIG.latest_version,
        version_code: APP_UPDATE_CONFIG.version_code,
        min_version: APP_UPDATE_CONFIG.min_version,
        release_notes: APP_UPDATE_CONFIG.release_notes,
        download_url: directUrl,
        file_size_bytes: 8388608
    });
});

app.get(['/api/app/download', '/download/app-release.apk', '/download/RootOptimizer.apk'], (req, res) => {
    const localApkPath = path.join(__dirname, 'public', 'downloads', 'RootOptimizer.apk');
    if (fs.existsSync(localApkPath)) {
        return res.download(localApkPath, 'RootOptimizer.apk', {
            headers: {
                'Content-Type': 'application/vnd.android.package-archive'
            }
        });
    }

    const builtApkPath = path.join(__dirname, '..', 'RootOptimizer', 'app', 'build', 'outputs', 'apk', 'debug', 'app-debug.apk');
    if (fs.existsSync(builtApkPath)) {
        return res.download(builtApkPath, 'RootOptimizer.apk', {
            headers: {
                'Content-Type': 'application/vnd.android.package-archive'
            }
        });
    }

    if (process.env.APP_DOWNLOAD_URL && !process.env.APP_DOWNLOAD_URL.startsWith('/')) {
        return res.redirect(process.env.APP_DOWNLOAD_URL);
    }

    res.status(404).json({
        success: false,
        message: 'No APK file uploaded to server yet.'
    });
});

// -------------------------------------------------------------
// Web Dashboard Serving
// -------------------------------------------------------------
app.get(['/', '/admin', '/login'], (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Initialize database schema and start server
db.initDatabase().then(() => {
    app.listen(PORT, '0.0.0.0', () => {
        console.log(`[SERVER] Optimizer License Server & Key Generator running on port ${PORT}`);
        // Attempt non-blocking background sync with Render Cloud if running locally
        if (!process.env.RENDER && process.env.AUTO_SYNC_CLOUD !== 'false') {
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
    console.error('[SERVER] Failed to start:', err);
});
