const express = require('express');
const cors = require('cors');
const path = require('node:path');
const {
    generateLicenseKey,
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
const adminLoginLimiter = new RateLimiter(10, 60 * 1000); // 10 req/min

// Helper to get client IP
function getClientIp(req) {
    return req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
}

// -------------------------------------------------------------
// Admin Auth Middleware
// -------------------------------------------------------------
function requireAdmin(req, res, next) {
    const authHeader = req.headers.authorization;
    let token = null;

    if (authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.substring(7);
    } else if (req.headers['x-admin-token']) {
        token = req.headers['x-admin-token'];
    }

    if (!token) {
        return res.status(401).json({ success: false, error: 'UNAUTHORIZED', message: 'Missing authentication token.' });
    }

    const session = db.getAdminSession(token);
    if (!session) {
        return res.status(401).json({ success: false, error: 'SESSION_EXPIRED', message: 'Session expired or invalid.' });
    }

    req.admin = session;
    next();
}

// -------------------------------------------------------------
// Public / Client APK Endpoints
// -------------------------------------------------------------

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', serverTime: new Date().toISOString() });
});

// Activate license from APK
app.post('/api/license/activate', (req, res) => {
    const ip = getClientIp(req);
    if (activateLimiter.isRateLimited(ip)) {
        return res.status(429).json({ success: false, error: 'RATE_LIMITED', message: 'Too many activation attempts. Please try again later.' });
    }

    const { license_key, device_id, device_model } = req.body;

    if (!license_key || !device_id) {
        return res.status(400).json({ success: false, error: 'MISSING_FIELDS', message: 'License key and Device ID are required.' });
    }

    const formattedKey = license_key.trim().toUpperCase();
    const license = db.getLicenseByKey(formattedKey);

    if (!license) {
        db.logAuditEvent('ACTIVATION_FAILED', { reason: 'Invalid license key', key: formattedKey, device_id }, ip);
        return res.status(404).json({ success: false, error: 'KEY_NOT_FOUND', message: 'Invalid license key. Please check and try again.' });
    }

    if (license.status === 'REVOKED') {
        db.logAuditEvent('ACTIVATION_FAILED', { reason: 'Revoked license key', key: formattedKey, device_id }, ip);
        return res.status(403).json({ success: false, error: 'KEY_REVOKED', message: 'This license key has been revoked by the administrator.' });
    }

    // Check expiration
    if (license.expires_at) {
        const expiryDate = new Date(license.expires_at);
        if (expiryDate.getTime() < Date.now()) {
            db.updateLicenseStatus(license.id, 'EXPIRED');
            db.logAuditEvent('ACTIVATION_FAILED', { reason: 'Expired license key', key: formattedKey, device_id }, ip);
            return res.status(403).json({ success: false, error: 'KEY_EXPIRED', message: 'This license key has expired.' });
        }
    }

    // Check if device is already registered for this license
    const existingActivation = db.findDeviceActivation(license.id, device_id);
    if (existingActivation) {
        db.updateActivationLastSeen(existingActivation.id);
        const sessionToken = existingActivation.session_token || generateToken();

        db.logAuditEvent('DEVICE_REACTIVATED', { key: formattedKey, device_id, device_model }, ip);
        return res.json({
            success: true,
            message: 'Device verified successfully.',
            license: {
                key: license.license_key,
                status: license.status,
                expires_at: license.expires_at,
                duration_days: license.duration_days,
                max_activations: license.max_activations
            },
            session_token: sessionToken
        });
    }

    // Check activation limit
    const activeCount = db.getActiveActivationsCount(license.id);
    if (activeCount >= license.max_activations) {
        db.logAuditEvent('ACTIVATION_FAILED', { reason: 'Activation limit reached', key: formattedKey, device_id, activeCount, max: license.max_activations }, ip);
        return res.status(403).json({
            success: false,
            error: 'ACTIVATION_LIMIT_REACHED',
            message: `Activation limit reached for this license (max ${license.max_activations} devices). Contact admin to manage or reset activations.`
        });
    }

    // If first activation and duration_days > 0 without explicit expires_at, compute expires_at now
    let calculatedExpiry = license.expires_at;
    if (!calculatedExpiry && license.duration_days > 0) {
        const exp = new Date(Date.now() + license.duration_days * 24 * 60 * 60 * 1000);
        calculatedExpiry = exp.toISOString();
        db.updateLicenseExpiry(license.id, calculatedExpiry);
    }

    const sessionToken = generateToken();
    db.recordActivation(license.id, device_id, device_model, sessionToken);
    db.logAuditEvent('DEVICE_ACTIVATED', { key: formattedKey, device_id, device_model }, ip);

    return res.json({
        success: true,
        message: 'License activated successfully!',
        license: {
            key: license.license_key,
            status: license.status,
            expires_at: calculatedExpiry,
            duration_days: license.duration_days,
            max_activations: license.max_activations
        },
        session_token: sessionToken
    });
});

// Periodic validation from APK
app.post('/api/license/validate', (req, res) => {
    const { license_key, device_id, session_token } = req.body;

    if (!license_key || !device_id) {
        return res.status(400).json({ success: false, error: 'MISSING_FIELDS' });
    }

    const license = db.getLicenseByKey(license_key);
    if (!license) {
        return res.status(404).json({ success: false, valid: false, error: 'KEY_NOT_FOUND' });
    }

    if (license.status === 'REVOKED') {
        return res.status(403).json({ success: false, valid: false, error: 'KEY_REVOKED' });
    }

    if (license.expires_at && new Date(license.expires_at).getTime() < Date.now()) {
        db.updateLicenseStatus(license.id, 'EXPIRED');
        return res.status(403).json({ success: false, valid: false, error: 'KEY_EXPIRED' });
    }

    const activation = db.findDeviceActivation(license.id, device_id);
    if (!activation || !activation.is_active) {
        return res.status(403).json({ success: false, valid: false, error: 'DEVICE_NOT_ACTIVATED' });
    }

    db.updateActivationLastSeen(activation.id);

    res.json({
        success: true,
        valid: true,
        status: license.status,
        expires_at: license.expires_at
    });
});

// -------------------------------------------------------------
// Admin Endpoints
// -------------------------------------------------------------

// Admin login
app.post('/api/admin/login', (req, res) => {
    const ip = getClientIp(req);
    if (adminLoginLimiter.isRateLimited(ip)) {
        return res.status(429).json({ success: false, error: 'RATE_LIMITED', message: 'Too many login attempts. Please wait.' });
    }

    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Username and password required.' });
    }

    const admin = db.getAdminByUsername(username);
    if (!admin || !verifyPassword(password, admin.salt, admin.password_hash)) {
        db.logAuditEvent('ADMIN_LOGIN_FAILED', { username }, ip);
        return res.status(401).json({ success: false, message: 'Invalid admin credentials.' });
    }

    const token = generateToken();
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
    db.createAdminSession(admin.id, token, expiresAt);
    db.logAuditEvent('ADMIN_LOGIN_SUCCESS', { username }, ip);

    res.json({
        success: true,
        token,
        username: admin.username,
        expires_at: expiresAt.toISOString()
    });
});

// Admin logout
app.post('/api/admin/logout', requireAdmin, (req, res) => {
    const authHeader = req.headers.authorization;
    const token = authHeader?.startsWith('Bearer ') ? authHeader.substring(7) : req.headers['x-admin-token'];
    if (token) db.deleteAdminSession(token);
    res.json({ success: true, message: 'Logged out successfully.' });
});

// Admin Dashboard stats
app.get('/api/admin/stats', requireAdmin, (req, res) => {
    const all = db.getAllLicenses();
    const active = all.filter(l => l.status === 'ACTIVE');
    const revoked = all.filter(l => l.status === 'REVOKED');
    const expired = all.filter(l => l.status === 'EXPIRED');
    const totalActivations = all.reduce((sum, l) => sum + (l.active_activations || 0), 0);

    res.json({
        success: true,
        stats: {
            total_licenses: all.length,
            active_licenses: active.length,
            revoked_licenses: revoked.length,
            expired_licenses: expired.length,
            active_devices: totalActivations
        }
    });
});

// List licenses
app.get('/api/admin/licenses', requireAdmin, (req, res) => {
    const search = req.query.search || '';
    const licenses = db.getAllLicenses(search);
    res.json({ success: true, licenses });
});

// Generate new license(s)
app.post('/api/admin/licenses/generate', requireAdmin, (req, res) => {
    const {
        count = 1,
        duration_days = 30,
        max_activations = 1,
        is_reusable = 1,
        notes = '',
        custom_expires_at = null,
        prefix = 'RO'
    } = req.body;

    const keyCount = Math.min(Math.max(1, parseInt(count) || 1), 100);
    const durationDaysInt = parseInt(duration_days) || 30;
    const maxActivationsInt = Math.max(1, parseInt(max_activations) || 1);
    const generated = [];

    for (let i = 0; i < keyCount; i++) {
        let key = generateLicenseKey(prefix);
        let expiresAt = null;

        if (custom_expires_at) {
            expiresAt = new Date(custom_expires_at).toISOString();
        }

        db.createLicense({
            licenseKey: key,
            durationDays: durationDaysInt,
            expiresAt,
            maxActivations: maxActivationsInt,
            isReusable: is_reusable ? 1 : 0,
            notes: notes || '',
            status: 'ACTIVE'
        });

        const created = db.getLicenseByKey(key);
        generated.push(created);
    }

    db.logAuditEvent('KEYS_GENERATED', {
        count: keyCount,
        duration_days: durationDaysInt,
        max_activations: maxActivationsInt,
        admin: req.admin.username
    });

    res.json({
        success: true,
        message: `Successfully generated ${keyCount} license key(s).`,
        licenses: generated
    });
});

// Revoke license
app.post('/api/admin/licenses/:id/revoke', requireAdmin, (req, res) => {
    const id = parseInt(req.params.id);
    const license = db.getLicenseById(id);
    if (!license) return res.status(404).json({ success: false, message: 'License not found.' });

    db.updateLicenseStatus(id, 'REVOKED');
    db.logAuditEvent('KEY_REVOKED', { license_id: id, key: license.license_key, admin: req.admin.username });
    res.json({ success: true, message: `License ${license.license_key} revoked.` });
});

// Reactivate license
app.post('/api/admin/licenses/:id/activate', requireAdmin, (req, res) => {
    const id = parseInt(req.params.id);
    const license = db.getLicenseById(id);
    if (!license) return res.status(404).json({ success: false, message: 'License not found.' });

    db.updateLicenseStatus(id, 'ACTIVE');
    db.logAuditEvent('KEY_REACTIVATED', { license_id: id, key: license.license_key, admin: req.admin.username });
    res.json({ success: true, message: `License ${license.license_key} activated.` });
});

// Delete license
app.delete('/api/admin/licenses/:id', requireAdmin, (req, res) => {
    const id = parseInt(req.params.id);
    const license = db.getLicenseById(id);
    if (!license) return res.status(404).json({ success: false, message: 'License not found.' });

    db.deleteLicense(id);
    db.logAuditEvent('KEY_DELETED', { license_id: id, key: license.license_key, admin: req.admin.username });
    res.json({ success: true, message: `License ${license.license_key} deleted.` });
});

// View activations for a license
app.get('/api/admin/licenses/:id/activations', requireAdmin, (req, res) => {
    const id = parseInt(req.params.id);
    const license = db.getLicenseById(id);
    if (!license) return res.status(404).json({ success: false, message: 'License not found.' });

    const activations = db.getActivationsByLicenseId(id);
    res.json({ success: true, license, activations });
});

// Unbind / deactivate device
app.delete('/api/admin/activations/:id', requireAdmin, (req, res) => {
    const id = parseInt(req.params.id);
    db.deactivateDevice(id);
    db.logAuditEvent('DEVICE_UNBOUND', { activation_id: id, admin: req.admin.username });
    res.json({ success: true, message: 'Device unbound successfully. Activation slot freed.' });
});

// View audit logs
app.get('/api/admin/logs', requireAdmin, (req, res) => {
    const logs = db.getAuditLogs(100);
    res.json({ success: true, logs });
});

// Admin UI routes
app.get('/', (req, res) => {
    res.redirect('/admin');
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start Server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`[LICENSE SERVER] Running at http://0.0.0.0:${PORT}`);
    console.log(`[ADMIN DASHBOARD] Available at http://localhost:${PORT}/admin`);
});
