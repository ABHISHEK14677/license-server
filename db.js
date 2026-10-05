const { DatabaseSync } = require('node:sqlite');
const path = require('node:path');
const { hashPassword } = require('./auth');

const DB_PATH = path.join(__dirname, 'licenses.db');
const db = new DatabaseSync(DB_PATH);

// Initialize schema
function initDatabase() {
    db.exec(`
        PRAGMA foreign_keys = ON;

        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS admin_sessions (
            token TEXT PRIMARY KEY,
            admin_id INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME NOT NULL,
            FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT UNIQUE NOT NULL,
            status TEXT DEFAULT 'ACTIVE', -- 'ACTIVE', 'EXPIRED', 'REVOKED'
            duration_days INTEGER DEFAULT 30, -- -1 = Lifetime
            expires_at DATETIME, -- Nullable, calculated on first activation or set explicitly
            max_activations INTEGER DEFAULT 1,
            is_reusable INTEGER DEFAULT 1,
            notes TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS activations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_id INTEGER NOT NULL,
            device_id TEXT NOT NULL,
            device_model TEXT,
            session_token TEXT,
            activated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            is_active INTEGER DEFAULT 1,
            FOREIGN KEY (license_id) REFERENCES licenses(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_licenses_key ON licenses(license_key);
        CREATE INDEX IF NOT EXISTS idx_activations_lic_dev ON activations(license_id, device_id);
    `);
}

initDatabase();

// Admin operations
function getAdminByUsername(username) {
    const stmt = db.prepare('SELECT * FROM admins WHERE username = ?');
    return stmt.get(username);
}

function createAdmin(username, password) {
    const { salt, hash } = hashPassword(password);
    const stmt = db.prepare('INSERT INTO admins (username, password_hash, salt) VALUES (?, ?, ?)');
    return stmt.run(username, hash, salt);
}

function createAdminSession(adminId, token, expiresAt) {
    const stmt = db.prepare('INSERT INTO admin_sessions (token, admin_id, expires_at) VALUES (?, ?, ?)');
    return stmt.run(token, adminId, expiresAt.toISOString());
}

function getAdminSession(token) {
    const stmt = db.prepare(`
        SELECT s.*, a.username 
        FROM admin_sessions s 
        JOIN admins a ON s.admin_id = a.id 
        WHERE s.token = ? AND datetime(s.expires_at) > datetime('now')
    `);
    return stmt.get(token);
}

function deleteAdminSession(token) {
    const stmt = db.prepare('DELETE FROM admin_sessions WHERE token = ?');
    return stmt.run(token);
}

// License operations
function createLicense({ licenseKey, durationDays = 30, expiresAt = null, maxActivations = 1, isReusable = 1, notes = '', status = 'ACTIVE' }) {
    const stmt = db.prepare(`
        INSERT INTO licenses (license_key, status, duration_days, expires_at, max_activations, is_reusable, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    const expiresAtStr = expiresAt instanceof Date ? expiresAt.toISOString() : expiresAt;
    return stmt.run(licenseKey, status, durationDays, expiresAtStr, maxActivations, isReusable, notes);
}

function getLicenseByKey(key) {
    const stmt = db.prepare('SELECT * FROM licenses WHERE license_key = ?');
    return stmt.get(key.trim().toUpperCase());
}

function getLicenseById(id) {
    const stmt = db.prepare('SELECT * FROM licenses WHERE id = ?');
    return stmt.get(id);
}

function getAllLicenses(search = '') {
    let sql = `
        SELECT l.*, 
            COUNT(CASE WHEN a.is_active = 1 THEN 1 END) as active_activations,
            COUNT(a.id) as total_activations
        FROM licenses l
        LEFT JOIN activations a ON l.id = a.license_id
    `;
    const params = [];
    if (search && search.trim().length > 0) {
        sql += ` WHERE l.license_key LIKE ? OR l.notes LIKE ? `;
        const term = `%${search.trim()}%`;
        params.push(term, term);
    }
    sql += ` GROUP BY l.id ORDER BY l.created_at DESC`;
    const stmt = db.prepare(sql);
    return stmt.all(...params);
}

function updateLicenseStatus(id, status) {
    const stmt = db.prepare(`
        UPDATE licenses 
        SET status = ?, updated_at = CURRENT_TIMESTAMP 
        WHERE id = ?
    `);
    return stmt.run(status, id);
}

function updateLicenseExpiry(id, expiresAt) {
    const expiresAtStr = expiresAt instanceof Date ? expiresAt.toISOString() : expiresAt;
    const stmt = db.prepare(`
        UPDATE licenses 
        SET expires_at = ?, updated_at = CURRENT_TIMESTAMP 
        WHERE id = ?
    `);
    return stmt.run(expiresAtStr, id);
}

function deleteLicense(id) {
    const stmt = db.prepare('DELETE FROM licenses WHERE id = ?');
    return stmt.run(id);
}

// Activation operations
function getActiveActivationsCount(licenseId) {
    const stmt = db.prepare('SELECT COUNT(*) as count FROM activations WHERE license_id = ? AND is_active = 1');
    const result = stmt.get(licenseId);
    return result ? result.count : 0;
}

function findDeviceActivation(licenseId, deviceId) {
    const stmt = db.prepare('SELECT * FROM activations WHERE license_id = ? AND device_id = ? AND is_active = 1');
    return stmt.get(licenseId, deviceId);
}

function recordActivation(licenseId, deviceId, deviceModel, sessionToken) {
    const stmt = db.prepare(`
        INSERT INTO activations (license_id, device_id, device_model, session_token)
        VALUES (?, ?, ?, ?)
    `);
    return stmt.run(licenseId, deviceId, deviceModel || 'Unknown Device', sessionToken);
}

function updateActivationLastSeen(activationId) {
    const stmt = db.prepare('UPDATE activations SET last_seen_at = CURRENT_TIMESTAMP WHERE id = ?');
    return stmt.run(activationId);
}

function deactivateDevice(activationId) {
    const stmt = db.prepare('UPDATE activations SET is_active = 0 WHERE id = ?');
    return stmt.run(activationId);
}

function getActivationsByLicenseId(licenseId) {
    const stmt = db.prepare('SELECT * FROM activations WHERE license_id = ? ORDER BY activated_at DESC');
    return stmt.all(licenseId);
}

// Audit logging
function logAuditEvent(eventType, details, ipAddress = '') {
    const stmt = db.prepare('INSERT INTO audit_logs (event_type, details, ip_address) VALUES (?, ?, ?)');
    return stmt.run(eventType, typeof details === 'object' ? JSON.stringify(details) : String(details), ipAddress);
}

function getAuditLogs(limit = 100) {
    const stmt = db.prepare('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?');
    return stmt.all(limit);
}

module.exports = {
    db,
    getAdminByUsername,
    createAdmin,
    createAdminSession,
    getAdminSession,
    deleteAdminSession,
    createLicense,
    getLicenseByKey,
    getLicenseById,
    getAllLicenses,
    updateLicenseStatus,
    updateLicenseExpiry,
    deleteLicense,
    getActiveActivationsCount,
    findDeviceActivation,
    recordActivation,
    updateActivationLastSeen,
    deactivateDevice,
    getActivationsByLicenseId,
    logAuditEvent,
    getAuditLogs
};
