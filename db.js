const path = require('node:path');
const { hashPassword, hashKey, getKeyLast4 } = require('./auth');

const DATABASE_URL = process.env.DATABASE_URL;
let isPostgres = false;
let pgPool = null;
let sqliteDb = null;

if (DATABASE_URL && DATABASE_URL.startsWith('postgres')) {
    isPostgres = true;
    const { Pool } = require('pg');
    pgPool = new Pool({
        connectionString: DATABASE_URL,
        ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
    });
    console.log('[DB] Using PostgreSQL connection pool');
} else {
    const { DatabaseSync } = require('node:sqlite');
    const DB_PATH = path.join(__dirname, 'licenses.db');
    sqliteDb = new DatabaseSync(DB_PATH);
    console.log('[DB] Using local SQLite database:', DB_PATH);
}

// Helper query function that abstracts Postgres ($1, $2) vs SQLite (?, ?)
async function query(sql, params = []) {
    if (isPostgres) {
        let paramIndex = 1;
        const pgSql = sql.replace(/\?/g, () => `$${paramIndex++}`);
        const res = await pgPool.query(pgSql, params);
        return {
            rows: res.rows,
            rowCount: res.rowCount,
            lastID: res.rows[0]?.id || null
        };
    } else {
        const trimmed = sql.trim().toUpperCase();
        if (trimmed.startsWith('SELECT') || trimmed.startsWith('WITH')) {
            const stmt = sqliteDb.prepare(sql);
            const rows = stmt.all(...params);
            return { rows, rowCount: rows.length };
        } else if (trimmed.startsWith('INSERT')) {
            const stmt = sqliteDb.prepare(sql);
            const info = stmt.run(...params);
            return {
                rows: [],
                rowCount: info.changes,
                lastID: Number(info.lastInsertRowid)
            };
        } else {
            const stmt = sqliteDb.prepare(sql);
            const info = stmt.run(...params);
            return {
                rows: [],
                rowCount: info.changes
            };
        }
    }
}

async function queryOne(sql, params = []) {
    const res = await query(sql, params);
    return res.rows[0] || null;
}

// Migration helper for SQLite
function ensureSqliteColumn(table, column, colType) {
    try {
        const cols = sqliteDb.prepare(`PRAGMA table_info(${table})`).all();
        const exists = cols.some(c => c.name === column);
        if (!exists) {
            sqliteDb.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${colType};`);
            console.log(`[DB MIGRATION] Added column ${column} to table ${table}`);
        }
    } catch (e) {
        // Table might not exist yet
    }
}

// Initialize tables and default seed data
async function initDatabase() {
    try {
        if (isPostgres) {
            await pgPool.query(`
                CREATE TABLE IF NOT EXISTS admins (
                    id SERIAL PRIMARY KEY,
                    email VARCHAR(255) UNIQUE,
                    username VARCHAR(100) UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    role VARCHAR(50) DEFAULT 'admin',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS admin_sessions (
                    token VARCHAR(128) PRIMARY KEY,
                    admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL
                );

                CREATE TABLE IF NOT EXISTS products (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(150) UNIQUE NOT NULL,
                    description TEXT,
                    status VARCHAR(50) DEFAULT 'ACTIVE',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS activation_keys (
                    id SERIAL PRIMARY KEY,
                    key_hash VARCHAR(128) UNIQUE NOT NULL,
                    key_last4 VARCHAR(10) NOT NULL,
                    key_display VARCHAR(100) NOT NULL,
                    product_id INTEGER REFERENCES products(id) ON DELETE SET NULL,
                    status VARCHAR(50) DEFAULT 'UNUSED',
                    duration_hours INTEGER DEFAULT 720,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    activated_at TIMESTAMP,
                    expires_at TIMESTAMP,
                    max_devices INTEGER DEFAULT 1,
                    customer_name VARCHAR(255),
                    notes TEXT
                );

                CREATE TABLE IF NOT EXISTS customers (
                    id SERIAL PRIMARY KEY,
                    customer_identifier VARCHAR(150) UNIQUE NOT NULL,
                    name VARCHAR(255),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS devices (
                    id SERIAL PRIMARY KEY,
                    customer_id INTEGER REFERENCES customers(id) ON DELETE SET NULL,
                    device_identifier VARCHAR(255) UNIQUE NOT NULL,
                    device_model VARCHAR(255),
                    app_identifier VARCHAR(255),
                    platform VARCHAR(50) DEFAULT 'Android',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS activations (
                    id SERIAL PRIMARY KEY,
                    key_id INTEGER NOT NULL REFERENCES activation_keys(id) ON DELETE CASCADE,
                    customer_id INTEGER REFERENCES customers(id) ON DELETE SET NULL,
                    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
                    activated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    status VARCHAR(50) DEFAULT 'ACTIVE',
                    last_verified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    session_token VARCHAR(128)
                );

                CREATE TABLE IF NOT EXISTS audit_logs (
                    id SERIAL PRIMARY KEY,
                    event_type VARCHAR(100) NOT NULL,
                    details TEXT,
                    ip_address VARCHAR(100),
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE INDEX IF NOT EXISTS idx_keys_hash ON activation_keys(key_hash);
                CREATE INDEX IF NOT EXISTS idx_keys_status ON activation_keys(status);
            `);
        } else {
            sqliteDb.exec(`
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

                CREATE TABLE IF NOT EXISTS products (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    description TEXT,
                    status TEXT DEFAULT 'ACTIVE',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS activation_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_hash TEXT UNIQUE NOT NULL,
                    key_last4 TEXT NOT NULL,
                    key_display TEXT NOT NULL,
                    product_id INTEGER,
                    status TEXT DEFAULT 'UNUSED',
                    duration_hours INTEGER DEFAULT 720,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    activated_at DATETIME,
                    expires_at DATETIME,
                    max_devices INTEGER DEFAULT 1,
                    customer_name TEXT,
                    notes TEXT,
                    FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE SET NULL
                );

                CREATE TABLE IF NOT EXISTS customers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    customer_identifier TEXT UNIQUE NOT NULL,
                    name TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    customer_id INTEGER,
                    device_identifier TEXT UNIQUE NOT NULL,
                    device_model TEXT,
                    app_identifier TEXT,
                    platform TEXT DEFAULT 'Android',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE SET NULL
                );

                CREATE TABLE IF NOT EXISTS activations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_id INTEGER,
                    customer_id INTEGER,
                    device_id INTEGER,
                    activated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    expires_at DATETIME,
                    status TEXT DEFAULT 'ACTIVE',
                    last_verified_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    session_token TEXT,
                    FOREIGN KEY (key_id) REFERENCES activation_keys(id) ON DELETE CASCADE,
                    FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE SET NULL,
                    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    details TEXT,
                    ip_address TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                );
            `);

            // Apply migrations to existing tables
            ensureSqliteColumn('admins', 'email', 'TEXT');
            ensureSqliteColumn('admins', 'role', "TEXT DEFAULT 'admin'");
            ensureSqliteColumn('admins', 'updated_at', 'DATETIME');

            ensureSqliteColumn('activations', 'key_id', 'INTEGER');
            ensureSqliteColumn('activations', 'customer_id', 'INTEGER');
            ensureSqliteColumn('activations', 'expires_at', 'DATETIME');
            ensureSqliteColumn('activations', 'status', "TEXT DEFAULT 'ACTIVE'");
            ensureSqliteColumn('activations', 'last_verified_at', 'DATETIME');
        }

        // Seed default product
        const defaultProduct = await queryOne('SELECT * FROM products WHERE name = ?', ['ADB Optimizer']);
        if (!defaultProduct) {
            await query('INSERT INTO products (name, description, status) VALUES (?, ?, ?)', [
                'ADB Optimizer',
                'Advanced Android Optimizer and Background Runner License',
                'ACTIVE'
            ]);
            console.log('[INIT] Created default product: ADB Optimizer');
        }

        // Ensure default admin exists
        const adminCheck = await queryOne('SELECT COUNT(*) as count FROM admins');
        const count = adminCheck ? Number(adminCheck.count) : 0;
        if (count === 0) {
            const defaultUser = process.env.ADMIN_USERNAME || 'admin';
            const defaultPass = process.env.ADMIN_PASSWORD || 'admin123';
            const defaultEmail = process.env.ADMIN_EMAIL || 'admin@rootoptimizer.com';
            const { salt, hash } = hashPassword(defaultPass);
            await query(
                'INSERT INTO admins (email, username, password_hash, salt, role) VALUES (?, ?, ?, ?, ?)',
                [defaultEmail, defaultUser, hash, salt, 'superadmin']
            );
            console.log(`[INIT] Created default admin: "${defaultUser}" with password: "${defaultPass}"`);
        }

        // Auto-migrate legacy licenses table into activation_keys if table exists
        try {
            const legacyRes = await query('SELECT * FROM licenses');
            if (legacyRes && legacyRes.rows && legacyRes.rows.length > 0) {
                const prodId = defaultProduct ? defaultProduct.id : 1;
                for (const lic of legacyRes.rows) {
                    if (!lic.license_key) continue;
                    const keyClean = lic.license_key.trim().toUpperCase();
                    const khash = hashKey(keyClean);
                    const exists = await queryOne('SELECT id FROM activation_keys WHERE key_hash = ?', [khash]);
                    if (!exists) {
                        const last4 = getKeyLast4(keyClean);
                        const durationH = (lic.duration_days && lic.duration_days > 0) ? (lic.duration_days * 24) : 720;
                        await query(`
                            INSERT INTO activation_keys (
                                key_hash, key_last4, key_display, product_id, status, duration_hours,
                                created_at, activated_at, expires_at, max_devices, customer_name, notes
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        `, [
                            khash,
                            last4,
                            keyClean,
                            prodId,
                            lic.status || 'ACTIVE',
                            durationH,
                            lic.created_at || new Date().toISOString(),
                            lic.activated_at || null,
                            lic.expires_at || null,
                            lic.max_activations || 1,
                            'Legacy Licensee',
                            lic.notes || 'Migrated from legacy licenses table'
                        ]);
                        console.log(`[INIT] Migrated legacy key: ${keyClean}`);
                    }
                }
            }
        } catch (e) {
            // licenses table may not exist, ignore
        }
    } catch (err) {
        console.error('[INIT] Database initialization error:', err.message);
    }
}

// -------------------------------------------------------------
// Admin & Auth Operations
// -------------------------------------------------------------
async function getAdminByUsername(username) {
    return await queryOne('SELECT * FROM admins WHERE username = ? OR email = ?', [username, username]);
}

async function getAdminById(id) {
    return await queryOne('SELECT id, email, username, role, created_at FROM admins WHERE id = ?', [id]);
}

async function createAdmin(username, password, email = null, role = 'admin') {
    const { salt, hash } = hashPassword(password);
    const effectiveEmail = email || `${username.toLowerCase()}@rootoptimizer.com`;
    return await query(
        'INSERT INTO admins (email, username, password_hash, salt, role) VALUES (?, ?, ?, ?, ?)',
        [effectiveEmail, username, hash, salt, role]
    );
}

async function updateAdminPassword(adminId, newPassword) {
    const { salt, hash } = hashPassword(newPassword);
    return await query(
        'UPDATE admins SET password_hash = ?, salt = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
        [hash, salt, adminId]
    );
}

async function createAdminSession(adminId, token, expiresAt) {
    const expiresStr = expiresAt instanceof Date ? expiresAt.toISOString() : expiresAt;
    return await query(
        'INSERT INTO admin_sessions (token, admin_id, expires_at) VALUES (?, ?, ?)',
        [token, adminId, expiresStr]
    );
}

async function getAdminSession(token) {
    const res = await queryOne(`
        SELECT s.*, a.username, a.email, a.role 
        FROM admin_sessions s 
        JOIN admins a ON s.admin_id = a.id 
        WHERE s.token = ?
    `, [token]);

    if (!res) return null;
    const expires = new Date(res.expires_at).getTime();
    if (Date.now() > expires) {
        await deleteAdminSession(token);
        return null;
    }
    return res;
}

async function deleteAdminSession(token) {
    return await query('DELETE FROM admin_sessions WHERE token = ?', [token]);
}

// -------------------------------------------------------------
// Products
// -------------------------------------------------------------
async function getAllProducts() {
    const res = await query('SELECT * FROM products ORDER BY name ASC');
    return res.rows;
}

async function getOrCreateProduct(name, description = '') {
    const existing = await queryOne('SELECT * FROM products WHERE name = ?', [name]);
    if (existing) return existing;
    await query('INSERT INTO products (name, description, status) VALUES (?, ?, ?)', [
        name,
        description || `${name} Service`,
        'ACTIVE'
    ]);
    return await queryOne('SELECT * FROM products WHERE name = ?', [name]);
}

// -------------------------------------------------------------
// Key Management
// -------------------------------------------------------------
async function createActivationKey({
    keyString,
    productId,
    durationHours = 720,
    maxDevices = 1,
    customerName = null,
    notes = ''
}) {
    const keyHash = hashKey(keyString);
    const keyLast4 = getKeyLast4(keyString);
    const keyDisplay = keyString.trim().toUpperCase();

    await query(`
        INSERT INTO activation_keys (
            key_hash, key_last4, key_display, product_id, status, 
            duration_hours, max_devices, customer_name, notes
        ) VALUES (?, ?, ?, ?, 'UNUSED', ?, ?, ?, ?)
    `, [
        keyHash,
        keyLast4,
        keyDisplay,
        productId,
        durationHours,
        maxDevices,
        customerName || null,
        notes || ''
    ]);

    return await getKeyByHash(keyHash);
}

async function getKeyByHash(keyHash) {
    return await queryOne(`
        SELECT k.*, p.name as product_name
        FROM activation_keys k
        LEFT JOIN products p ON k.product_id = p.id
        WHERE k.key_hash = ?
    `, [keyHash]);
}

async function getKeyById(id) {
    return await queryOne(`
        SELECT k.*, p.name as product_name
        FROM activation_keys k
        LEFT JOIN products p ON k.product_id = p.id
        WHERE k.id = ?
    `, [id]);
}

async function getAllKeys({ search = '', status = '', limit = 100 } = {}) {
    let sql = `
        SELECT k.*, p.name as product_name,
               (SELECT COUNT(*) FROM activations a WHERE a.key_id = k.id AND a.status = 'ACTIVE') as active_devices_count,
               (SELECT d.device_model FROM activations a JOIN devices d ON a.device_id = d.id WHERE a.key_id = k.id ORDER BY a.activated_at DESC LIMIT 1) as last_device_model
        FROM activation_keys k
        LEFT JOIN products p ON k.product_id = p.id
        WHERE 1=1
    `;
    const params = [];

    if (status && status !== 'ALL') {
        sql += ` AND k.status = ?`;
        params.push(status.toUpperCase());
    }

    if (search && search.trim()) {
        const s = `%${search.trim()}%`;
        sql += ` AND (k.key_display LIKE ? OR k.customer_name LIKE ? OR k.notes LIKE ? OR p.name LIKE ?)`;
        params.push(s, s, s, s);
    }

    sql += ` ORDER BY k.created_at DESC LIMIT ?`;
    params.push(limit);

    const res = await query(sql, params);

    // Auto-update expired keys if applicable
    const now = Date.now();
    for (const key of res.rows) {
        if (key.status === 'ACTIVE' && key.expires_at) {
            const expTime = new Date(key.expires_at).getTime();
            if (now > expTime) {
                key.status = 'EXPIRED';
                await query('UPDATE activation_keys SET status = ? WHERE id = ?', ['EXPIRED', key.id]);
            }
        }
    }

    return res.rows;
}

async function updateKeyStatus(id, newStatus) {
    await query('UPDATE activation_keys SET status = ? WHERE id = ?', [newStatus, id]);
    if (newStatus === 'REVOKED' || newStatus === 'SUSPENDED') {
        await query('UPDATE activations SET status = ? WHERE key_id = ?', [newStatus, id]);
    } else if (newStatus === 'ACTIVE') {
        await query("UPDATE activations SET status = 'ACTIVE' WHERE key_id = ?", [id]);
    }
    return await getKeyById(id);
}

async function deleteKey(id) {
    await query('DELETE FROM activations WHERE key_id = ?', [id]);
    return await query('DELETE FROM activation_keys WHERE id = ?', [id]);
}

// -------------------------------------------------------------
// Customers & Devices
// -------------------------------------------------------------
async function getOrCreateCustomer(identifier, name = null) {
    if (!identifier) identifier = `cust_${Date.now()}`;
    let cust = await queryOne('SELECT * FROM customers WHERE customer_identifier = ?', [identifier]);
    if (!cust) {
        await query('INSERT INTO customers (customer_identifier, name) VALUES (?, ?)', [identifier, name || identifier]);
        cust = await queryOne('SELECT * FROM customers WHERE customer_identifier = ?', [identifier]);
    }
    return cust;
}

async function getOrCreateDevice(customerId, deviceId, deviceModel = null, appIdentifier = null, platform = 'Android') {
    let dev = await queryOne('SELECT * FROM devices WHERE device_identifier = ?', [deviceId]);
    if (!dev) {
        await query(`
            INSERT INTO devices (customer_id, device_identifier, device_model, app_identifier, platform) 
            VALUES (?, ?, ?, ?, ?)
        `, [
            customerId,
            deviceId,
            deviceModel || 'Android Device',
            appIdentifier || 'com.example.rootoptimizer',
            platform
        ]);
        dev = await queryOne('SELECT * FROM devices WHERE device_identifier = ?', [deviceId]);
    } else {
        await query(`
            UPDATE devices 
            SET device_model = COALESCE(?, device_model),
                last_seen_at = CURRENT_TIMESTAMP
            WHERE id = ?
        `, [deviceModel, dev.id]);
    }
    return dev;
}

// -------------------------------------------------------------
// Activations
// -------------------------------------------------------------
async function findActivation(keyId, deviceId) {
    return await queryOne(`
        SELECT a.*, d.device_identifier, d.device_model
        FROM activations a
        JOIN devices d ON a.device_id = d.id
        WHERE (a.key_id = ? OR a.license_id = ?) AND a.device_id = ?
    `, [keyId, keyId, deviceId]);
}

async function getActiveActivationsCount(keyId) {
    const res = await queryOne(`
        SELECT COUNT(*) as count FROM activations 
        WHERE (key_id = ? OR license_id = ?) AND (status = 'ACTIVE' OR is_active = 1)
    `, [keyId, keyId]);
    return res ? Number(res.count) : 0;
}

async function getKeyActivations(keyId) {
    const res = await query(`
        SELECT a.*, d.device_identifier, d.device_model, d.platform, d.last_seen_at as device_last_seen
        FROM activations a
        JOIN devices d ON a.device_id = d.id
        WHERE (a.key_id = ? OR a.license_id = ?)
        ORDER BY a.activated_at DESC
    `, [keyId, keyId]);
    return res.rows;
}

async function recordActivation({ keyId, customerId, deviceId, expiresAt, sessionToken }) {
    const expiresStr = expiresAt instanceof Date ? expiresAt.toISOString() : expiresAt;
    return await query(`
        INSERT INTO activations (key_id, license_id, customer_id, device_id, expires_at, status, session_token)
        VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?)
    `, [keyId, keyId, customerId, deviceId, expiresStr, sessionToken]);
}

async function updateActivationLastSeen(activationId, sessionToken = null) {
    if (sessionToken) {
        return await query(`
            UPDATE activations 
            SET last_verified_at = CURRENT_TIMESTAMP, last_seen_at = CURRENT_TIMESTAMP, session_token = ?
            WHERE id = ?
        `, [sessionToken, activationId]);
    } else {
        return await query(`
            UPDATE activations 
            SET last_verified_at = CURRENT_TIMESTAMP, last_seen_at = CURRENT_TIMESTAMP 
            WHERE id = ?
        `, [activationId]);
    }
}

async function deactivateDevice(keyId, deviceId) {
    return await query(`
        UPDATE activations 
        SET status = 'INACTIVE', is_active = 0 
        WHERE (key_id = ? OR license_id = ?) AND device_id = ?
    `, [keyId, keyId, deviceId]);
}

// -------------------------------------------------------------
// Dashboard Statistics
// -------------------------------------------------------------
async function getDashboardStats() {
    const totalKeysRes = await queryOne('SELECT COUNT(*) as count FROM activation_keys');
    const activeKeysRes = await queryOne("SELECT COUNT(*) as count FROM activation_keys WHERE status = 'ACTIVE'");
    const unusedKeysRes = await queryOne("SELECT COUNT(*) as count FROM activation_keys WHERE status = 'UNUSED'");
    const expiredKeysRes = await queryOne("SELECT COUNT(*) as count FROM activation_keys WHERE status = 'EXPIRED'");
    const revokedKeysRes = await queryOne("SELECT COUNT(*) as count FROM activation_keys WHERE status = 'REVOKED'");
    const suspendedKeysRes = await queryOne("SELECT COUNT(*) as count FROM activation_keys WHERE status = 'SUSPENDED'");
    const customersRes = await queryOne('SELECT COUNT(*) as count FROM customers');
    const devicesRes = await queryOne("SELECT COUNT(*) as count FROM activations WHERE status = 'ACTIVE'");

    return {
        total_keys: Number(totalKeysRes?.count || 0),
        active_keys: Number(activeKeysRes?.count || 0),
        unused_keys: Number(unusedKeysRes?.count || 0),
        expired_keys: Number(expiredKeysRes?.count || 0),
        revoked_keys: Number(revokedKeysRes?.count || 0),
        suspended_keys: Number(suspendedKeysRes?.count || 0),
        active_customers: Number(customersRes?.count || 0),
        activated_devices: Number(devicesRes?.count || 0)
    };
}

// -------------------------------------------------------------
// Audit Logs
// -------------------------------------------------------------
async function logAuditEvent(eventType, details = {}, ip = '127.0.0.1') {
    try {
        const detailsStr = typeof details === 'string' ? details : JSON.stringify(details);
        await query('INSERT INTO audit_logs (event_type, details, ip_address) VALUES (?, ?, ?)', [
            eventType,
            detailsStr,
            ip
        ]);
    } catch (e) {
        console.error('[AUDIT] Failed to write log:', e.message);
    }
}

async function getRecentLogs(limit = 50) {
    const res = await query('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?', [limit]);
    return res.rows;
}

module.exports = {
    query,
    queryOne,
    initDatabase,
    // Admin
    getAdminByUsername,
    getAdminById,
    createAdmin,
    updateAdminPassword,
    createAdminSession,
    getAdminSession,
    deleteAdminSession,
    // Products
    getAllProducts,
    getOrCreateProduct,
    // Keys
    createActivationKey,
    getKeyByHash,
    getKeyById,
    getAllKeys,
    updateKeyStatus,
    deleteKey,
    // Customers & Devices
    getOrCreateCustomer,
    getOrCreateDevice,
    // Activations
    findActivation,
    getActiveActivationsCount,
    getKeyActivations,
    recordActivation,
    updateActivationLastSeen,
    deactivateDevice,
    // Stats & Logs
    getDashboardStats,
    logAuditEvent,
    getRecentLogs
};
