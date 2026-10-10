const path = require('node:path');
const fs = require('node:fs');
const { hashPassword, hashKey, getKeyLast4 } = require('./auth');

// Load environment variables from .env if present
const envPath = path.join(__dirname, '.env');
if (fs.existsSync(envPath)) {
    const lines = fs.readFileSync(envPath, 'utf8').split('\n');
    for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed && !trimmed.startsWith('#')) {
            const idx = trimmed.indexOf('=');
            if (idx !== -1) {
                const k = trimmed.substring(0, idx).trim();
                const v = trimmed.substring(idx + 1).trim();
                if (process.env[k] === undefined) process.env[k] = v;
            }
        }
    }
}

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

const SEED_FILE_PATH = path.join(__dirname, 'seed-keys.json');

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
                    license_id INTEGER,
                    customer_id INTEGER REFERENCES customers(id) ON DELETE SET NULL,
                    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
                    activated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    status VARCHAR(50) DEFAULT 'ACTIVE',
                    last_verified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    session_token VARCHAR(128),
                    is_active INTEGER DEFAULT 1
                );

                CREATE TABLE IF NOT EXISTS audit_logs (
                    id SERIAL PRIMARY KEY,
                    event_type VARCHAR(100) NOT NULL,
                    details TEXT,
                    ip_address VARCHAR(100),
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS deleted_keys (
                    id SERIAL PRIMARY KEY,
                    key_hash VARCHAR(128) UNIQUE NOT NULL,
                    key_display VARCHAR(100),
                    deleted_by VARCHAR(100) DEFAULT 'admin',
                    reason TEXT,
                    deleted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE INDEX IF NOT EXISTS idx_keys_hash ON activation_keys(key_hash);
                CREATE INDEX IF NOT EXISTS idx_keys_status ON activation_keys(status);
                CREATE INDEX IF NOT EXISTS idx_deleted_keys_hash ON deleted_keys(key_hash);
            `);

            try {
                await pgPool.query(`
                    ALTER TABLE activations ADD COLUMN IF NOT EXISTS license_id INTEGER;
                    ALTER TABLE activations ADD COLUMN IF NOT EXISTS is_active INTEGER DEFAULT 1;
                    ALTER TABLE activations ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
                    ALTER TABLE activations ADD COLUMN IF NOT EXISTS session_token VARCHAR(128);
                `);
            } catch (e) {
                // Columns may already exist
            }
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
                    license_id INTEGER,
                    customer_id INTEGER,
                    device_id INTEGER,
                    activated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    expires_at DATETIME,
                    status TEXT DEFAULT 'ACTIVE',
                    last_verified_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    session_token TEXT,
                    is_active INTEGER DEFAULT 1,
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

                CREATE TABLE IF NOT EXISTS deleted_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_hash TEXT UNIQUE NOT NULL,
                    key_display TEXT,
                    deleted_by TEXT DEFAULT 'admin',
                    reason TEXT,
                    deleted_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );
            `);

            // Apply migrations to existing tables
            ensureSqliteColumn('admins', 'email', 'TEXT');
            ensureSqliteColumn('admins', 'role', "TEXT DEFAULT 'admin'");
            ensureSqliteColumn('admins', 'updated_at', 'DATETIME');

            ensureSqliteColumn('activations', 'key_id', 'INTEGER');
            ensureSqliteColumn('activations', 'license_id', 'INTEGER');
            ensureSqliteColumn('activations', 'customer_id', 'INTEGER');
            ensureSqliteColumn('activations', 'expires_at', 'DATETIME');
            ensureSqliteColumn('activations', 'status', "TEXT DEFAULT 'ACTIVE'");
            ensureSqliteColumn('activations', 'last_verified_at', 'DATETIME');
            ensureSqliteColumn('activations', 'last_seen_at', 'DATETIME');
            ensureSqliteColumn('activations', 'session_token', 'TEXT');
            ensureSqliteColumn('activations', 'is_active', "INTEGER DEFAULT 1");

            // Clean up legacy activations with null key_id
            try {
                await query('UPDATE activations SET key_id = license_id WHERE key_id IS NULL AND license_id IS NOT NULL');
                await query('DELETE FROM activations WHERE key_id IS NULL');
            } catch (e) {}
        }

        // Seed default product: Zexora
        let defaultProduct = await queryOne('SELECT * FROM products WHERE name = ?', ['Zexora']);
        if (!defaultProduct) {
            defaultProduct = await queryOne('SELECT * FROM products WHERE name = ? OR name = ?', ['Optimizer', 'ADB Optimizer']);
            if (defaultProduct) {
                await query('UPDATE products SET name = ?, description = ? WHERE id = ?', [
                    'Zexora',
                    'Zexora - Developed by MADARA FF',
                    defaultProduct.id
                ]);
            } else {
                await query('INSERT INTO products (name, description, status) VALUES (?, ?, ?)', [
                    'Zexora',
                    'Zexora - Developed by MADARA FF',
                    'ACTIVE'
                ]);
            }
            console.log('[INIT] Default product set to: Zexora');
        }

        // Ensure admin MADARA-FF exists with configured credentials
        const adminUser = process.env.ADMIN_USERNAME || 'MADARA-FF';
        const adminPass = process.env.ADMIN_PASSWORD || 'ABHISHEK!';
        const adminEmail = process.env.ADMIN_EMAIL || 'madara-ff@rootoptimizer.com';
        const existingAdmin = await queryOne('SELECT id, salt, password_hash FROM admins WHERE username = ?', [adminUser]);

        const { salt, hash } = hashPassword(adminPass);
        if (!existingAdmin) {
            await query(
                'INSERT INTO admins (email, username, password_hash, salt, role) VALUES (?, ?, ?, ?, ?)',
                [adminEmail, adminUser, hash, salt, 'superadmin']
            );
            console.log(`[INIT] Created secure admin account: "${adminUser}"`);
        } else {
            await query(
                'UPDATE admins SET password_hash = ?, salt = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
                [hash, salt, existingAdmin.id]
            );
            console.log(`[INIT] Verified/Updated admin account credentials for: "${adminUser}"`);
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

        // Restore persistent keys and active devices from seed-keys.json
        await importSeedKeys();
    } catch (err) {
        console.error('[INIT] Database initialization error:', err.message);
    }
}

// -------------------------------------------------------------
// Persistent Seed Storage (seed-keys.json)
// -------------------------------------------------------------
async function exportSeedKeys() {
    try {
        const keysRes = await query(`
            SELECT k.*, p.name as product_name
            FROM activation_keys k
            LEFT JOIN products p ON k.product_id = p.id
            ORDER BY k.created_at ASC
        `);

        // Load existing seed keys from file as persistent baseline so keys are NEVER accidentally wiped
        const existingSeedMap = new Map();
        if (fs.existsSync(SEED_FILE_PATH)) {
            try {
                const rawExisting = fs.readFileSync(SEED_FILE_PATH, 'utf8').trim();
                if (rawExisting) {
                    const parsed = JSON.parse(rawExisting);
                    if (Array.isArray(parsed)) {
                        for (const item of parsed) {
                            const kStr = (item.key || item.key_display || '').trim().toUpperCase();
                            if (kStr) existingSeedMap.set(kStr, item);
                        }
                    }
                }
            } catch (e) {
                console.warn('[SEED] Could not read existing seed-keys.json:', e.message);
            }
        }

        // Filter out any keys that have been explicitly deleted
        try {
            const delRes = await query("SELECT key_hash, key_display FROM deleted_keys");
            if (delRes && delRes.rows) {
                for (const del of delRes.rows) {
                    if (del.key_display) existingSeedMap.delete(del.key_display.trim().toUpperCase());
                    for (const [kStr, _] of existingSeedMap) {
                        if (hashKey(kStr) === del.key_hash) {
                            existingSeedMap.delete(kStr);
                        }
                    }
                }
            }
        } catch (e) {
            // deleted_keys query failure is non-fatal
        }

        const dbRows = (keysRes && keysRes.rows) ? keysRes.rows : [];
        if (dbRows.length === 0 && existingSeedMap.size > 0) {
            console.log(`[SEED] Database has 0 keys; preserving existing ${existingSeedMap.size} seed keys in seed-keys.json`);
            return Array.from(existingSeedMap.values());
        }

        for (const k of dbRows) {
            const activationsRes = await query(`
                SELECT a.*, d.device_identifier, d.device_model, d.platform
                FROM activations a
                JOIN devices d ON a.device_id = d.id
                WHERE a.key_id = ?
            `, [k.id]);

            const acts = activationsRes.rows || [];
            let effectiveStatus = k.status;
            if (effectiveStatus === 'UNUSED' && (k.activated_at || acts.some(a => a.status === 'ACTIVE'))) {
                effectiveStatus = 'ACTIVE';
                await query("UPDATE activation_keys SET status = 'ACTIVE' WHERE id = ?", [k.id]);
            }

            const item = {
                key: k.key_display,
                product: k.product_name || 'Optimizer',
                status: effectiveStatus,
                duration_hours: k.duration_hours,
                created_at: k.created_at,
                activated_at: k.activated_at,
                expires_at: k.expires_at,
                max_devices: k.max_devices,
                customer_name: k.customer_name,
                notes: k.notes || '',
                activations: acts.map(a => ({
                    device_identifier: a.device_identifier,
                    device_model: a.device_model,
                    platform: a.platform || 'Android',
                    activated_at: a.activated_at,
                    expires_at: a.expires_at,
                    status: a.status || 'ACTIVE',
                    session_token: a.session_token,
                    last_seen_at: a.last_seen_at
                }))
            };

            const kUpper = (k.key_display || '').trim().toUpperCase();
            if (kUpper) {
                existingSeedMap.set(kUpper, item);
            }
        }

        const finalOutput = Array.from(existingSeedMap.values());
        if (finalOutput.length > 0) {
            fs.writeFileSync(SEED_FILE_PATH, JSON.stringify(finalOutput, null, 2), 'utf8');
        }
        return finalOutput;
    } catch (err) {
        console.error('[SEED] Failed to export seed-keys.json:', err.message);
        return [];
    }
}

async function importSeedKeys(customList = null) {
    try {
        let seedList = customList;
        if (!seedList) {
            if (!fs.existsSync(SEED_FILE_PATH)) return 0;
            const raw = fs.readFileSync(SEED_FILE_PATH, 'utf8').trim();
            if (!raw) return 0;
            seedList = JSON.parse(raw);
        }
        if (!Array.isArray(seedList) || seedList.length === 0) return 0;

        let defaultProduct = await queryOne('SELECT * FROM products WHERE name = ?', ['Zexora']) ||
                             await queryOne('SELECT * FROM products WHERE name = ?', ['Optimizer']);
        const prodId = defaultProduct ? defaultProduct.id : 1;
        let count = 0;

        for (const item of seedList) {
            const keyString = (item.key || item.key_display || item.license_key || '').trim().toUpperCase();
            if (!keyString) continue;

            const khash = hashKey(keyString);
            const last4 = getKeyLast4(keyString);

            let existing = await queryOne('SELECT * FROM activation_keys WHERE key_hash = ?', [khash]);
            let keyId = null;

            const itemDuration = (item.duration_hours !== undefined && item.duration_hours !== null) ? parseInt(item.duration_hours, 10) : 720;

            if (!existing) {
                const insertRes = await query(`
                    INSERT INTO activation_keys (
                        key_hash, key_last4, key_display, product_id, status, duration_hours,
                        created_at, activated_at, expires_at, max_devices, customer_name, notes
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                `, [
                    khash,
                    last4,
                    keyString,
                    prodId,
                    item.status || 'UNUSED',
                    itemDuration,
                    item.created_at || new Date().toISOString(),
                    item.activated_at || null,
                    item.expires_at || null,
                    item.max_devices || 1,
                    item.customer_name || null,
                    item.notes || ''
                ]);
                const created = await queryOne('SELECT id FROM activation_keys WHERE key_hash = ?', [khash]);
                keyId = created ? created.id : insertRes.lastID;
                count++;
                console.log(`[SEED] Restored persistent key: ${keyString} (${item.status || 'UNUSED'})`);
            } else {
                keyId = existing.id;
                // If seed has newer status, duration or timestamps, update DB without overwriting valid durations with defaults
                if (item.status && (item.status !== existing.status || item.activated_at !== existing.activated_at || item.expires_at !== existing.expires_at || (item.duration_hours !== undefined && item.duration_hours !== existing.duration_hours))) {
                    await query(`
                        UPDATE activation_keys 
                        SET status = ?, 
                            duration_hours = COALESCE(?, duration_hours),
                            activated_at = COALESCE(?, activated_at), 
                            expires_at = COALESCE(?, expires_at),
                            customer_name = COALESCE(customer_name, ?),
                            notes = COALESCE(notes, ?)
                        WHERE id = ?
                    `, [item.status, item.duration_hours !== undefined ? parseInt(item.duration_hours, 10) : existing.duration_hours, item.activated_at || null, item.expires_at || null, item.customer_name || null, item.notes || null, keyId]);
                    count++;
                }
            }

            // Restore activations if present in seed file
            if (item.activations && Array.isArray(item.activations) && keyId) {
                for (const act of item.activations) {
                    if (!act.device_identifier) continue;
                    const custName = item.customer_name || `user_${act.device_identifier.slice(0, 8)}`;
                    const customer = await getOrCreateCustomer(custName, item.customer_name);
                    const device = await getOrCreateDevice(customer.id, act.device_identifier, act.device_model || 'Android Device', 'com.example.zexora', act.platform || 'Android');

                    const existingAct = await findActivation(keyId, device.id);
                    if (!existingAct) {
                        await query(`
                            INSERT INTO activations (
                                key_id, license_id, customer_id, device_id, activated_at, expires_at, status, session_token, last_seen_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        `, [
                            keyId, keyId, customer.id, device.id,
                            act.activated_at || new Date().toISOString(),
                            act.expires_at || null,
                            act.status || 'ACTIVE',
                            act.session_token || null,
                            act.last_seen_at || act.activated_at || new Date().toISOString()
                        ]);
                        console.log(`[SEED] Restored device activation for key ${keyString} on ${act.device_identifier}`);
                    } else if (act.session_token && !existingAct.session_token) {
                        await query(`UPDATE activations SET session_token = ?, status = ? WHERE id = ?`, [act.session_token, act.status || 'ACTIVE', existingAct.id]);
                    }
                }
            }
        }

        await exportSeedKeys();
        return count;
    } catch (err) {
        console.error('[SEED] Failed to import seed keys:', err.message);
        return 0;
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
    if (!token || typeof token !== 'string') return null;
    const cleanToken = token.trim();
    if (!cleanToken) return null;

    const res = await queryOne(`
        SELECT s.*, a.username, a.email, a.role 
        FROM admin_sessions s 
        JOIN admins a ON s.admin_id = a.id 
        WHERE s.token = ?
    `, [cleanToken]);

    if (!res) return null;
    const expires = new Date(res.expires_at).getTime();
    if (!isNaN(expires) && Date.now() > expires) {
        await deleteAdminSession(cleanToken);
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

    const created = await getKeyByHash(keyHash);
    await exportSeedKeys();
    return created;
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
    // Self-heal: ensure keys with active devices or activated_at are marked ACTIVE
    try {
        await query(`
            UPDATE activation_keys 
            SET status = 'ACTIVE' 
            WHERE status = 'UNUSED' AND (
                activated_at IS NOT NULL 
                OR id IN (SELECT key_id FROM activations WHERE key_id IS NOT NULL AND (status = 'ACTIVE' OR is_active = 1))
            )
        `);
    } catch (e) {
        // Non-fatal
    }

    let sql = `
        SELECT k.*, p.name as product_name,
               (SELECT COUNT(*) FROM activations a WHERE a.key_id = k.id AND (a.status = 'ACTIVE' OR a.is_active = 1)) as active_devices_count,
               (SELECT d.device_model FROM activations a JOIN devices d ON a.device_id = d.id WHERE a.key_id = k.id ORDER BY a.activated_at DESC LIMIT 1) as last_device_model
        FROM activation_keys k
        LEFT JOIN products p ON k.product_id = p.id
        WHERE 1=1
    `;
    const params = [];

    if (status && status !== 'ALL') {
        const s = status.toUpperCase();
        if (s === 'ACTIVE') {
            sql += ` AND (k.status = 'ACTIVE' OR (SELECT COUNT(*) FROM activations a WHERE a.key_id = k.id AND (a.status = 'ACTIVE' OR a.is_active = 1)) > 0)`;
        } else if (s === 'UNUSED' || s === 'INACTIVE') {
            sql += ` AND (k.status = 'UNUSED' AND (SELECT COUNT(*) FROM activations a WHERE a.key_id = k.id AND (a.status = 'ACTIVE' OR a.is_active = 1)) = 0)`;
        } else {
            sql += ` AND k.status = ?`;
            params.push(s);
        }
    }

    if (search && search.trim()) {
        const s = `%${search.trim()}%`;
        sql += ` AND (k.key_display LIKE ? OR k.customer_name LIKE ? OR k.notes LIKE ? OR p.name LIKE ?)`;
        params.push(s, s, s, s);
    }

    sql += ` ORDER BY k.created_at DESC LIMIT ?`;
    params.push(limit);

    const res = await query(sql, params);

    // Auto-update expired keys or active status if activated
    const now = Date.now();
    for (const key of res.rows) {
        if (key.status === 'ACTIVE' && key.expires_at) {
            const expTime = new Date(key.expires_at).getTime();
            if (now > expTime) {
                key.status = 'EXPIRED';
                await query('UPDATE activation_keys SET status = ? WHERE id = ?', ['EXPIRED', key.id]);
            }
        } else if (key.status === 'UNUSED' && (key.activated_at || key.active_devices_count > 0)) {
            key.status = 'ACTIVE';
            await query("UPDATE activation_keys SET status = 'ACTIVE' WHERE id = ?", [key.id]);
        }
    }

    return res.rows;
}

async function getKeyByIdOrString(idOrKey) {
    if (!idOrKey) return null;
    const str = String(idOrKey).trim();
    if (/^\d+$/.test(str)) {
        const byId = await getKeyById(parseInt(str, 10));
        if (byId) return byId;
    }
    const khash = hashKey(str);
    const byHash = await getKeyByHash(khash);
    if (byHash) return byHash;
    return await queryOne(`
        SELECT k.*, p.name as product_name
        FROM activation_keys k
        LEFT JOIN products p ON k.product_id = p.id
        WHERE UPPER(k.key_display) = ?
    `, [str.toUpperCase()]);
}

async function updateKeyDetails(id, { notes, customerName, maxDevices, status, keyDisplay, durationHours, expiresAt, activatedAt }) {
    const fields = [];
    const params = [];

    if (keyDisplay !== undefined && String(keyDisplay).trim().length > 0) {
        const cleanKey = String(keyDisplay).trim().toUpperCase();
        fields.push('key_display = ?');
        params.push(cleanKey);
        fields.push('key_hash = ?');
        params.push(hashKey(cleanKey));
        fields.push('key_last4 = ?');
        params.push(getKeyLast4(cleanKey));
    }
    if (durationHours !== undefined) {
        fields.push('duration_hours = ?');
        params.push(parseInt(durationHours, 10));
    }
    if (expiresAt !== undefined) {
        fields.push('expires_at = ?');
        params.push(expiresAt ? new Date(expiresAt).toISOString() : null);
    }
    if (activatedAt !== undefined) {
        fields.push('activated_at = ?');
        params.push(activatedAt ? new Date(activatedAt).toISOString() : null);
    }
    if (notes !== undefined) {
        fields.push('notes = ?');
        params.push(notes);
    }
    if (customerName !== undefined) {
        fields.push('customer_name = ?');
        params.push(customerName);
    }
    if (maxDevices !== undefined) {
        fields.push('max_devices = ?');
        params.push(parseInt(maxDevices, 10) || 1);
    }
    if (status !== undefined) {
        fields.push('status = ?');
        params.push(status.toUpperCase());
    }
    if (fields.length > 0) {
        params.push(id);
        await query(`UPDATE activation_keys SET ${fields.join(', ')} WHERE id = ?`, params);
    }
    if (status) {
        const s = status.toUpperCase();
        if (s === 'REVOKED' || s === 'SUSPENDED' || s === 'PAUSED') {
            await query('UPDATE activations SET status = ? WHERE key_id = ?', [s, id]);
        } else if (s === 'ACTIVE') {
            await query("UPDATE activations SET status = 'ACTIVE' WHERE key_id = ?", [id]);
        }
    }
    const updated = await getKeyById(id);
    await exportSeedKeys();
    return updated;
}

async function updateKeyStatus(id, newStatus) {
    const s = (newStatus || '').toUpperCase();
    await query('UPDATE activation_keys SET status = ? WHERE id = ?', [s, id]);
    if (s === 'REVOKED' || s === 'SUSPENDED' || s === 'PAUSED') {
        await query('UPDATE activations SET status = ? WHERE key_id = ?', [s, id]);
    } else if (s === 'ACTIVE') {
        await query("UPDATE activations SET status = 'ACTIVE' WHERE key_id = ?", [id]);
    }
    const updated = await getKeyById(id);
    await exportSeedKeys();
    return updated;
}

async function isKeyDeleted(keyHash) {
    if (!keyHash) return false;
    try {
        const res = await queryOne('SELECT id FROM deleted_keys WHERE key_hash = ?', [keyHash]);
        return !!res;
    } catch (e) {
        return false;
    }
}

async function deleteKey(idOrKey, deletedBy = 'admin', reason = 'Deleted by Administrator') {
    const key = await getKeyByIdOrString(idOrKey);
    if (!key) {
        return { success: true, count: 0, message: 'Key not found or already deleted' };
    }

    // 1. Blacklist key hash in deleted_keys so it can never be reused, reactivated, or restored
    try {
        if (isPostgres) {
            await query(
                'INSERT INTO deleted_keys (key_hash, key_display, deleted_by, reason) VALUES (?, ?, ?, ?) ON CONFLICT (key_hash) DO NOTHING',
                [key.key_hash, key.key_display, deletedBy, reason]
            );
        } else {
            await query(
                'INSERT OR IGNORE INTO deleted_keys (key_hash, key_display, deleted_by, reason) VALUES (?, ?, ?, ?)',
                [key.key_hash, key.key_display, deletedBy, reason]
            );
        }
    } catch (e) {
        console.error('[DB] Error recording deleted key hash:', e.message);
    }

    // 2. Immediately invalidate and remove all active sessions & device activations associated with this key
    await query('DELETE FROM activations WHERE key_id = ? OR license_id = ?', [key.id, key.id]);

    // 3. Delete from activation_keys table
    const res = await query('DELETE FROM activation_keys WHERE id = ?', [key.id]);

    // 4. Remove from legacy licenses table if exists
    try {
        await query('DELETE FROM licenses WHERE license_key = ? OR license_key = ?', [key.key_display, key.key_last4]);
    } catch (e) {}

    // 5. Update and persist seed-keys.json to guarantee permanence across restarts
    await exportSeedKeys();

    return {
        success: true,
        count: res.rowCount || 1,
        key: key
    };
}

async function clearExpiredKeys() {
    const allKeysRes = await query("SELECT id, status, expires_at, duration_hours FROM activation_keys");
    const now = Date.now();
    let count = 0;
    if (allKeysRes.rows && allKeysRes.rows.length > 0) {
        for (const k of allKeysRes.rows) {
            const isPerm = k.duration_hours === -1;
            const isExp = !isPerm && k.expires_at && (new Date(k.expires_at).getTime() <= now);
            if (k.status === 'EXPIRED' || isExp) {
                await query('DELETE FROM activations WHERE key_id = ?', [k.id]);
                await query('DELETE FROM activation_keys WHERE id = ?', [k.id]);
                count++;
            }
        }
        await exportSeedKeys();
    }
    return count;
}

async function clearAllKeys() {
    await query('DELETE FROM activations');
    await query('DELETE FROM devices');
    await query('DELETE FROM customers');
    const res = await query('DELETE FROM activation_keys');
    await exportSeedKeys(); // Will write [] to seed-keys.json
    return res.rowCount || 0;
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
            appIdentifier || 'com.example.zexora',
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
    const res = await query(`
        INSERT INTO activations (key_id, license_id, customer_id, device_id, expires_at, status, session_token)
        VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?)
    `, [keyId, keyId, customerId, deviceId, expiresStr, sessionToken]);
    await exportSeedKeys();
    return res;
}

async function updateActivationLastSeen(activationId, sessionToken = null) {
    let res;
    if (sessionToken) {
        res = await query(`
            UPDATE activations 
            SET last_verified_at = CURRENT_TIMESTAMP, last_seen_at = CURRENT_TIMESTAMP, session_token = ?
            WHERE id = ?
        `, [sessionToken, activationId]);
        await exportSeedKeys();
    } else {
        res = await query(`
            UPDATE activations 
            SET last_verified_at = CURRENT_TIMESTAMP, last_seen_at = CURRENT_TIMESTAMP 
            WHERE id = ?
        `, [activationId]);
    }
    return res;
}

async function deactivateDevice(keyId, deviceId) {
    const res = await query(`
        UPDATE activations 
        SET status = 'INACTIVE', is_active = 0 
        WHERE (key_id = ? OR license_id = ?) AND device_id = ?
    `, [keyId, keyId, deviceId]);
    await exportSeedKeys();
    return res;
}

// -------------------------------------------------------------
// Dashboard Statistics
// -------------------------------------------------------------
async function getDashboardStats() {
    // Auto-heal status for any activated keys
    try {
        await query(`
            UPDATE activation_keys 
            SET status = 'ACTIVE' 
            WHERE status = 'UNUSED' AND (
                activated_at IS NOT NULL 
                OR id IN (SELECT key_id FROM activations WHERE key_id IS NOT NULL AND (status = 'ACTIVE' OR is_active = 1))
            )
        `);
    } catch (e) {
        // Non-fatal
    }

    const totalKeysRes = await queryOne('SELECT COUNT(*) as count FROM activation_keys');
    const activeKeysRes = await queryOne("SELECT COUNT(DISTINCT id) as count FROM activation_keys WHERE status = 'ACTIVE' OR id IN (SELECT key_id FROM activations WHERE key_id IS NOT NULL AND (status = 'ACTIVE' OR is_active = 1))");
    const unusedKeysRes = await queryOne("SELECT COUNT(*) as count FROM activation_keys WHERE status = 'UNUSED' AND NOT EXISTS (SELECT 1 FROM activations WHERE activations.key_id = activation_keys.id AND (activations.status = 'ACTIVE' OR activations.is_active = 1))");
    const expiredKeysRes = await queryOne("SELECT COUNT(*) as count FROM activation_keys WHERE status = 'EXPIRED'");
    const revokedKeysRes = await queryOne("SELECT COUNT(*) as count FROM activation_keys WHERE status = 'REVOKED'");
    const suspendedKeysRes = await queryOne("SELECT COUNT(*) as count FROM activation_keys WHERE status = 'SUSPENDED'");
    const customersRes = await queryOne('SELECT COUNT(*) as count FROM customers');
    const devicesRes = await queryOne("SELECT COUNT(*) as count FROM activations WHERE status = 'ACTIVE' OR is_active = 1");

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

async function createLicense({
    licenseKey,
    durationDays = 30,
    maxActivations = 1,
    notes = '',
    status = 'ACTIVE'
}) {
    const product = await getOrCreateProduct('Zexora');
    const effectiveHours = durationDays === -1 ? -1 : (durationDays * 24);
    return await createActivationKey({
        keyString: licenseKey,
        productId: product.id,
        durationHours: effectiveHours,
        maxDevices: maxActivations,
        customerName: 'MADARA FF User',
        notes: notes
    });
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
    createLicense,
    getKeyByHash,
    getKeyById,
    getKeyByIdOrString,
    getAllKeys,
    updateKeyStatus,
    updateKeyDetails,
    deleteKey,
    isKeyDeleted,
    clearExpiredKeys,
    clearAllKeys,
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
    getRecentLogs,
    // Persistence
    exportSeedKeys,
    importSeedKeys
};
