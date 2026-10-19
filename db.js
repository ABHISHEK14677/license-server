const path = require('node:path');
const fs = require('node:fs');
const { hashPassword, hashKey, getKeyLast4 } = require('./auth');
const { config } = require('./config');

const DATABASE_URL = config.databaseUrl;
let isPostgres = false;
let pgPool = null;
let sqliteDb = null;

if (DATABASE_URL && DATABASE_URL.startsWith('postgres')) {
    isPostgres = true;
    const { Pool } = require('pg');
    pgPool = new Pool({
        connectionString: DATABASE_URL,
        ssl: config.isProduction ? { rejectUnauthorized: false } : false
    });
    console.log('[DB] Using PostgreSQL connection pool');
} else {
    if (config.isProduction) {
        console.warn('[DB WARNING] Running in production on local SQLite. Data will not persist across container redeployments without a persistent database. Configure DATABASE_URL.');
    }
    let DatabaseSync;
    try {
        DatabaseSync = require('node:sqlite').DatabaseSync;
    } catch (e) {
        console.error('[DB FATAL] Failed to load node:sqlite. Ensure Node.js is executed with --experimental-sqlite or connect a PostgreSQL instance via DATABASE_URL.');
        throw new Error(`node:sqlite unavailable: ${e.message}. Run with node --experimental-sqlite or provide DATABASE_URL.`);
    }
    const DB_PATH = path.join(__dirname, 'licenses.db');
    sqliteDb = new DatabaseSync(DB_PATH);
    try {
        sqliteDb.exec('PRAGMA journal_mode = WAL;');
        sqliteDb.exec('PRAGMA busy_timeout = 10000;');
    } catch {}
    console.log('[DB] Using local SQLite database:', DB_PATH);
}

const SEED_FILE_PATH = path.join(__dirname, 'seed-keys.json');

async function execSqliteWithRetry(fn, maxRetries = 30) {
    let retries = maxRetries;
    while (true) {
        try {
            return fn();
        } catch (err) {
            if ((err.errcode === 5 || (err.message && err.message.includes('locked'))) && retries > 0) {
                retries--;
                await new Promise(r => setTimeout(r, 20 + Math.floor(Math.random() * 30)));
                continue;
            }
            throw err;
        }
    }
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
        return await execSqliteWithRetry(() => {
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
        });
    }
}

async function queryOne(sql, params = []) {
    const res = await query(sql, params);
    return res.rows[0] || null;
}

// Migration helper for SQLite
async function ensureSqliteColumn(table, column, colType) {
    try {
        await execSqliteWithRetry(() => {
            const cols = sqliteDb.prepare(`PRAGMA table_info(${table})`).all();
            const exists = cols.some(c => c.name === column);
            if (!exists) {
                sqliteDb.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${colType};`);
                console.log(`[DB MIGRATION] Added column ${column} to table ${table}`);
            }
        });
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

                CREATE TABLE IF NOT EXISTS app_releases (
                    id SERIAL PRIMARY KEY,
                    latest_version VARCHAR(50) NOT NULL,
                    version_code INTEGER NOT NULL,
                    min_version VARCHAR(50) DEFAULT '1.0.0',
                    title VARCHAR(255) DEFAULT 'Z E X O Update Available',
                    release_notes TEXT,
                    apk_filename VARCHAR(255) DEFAULT 'RootOptimizer.apk',
                    download_url TEXT,
                    file_size_bytes BIGINT DEFAULT 0,
                    sha256 VARCHAR(64),
                    is_active INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE INDEX IF NOT EXISTS idx_keys_hash ON activation_keys(key_hash);
                CREATE INDEX IF NOT EXISTS idx_keys_status ON activation_keys(status);
                CREATE INDEX IF NOT EXISTS idx_keys_display ON activation_keys(key_display);
                CREATE INDEX IF NOT EXISTS idx_activations_key_id ON activations(key_id);
                CREATE INDEX IF NOT EXISTS idx_activations_device_id ON activations(device_id);
                CREATE INDEX IF NOT EXISTS idx_activations_status ON activations(status);
                CREATE INDEX IF NOT EXISTS idx_deleted_keys_hash ON deleted_keys(key_hash);
                CREATE INDEX IF NOT EXISTS idx_app_releases_code ON app_releases(version_code);
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
            await execSqliteWithRetry(() => sqliteDb.exec(`
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

                CREATE TABLE IF NOT EXISTS app_releases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    latest_version TEXT NOT NULL,
                    version_code INTEGER NOT NULL,
                    min_version TEXT DEFAULT '1.0.0',
                    title TEXT DEFAULT 'Z E X O Update Available',
                    release_notes TEXT,
                    apk_filename TEXT DEFAULT 'RootOptimizer.apk',
                    download_url TEXT,
                    file_size_bytes INTEGER DEFAULT 0,
                    sha256 TEXT,
                    is_active INTEGER DEFAULT 1,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );

                CREATE INDEX IF NOT EXISTS idx_keys_hash ON activation_keys(key_hash);
                CREATE INDEX IF NOT EXISTS idx_keys_status ON activation_keys(status);
                CREATE INDEX IF NOT EXISTS idx_keys_display ON activation_keys(key_display);
                CREATE INDEX IF NOT EXISTS idx_activations_key_id ON activations(key_id);
                CREATE INDEX IF NOT EXISTS idx_activations_device_id ON activations(device_id);
                CREATE INDEX IF NOT EXISTS idx_activations_status ON activations(status);
                CREATE INDEX IF NOT EXISTS idx_deleted_keys_hash ON deleted_keys(key_hash);
                CREATE INDEX IF NOT EXISTS idx_app_releases_code ON app_releases(version_code);
            `));

            // Apply migrations to existing tables
            await ensureSqliteColumn('admins', 'email', 'TEXT');
            await ensureSqliteColumn('admins', 'role', "TEXT DEFAULT 'admin'");
            await ensureSqliteColumn('admins', 'updated_at', 'DATETIME');

            await ensureSqliteColumn('activations', 'key_id', 'INTEGER');
            await ensureSqliteColumn('activations', 'license_id', 'INTEGER');
            await ensureSqliteColumn('activations', 'customer_id', 'INTEGER');
            await ensureSqliteColumn('activations', 'expires_at', 'DATETIME');
            await ensureSqliteColumn('activations', 'status', "TEXT DEFAULT 'ACTIVE'");
            await ensureSqliteColumn('activations', 'last_verified_at', 'DATETIME');
            await ensureSqliteColumn('activations', 'last_seen_at', 'DATETIME');
            await ensureSqliteColumn('activations', 'session_token', 'TEXT');
            await ensureSqliteColumn('activations', 'is_active', "INTEGER DEFAULT 1");

            await ensureSqliteColumn('audit_logs', 'action', 'TEXT');
            await ensureSqliteColumn('audit_logs', 'event_type', 'TEXT');
            await ensureSqliteColumn('audit_logs', 'timestamp', 'DATETIME');

            // Clean up legacy activations with null key_id
            try {
                await query('UPDATE activations SET key_id = license_id WHERE key_id IS NULL AND license_id IS NOT NULL');
                await query('DELETE FROM activations WHERE key_id IS NULL');
            } catch (e) {}
        }

        // Seed default product: Z E X O
        let defaultProduct = await queryOne('SELECT * FROM products WHERE name = ?', ['Z E X O']);
        if (!defaultProduct) {
            defaultProduct = await queryOne('SELECT * FROM products WHERE name = ? OR name = ? OR name = ?', ['Zexora', 'Optimizer', 'ADB Optimizer']);
            if (defaultProduct) {
                await query('UPDATE products SET name = ?, description = ? WHERE id = ?', [
                    'Z E X O',
                    'Z E X O - Developed by MADARA FF',
                    defaultProduct.id
                ]);
            } else {
                await query('INSERT INTO products (name, description, status) VALUES (?, ?, ?)', [
                    'Z E X O',
                    'Z E X O - Developed by MADARA FF',
                    'ACTIVE'
                ]);
            }
            console.log('[INIT] Default product set to: Z E X O');
        }

        // Ensure default admin exists with configured credentials without overwriting on deployment
        const adminUser = config.adminUsername;
        const adminPass = config.adminPassword;
        const adminEmail = config.adminEmail;
        const existingAdmin = await queryOne('SELECT id, salt, password_hash FROM admins WHERE username = ?', [adminUser]);

        if (!existingAdmin) {
            const { salt, hash } = hashPassword(adminPass);
            await query(
                'INSERT INTO admins (email, username, password_hash, salt, role) VALUES (?, ?, ?, ?, ?)',
                [adminEmail, adminUser, hash, salt, 'superadmin']
            );
            console.log(`[INIT] Created secure initial admin account: "${adminUser}"`);
        } else if (config.forceAdminPasswordReset) {
            const { salt, hash } = hashPassword(adminPass);
            await query(
                'UPDATE admins SET password_hash = ?, salt = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
                [hash, salt, existingAdmin.id]
            );
            console.log(`[INIT] Force-reset admin credentials for "${adminUser}" per configuration flag.`);
        } else {
            console.log(`[INIT] Verified existing admin account credentials for: "${adminUser}" (preserved)`);
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
        if (dbRows.length === 0) {
            try {
                fs.writeFileSync(SEED_FILE_PATH, JSON.stringify([], null, 2), 'utf8');
            } catch (e) {}
            return [];
        }

        for (const k of dbRows) {
            const kUpper = (k.key_display || '').trim().toUpperCase();
            const kHash = k.key_hash || hashKey(kUpper);
            if (await isKeyDeleted(kHash)) {
                if (kUpper) existingSeedMap.delete(kUpper);
                continue;
            }

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
                product: k.product_name || 'Z E X O',
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

            if (kUpper) {
                existingSeedMap.set(kUpper, item);
            }
        }

        const finalOutput = Array.from(existingSeedMap.values());
        try {
            fs.writeFileSync(SEED_FILE_PATH, JSON.stringify(finalOutput, null, 2), 'utf8');
        } catch (e) {}
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

        let defaultProduct = await queryOne('SELECT * FROM products WHERE name = ?', ['Z E X O']) ||
                             await queryOne('SELECT * FROM products WHERE name = ?', ['Zexora']) ||
                             await queryOne('SELECT * FROM products WHERE name = ?', ['Optimizer']);
        const prodId = defaultProduct ? defaultProduct.id : 1;
        let count = 0;

        for (const item of seedList) {
            const keyString = (item.key || item.key_display || item.license_key || '').trim().toUpperCase();
            if (!keyString) continue;

            const khash = hashKey(keyString);
            const last4 = getKeyLast4(keyString);

            // Skip keys that have been explicitly deleted by administrator
            if (await isKeyDeleted(khash)) {
                console.log(`[SEED] Ignoring deleted key: ${keyString}`);
                // Ensure it is purged from activation_keys if previously existed
                await query('DELETE FROM activation_keys WHERE key_hash = ?', [khash]);
                continue;
            }

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
                // Preserve ACTIVE status so an active key is never downgraded to UNUSED
                const targetStatus = (existing.status === 'ACTIVE' && item.status === 'UNUSED') 
                    ? 'ACTIVE' 
                    : (item.status || existing.status);
                const targetActivatedAt = existing.activated_at || item.activated_at || null;
                const targetExpiresAt = existing.expires_at || item.expires_at || null;

                if (targetStatus !== existing.status || targetActivatedAt !== existing.activated_at || targetExpiresAt !== existing.expires_at || (item.duration_hours !== undefined && item.duration_hours !== existing.duration_hours)) {
                    await query(`
                        UPDATE activation_keys 
                        SET status = ?, 
                            duration_hours = COALESCE(?, duration_hours),
                            activated_at = COALESCE(?, activated_at), 
                            expires_at = COALESCE(?, expires_at),
                            customer_name = COALESCE(customer_name, ?),
                            notes = COALESCE(notes, ?)
                        WHERE id = ?
                    `, [targetStatus, item.duration_hours !== undefined ? parseInt(item.duration_hours, 10) : existing.duration_hours, targetActivatedAt, targetExpiresAt, item.customer_name || null, item.notes || null, keyId]);
                    count++;
                }
            }

            // Restore activations if present in seed file
            if (item.activations && Array.isArray(item.activations) && keyId) {
                for (const act of item.activations) {
                    if (!act.device_identifier) continue;
                    const custName = item.customer_name || `user_${act.device_identifier.slice(0, 8)}`;
                    const customer = await getOrCreateCustomer(custName, item.customer_name);
                    const device = await getOrCreateDevice(customer.id, act.device_identifier, act.device_model || 'Android Device', 'com.example.rootoptimizer', act.platform || 'Android');

                    const existingAct = await findActivation(keyId, device.id);
                    if (!existingAct) {
                        await query(`
                            INSERT INTO activations (
                                key_id, license_id, customer_id, device_id, activated_at, expires_at, status, session_token, last_seen_at, is_active
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                        `, [
                            keyId, keyId, customer.id, device.id,
                            act.activated_at || new Date().toISOString(),
                            act.expires_at || null,
                            act.status || 'ACTIVE',
                            act.session_token || null,
                            act.last_seen_at || act.activated_at || new Date().toISOString()
                        ]);
                        console.log(`[SEED] Restored device activation for key ${keyString} on ${act.device_identifier}`);
                    } else {
                        await query(`
                            UPDATE activations 
                            SET session_token = COALESCE(?, session_token),
                                status = 'ACTIVE',
                                is_active = 1,
                                last_seen_at = COALESCE(?, last_seen_at)
                            WHERE id = ?
                        `, [act.session_token || null, act.last_seen_at || null, existingAct.id]);
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
            sql += ` AND (k.status = 'ACTIVE' OR (SELECT COUNT(*) FROM activations a WHERE a.key_id = k.id AND (a.status = 'ACTIVE' OR a.is_active = 1)) > 0) AND k.status NOT IN ('REVOKED', 'SUSPENDED', 'PAUSED', 'EXPIRED')`;
        } else if (s === 'UNUSED' || s === 'INACTIVE' || s === 'NON-ACTIVE' || s === 'NON_ACTIVE') {
            sql += ` AND (k.status IN ('UNUSED', 'INACTIVE', 'NON-ACTIVE', 'NON_ACTIVE') AND (SELECT COUNT(*) FROM activations a WHERE a.key_id = k.id AND (a.status = 'ACTIVE' OR a.is_active = 1)) = 0)`;
        } else if (s === 'PAUSED' || s === 'SUSPENDED') {
            sql += ` AND k.status IN ('PAUSED', 'SUSPENDED')`;
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

    // Efficient atomic batch update for any expired active keys
    const nowIso = new Date().toISOString();
    try {
        await query("UPDATE activation_keys SET status = 'EXPIRED' WHERE status = 'ACTIVE' AND duration_hours != -1 AND expires_at IS NOT NULL AND expires_at <= ?", [nowIso]);
    } catch (e) {
        // Non-fatal
    }

    // Reflect status in-memory for returned rows
    const now = Date.now();
    for (const key of res.rows) {
        if (key.status === 'ACTIVE' && key.duration_hours !== -1 && key.expires_at) {
            const expTime = new Date(key.expires_at).getTime();
            if (now >= expTime) {
                key.status = 'EXPIRED';
            }
        } else if ((key.status === 'UNUSED' || key.status === 'INACTIVE' || key.status === 'NON-ACTIVE') && (key.activated_at || key.active_devices_count > 0)) {
            key.status = 'ACTIVE';
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

async function getKeyByDeviceOrSession(deviceId, sessionToken = null) {
    if (!deviceId && !sessionToken) return null;
    let sql = `
        SELECT k.*, p.name as product_name
        FROM activations a
        JOIN activation_keys k ON (a.key_id = k.id OR a.license_id = k.id)
        LEFT JOIN products p ON k.product_id = p.id
        LEFT JOIN devices d ON a.device_id = d.id
        WHERE 1=1
    `;
    const params = [];
    if (sessionToken && deviceId) {
        sql += ` AND a.session_token = ? AND d.device_identifier = ?`;
        params.push(sessionToken, deviceId);
    } else if (sessionToken) {
        sql += ` AND a.session_token = ?`;
        params.push(sessionToken);
    } else if (deviceId) {
        sql += ` AND d.device_identifier = ? AND (a.status = 'ACTIVE' OR a.is_active = 1)`;
        params.push(deviceId);
    }
    sql += ` ORDER BY a.last_seen_at DESC LIMIT 1`;
    return await queryOne(sql, params);
}

async function updateKeyDetails(id, { notes, customerName, maxDevices, status, keyDisplay, durationHours, expiresAt, activatedAt }) {
    const currentKey = await getKeyById(id);
    if (!currentKey) return null;

    // Prevent changing a revoked key back to active or any other status
    const normStatus = (status !== undefined && status !== null) ? status.toUpperCase() : undefined;
    if (currentKey.status === 'REVOKED' && normStatus && normStatus !== 'REVOKED') {
        throw new Error('A revoked key cannot be reactivated through ordinary editing. Reissuing access must follow the authorized workflow or generate a new key.');
    }

    const fields = [];
    const params = [];

    // Note: Secret key value (key_display, key_hash, key_last4) is strictly immutable per security policy

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

    let targetStatus = normStatus || currentKey.status;
    if (targetStatus === 'INACTIVE' || targetStatus === 'NON-ACTIVE' || targetStatus === 'NON_ACTIVE') {
        targetStatus = 'UNUSED';
    }

    if (durationHours !== undefined && durationHours !== null) {
        const d = parseInt(durationHours, 10);
        if (d === -1 && currentKey.duration_hours !== -1) {
            throw new Error('Permanent time-changing or lifetime extension is not permitted in key editing.');
        }
    }

    let targetDuration = (durationHours !== undefined && durationHours !== null)
        ? parseInt(durationHours, 10)
        : currentKey.duration_hours;

    if (durationHours !== undefined) {
        fields.push('duration_hours = ?');
        params.push(targetDuration);
    }

    // Determine target activated_at
    let targetActivatedAt = (activatedAt !== undefined)
        ? (activatedAt ? new Date(activatedAt).toISOString() : null)
        : currentKey.activated_at;

    if (activatedAt !== undefined) {
        fields.push('activated_at = ?');
        params.push(targetActivatedAt);
    }

    // Determine target expires_at: PRESERVE existing expiration time unless explicitly modified
    let targetExpiresAt = undefined;
    let shouldUpdateExpiryField = false;

    if (expiresAt !== undefined) {
        shouldUpdateExpiryField = true;
        targetExpiresAt = expiresAt ? new Date(expiresAt).toISOString() : null;
    } else if (normStatus === 'EXPIRED') {
        shouldUpdateExpiryField = true;
        targetExpiresAt = new Date(Date.now() - 1000).toISOString();
    } else if (normStatus === 'UNUSED' || normStatus === 'NON-ACTIVE' || normStatus === 'INACTIVE') {
        shouldUpdateExpiryField = true;
        targetActivatedAt = null;
        targetExpiresAt = null;
        fields.push('activated_at = NULL');
    } else if (durationHours !== undefined && durationHours !== currentKey.duration_hours && !currentKey.expires_at) {
        // Only calculate expires_at from duration if key does not already have an active expiration timestamp
        shouldUpdateExpiryField = true;
        if (targetDuration === -1) {
            targetExpiresAt = null;
        } else if (targetDuration > 0 && targetActivatedAt) {
            const baseActTime = new Date(targetActivatedAt).getTime();
            let calcExpiry = baseActTime + targetDuration * 3600 * 1000;
            targetExpiresAt = new Date(calcExpiry).toISOString();
            if (calcExpiry <= Date.now() && !normStatus) {
                targetStatus = 'EXPIRED';
            }
        }
    } else {
        // Retain original expiration timestamp unchanged
        targetExpiresAt = currentKey.expires_at;
    }

    if (shouldUpdateExpiryField) {
        fields.push('expires_at = ?');
        params.push(targetExpiresAt);
    }

    if (targetStatus !== undefined) {
        fields.push('status = ?');
        params.push(targetStatus);
    }

    if (fields.length > 0) {
        params.push(id);
        await query(`UPDATE activation_keys SET ${fields.join(', ')} WHERE id = ?`, params);
    }

    // Synchronize activations table
    if (targetStatus === 'REVOKED') {
        await query("UPDATE activations SET status = 'REVOKED', is_active = 0 WHERE key_id = ?", [id]);
    } else if (targetStatus === 'SUSPENDED' || targetStatus === 'PAUSED') {
        await query("UPDATE activations SET status = 'SUSPENDED' WHERE key_id = ?", [id]);
    } else if (targetStatus === 'EXPIRED') {
        const exp = targetExpiresAt || new Date(Date.now() - 1000).toISOString();
        await query("UPDATE activations SET status = 'EXPIRED', expires_at = ?, is_active = 0 WHERE key_id = ?", [exp, id]);
    } else if (targetStatus === 'UNUSED') {
        await query("UPDATE activations SET status = 'INACTIVE', is_active = 0, expires_at = NULL WHERE key_id = ?", [id]);
    } else if (targetStatus === 'ACTIVE') {
        await query("UPDATE activations SET status = 'ACTIVE', is_active = 1, expires_at = ? WHERE key_id = ?", [targetExpiresAt, id]);
    } else if (shouldUpdateExpiryField && targetExpiresAt !== undefined) {
        await query("UPDATE activations SET expires_at = ? WHERE key_id = ?", [targetExpiresAt, id]);
    }

    const updated = await getKeyById(id);
    // Export seed keys asynchronously to eliminate latency
    exportSeedKeys().catch(e => console.warn('[SEED] Async export warning:', e.message));
    return updated;
}

async function updateKeyStatus(id, newStatus) {
    const current = await getKeyById(id);
    if (!current) return null;
    let s = (newStatus || '').toUpperCase();
    if (s === 'INACTIVE' || s === 'NON-ACTIVE' || s === 'NON_ACTIVE') s = 'UNUSED';
    if (current.status === 'REVOKED' && s !== 'REVOKED') {
        throw new Error('A revoked key must never be reactivated; generate a new key if access is needed again.');
    }
    await query('UPDATE activation_keys SET status = ? WHERE id = ?', [s, id]);
    if (s === 'REVOKED') {
        await query("UPDATE activations SET status = 'REVOKED', is_active = 0 WHERE key_id = ?", [id]);
    } else if (s === 'SUSPENDED' || s === 'PAUSED') {
        await query("UPDATE activations SET status = 'SUSPENDED', is_active = 0 WHERE key_id = ?", [id]);
    } else if (s === 'EXPIRED') {
        const exp = new Date(Date.now() - 1000).toISOString();
        await query("UPDATE activations SET status = 'EXPIRED', expires_at = ?, is_active = 0 WHERE key_id = ?", [exp, id]);
        await query("UPDATE activation_keys SET expires_at = ? WHERE id = ?", [exp, id]);
    } else if (s === 'ACTIVE') {
        await query("UPDATE activations SET status = 'ACTIVE', is_active = 1 WHERE key_id = ?", [id]);
    } else if (s === 'UNUSED') {
        await query("UPDATE activations SET status = 'INACTIVE', is_active = 0, expires_at = NULL WHERE key_id = ?", [id]);
        await query("UPDATE activation_keys SET activated_at = NULL, expires_at = NULL WHERE id = ?", [id]);
    }
    const updated = await getKeyById(id);
    exportSeedKeys().catch(e => console.warn('[SEED] Async export warning:', e.message));
    return updated;
}

async function extendKeyExpiry(id, hours) {
    const key = await getKeyById(id);
    if (!key) return null;
    if (key.status === 'REVOKED') {
        throw new Error('Revoked keys cannot be extended. Generate a new key if access is needed.');
    }
    const extHours = parseInt(hours, 10);
    if (isNaN(extHours) || extHours <= 0) {
        throw new Error('Invalid extension hours.');
    }

    if (key.duration_hours === -1) {
        return key;
    }

    const now = Date.now();
    let newExpiresAtIso = null;

    if (key.expires_at) {
        const curExp = new Date(key.expires_at).getTime();
        const base = Math.max(curExp, now);
        newExpiresAtIso = new Date(base + extHours * 3600 * 1000).toISOString();
    } else if (key.activated_at) {
        const base = Math.max(new Date(key.activated_at).getTime(), now);
        newExpiresAtIso = new Date(base + extHours * 3600 * 1000).toISOString();
    } else {
        const newDur = (key.duration_hours || 0) + extHours;
        await query('UPDATE activation_keys SET duration_hours = ? WHERE id = ?', [newDur, id]);
        exportSeedKeys().catch(e => console.warn('[SEED] Async export warning:', e.message));
        return await getKeyById(id);
    }

    const newDurationHours = (key.duration_hours || 0) + extHours;
    const newStatus = (key.status === 'PAUSED' || key.status === 'SUSPENDED') ? 'PAUSED' : 'ACTIVE';

    await query(`
        UPDATE activation_keys 
        SET expires_at = ?, duration_hours = ?, status = ?
        WHERE id = ?
    `, [newExpiresAtIso, newDurationHours, newStatus, id]);

    await query(`
        UPDATE activations 
        SET expires_at = ?, status = 'ACTIVE', is_active = 1 
        WHERE key_id = ? AND status != 'REVOKED'
    `, [newExpiresAtIso, id]);

    exportSeedKeys().catch(e => console.warn('[SEED] Async export warning:', e.message));
    return await getKeyById(id);
}

/**
 * Reduce a key's remaining validity duration atomically on the server.
 * Shortens remaining validity; never increases it.
 */
async function reduceKeyTime(id, reductionHours, adminUsername = 'admin') {
    const key = await getKeyById(id);
    if (!key) return null;

    if (key.status === 'REVOKED') {
        throw new Error('Revoked keys cannot have time reduced or modified. Generate a new key if access is needed.');
    }

    if (key.duration_hours === -1) {
        throw new Error('Permanent (lifetime) keys do not have a finite validity period to reduce.');
    }

    const numHours = Number(reductionHours);
    if (isNaN(numHours) || !isFinite(numHours) || numHours <= 0) {
        throw new Error('Reduction hours must be a positive number greater than zero.');
    }

    if (numHours > 876000) {
        throw new Error('Reduction amount is too large.');
    }

    const previousExpiresAt = key.expires_at;
    const previousDurationHours = key.duration_hours;
    const now = Date.now();
    let newExpiresAtIso = null;
    let newDurationHours = key.duration_hours;
    let targetStatus = key.status;

    if (key.expires_at) {
        const curExp = new Date(key.expires_at).getTime();
        const reductionMs = Math.round(numHours * 3600 * 1000);
        const newExpMs = curExp - reductionMs;
        newExpiresAtIso = new Date(newExpMs).toISOString();

        if (newDurationHours > 0) {
            newDurationHours = Math.max(0, Math.round(newDurationHours - numHours));
        }

        if (newExpMs <= now) {
            // Resulting expiration is in the past or now: mark as EXPIRED
            targetStatus = 'EXPIRED';
            await query(`
                UPDATE activation_keys 
                SET expires_at = ?, duration_hours = ?, status = 'EXPIRED'
                WHERE id = ?
            `, [newExpiresAtIso, newDurationHours, id]);

            await query(`
                UPDATE activations 
                SET expires_at = ?, status = 'EXPIRED', is_active = 0 
                WHERE key_id = ?
            `, [newExpiresAtIso, id]);
        } else {
            await query(`
                UPDATE activation_keys 
                SET expires_at = ?, duration_hours = ?
                WHERE id = ?
            `, [newExpiresAtIso, newDurationHours, id]);

            await query(`
                UPDATE activations 
                SET expires_at = ?
                WHERE key_id = ?
            `, [newExpiresAtIso, id]);
        }
    } else {
        // Key has not yet been activated (timer starts on first device activation)
        const curDur = key.duration_hours || 0;
        const newDur = Math.round(curDur - numHours);

        if (newDur <= 0) {
            newDurationHours = 0;
            targetStatus = 'EXPIRED';
            const nowIso = new Date(now).toISOString();
            newExpiresAtIso = nowIso;
            await query(`
                UPDATE activation_keys 
                SET duration_hours = 0, expires_at = ?, status = 'EXPIRED'
                WHERE id = ?
            `, [nowIso, id]);

            await query(`
                UPDATE activations 
                SET expires_at = ?, status = 'EXPIRED', is_active = 0 
                WHERE key_id = ?
            `, [nowIso, id]);
        } else {
            newDurationHours = newDur;
            await query(`
                UPDATE activation_keys 
                SET duration_hours = ?
                WHERE id = ?
            `, [newDur, id]);
        }
    }

    exportSeedKeys().catch(e => console.warn('[SEED] Async export warning:', e.message));
    const updated = await getKeyById(id);
    return {
        updated,
        previousExpiresAt,
        newExpiresAt: updated.expires_at,
        previousDurationHours,
        newDurationHours: updated.duration_hours,
        status: updated.status
    };
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

async function getAllDeletedKeys() {
    try {
        const res = await query('SELECT * FROM deleted_keys ORDER BY id DESC');
        return res ? (res.rows || []) : [];
    } catch (e) {
        return [];
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

async function deleteActiveKeys(deletedBy = 'admin', reason = 'Active key revoked and deleted by Administrator') {
    // 1. Find all keys that are active or have active activations
    const activeKeysRes = await query(`
        SELECT DISTINCT k.id, k.key_hash, k.key_display 
        FROM activation_keys k
        LEFT JOIN activations a ON a.key_id = k.id
        WHERE k.status = 'ACTIVE' OR a.status = 'ACTIVE' OR a.is_active = 1 OR k.activated_at IS NOT NULL
    `);

    let count = 0;
    if (activeKeysRes.rows && activeKeysRes.rows.length > 0) {
        for (const k of activeKeysRes.rows) {
            try {
                if (isPostgres) {
                    await query(
                        'INSERT INTO deleted_keys (key_hash, key_display, deleted_by, reason) VALUES (?, ?, ?, ?) ON CONFLICT (key_hash) DO NOTHING',
                        [k.key_hash, k.key_display, deletedBy, reason]
                    );
                } else {
                    await query(
                        'INSERT OR IGNORE INTO deleted_keys (key_hash, key_display, deleted_by, reason) VALUES (?, ?, ?, ?)',
                        [k.key_hash, k.key_display, deletedBy, reason]
                    );
                }
            } catch (e) {}

            await query('DELETE FROM activations WHERE key_id = ?', [k.id]);
            await query('DELETE FROM activation_keys WHERE id = ?', [k.id]);
            count++;
        }
    }

    // Clean up any remaining active activations or devices
    await query("UPDATE activations SET status = 'REVOKED', is_active = 0 WHERE status = 'ACTIVE' OR is_active = 1");
    await query("DELETE FROM activations WHERE status = 'REVOKED'");
    await exportSeedKeys();
    return count;
}

async function clearAllKeys(deletedBy = 'admin', reason = 'All keys purged by Administrator') {
    // Record all existing keys into deleted_keys so any active client apps receive KEY_DELETED and get revoked
    try {
        const allKeysRes = await query('SELECT key_hash, key_display FROM activation_keys');
        if (allKeysRes.rows && allKeysRes.rows.length > 0) {
            for (const k of allKeysRes.rows) {
                if (isPostgres) {
                    await query(
                        'INSERT INTO deleted_keys (key_hash, key_display, deleted_by, reason) VALUES (?, ?, ?, ?) ON CONFLICT (key_hash) DO NOTHING',
                        [k.key_hash, k.key_display, deletedBy, reason]
                    );
                } else {
                    await query(
                        'INSERT OR IGNORE INTO deleted_keys (key_hash, key_display, deleted_by, reason) VALUES (?, ?, ?, ?)',
                        [k.key_hash, k.key_display, deletedBy, reason]
                    );
                }
            }
        }
    } catch (e) {}

    await query('DELETE FROM activations');
    await query('DELETE FROM devices');
    await query('DELETE FROM customers');
    // Note: Do NOT delete from deleted_keys, so that active client apps receive KEY_DELETED upon check-in
    try {
        await query('DROP TABLE IF EXISTS licenses');
    } catch (e) {}
    const res = await query('DELETE FROM activation_keys');
    try {
        fs.writeFileSync(SEED_FILE_PATH, JSON.stringify([], null, 2), 'utf8');
    } catch (e) {}
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
    exportSeedKeys().catch(e => console.warn('[SEED] Async export warning:', e.message));
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
        exportSeedKeys().catch(e => console.warn('[SEED] Async export warning:', e.message));
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
    exportSeedKeys().catch(e => console.warn('[SEED] Async export warning:', e.message));
    return res;
}

// -------------------------------------------------------------
// Dashboard Statistics
// -------------------------------------------------------------
async function getDashboardStats() {
    // Auto-heal status for any activated keys that are currently UNUSED
    try {
        await query(`
            UPDATE activation_keys 
            SET status = 'ACTIVE' 
            WHERE status IN ('UNUSED', 'INACTIVE', 'NON-ACTIVE', 'NON_ACTIVE') AND (
                activated_at IS NOT NULL 
                OR id IN (SELECT key_id FROM activations WHERE key_id IS NOT NULL AND (status = 'ACTIVE' OR is_active = 1))
            )
        `);
    } catch (e) {
        // Non-fatal
    }

    const totalKeysRes = await queryOne('SELECT COUNT(*) as count FROM activation_keys');
    const activeKeysRes = await queryOne("SELECT COUNT(DISTINCT id) as count FROM activation_keys WHERE (status = 'ACTIVE' OR (status IN ('UNUSED', 'INACTIVE', 'NON-ACTIVE', 'NON_ACTIVE') AND id IN (SELECT key_id FROM activations WHERE key_id IS NOT NULL AND (status = 'ACTIVE' OR is_active = 1)))) AND status NOT IN ('REVOKED', 'SUSPENDED', 'PAUSED', 'EXPIRED')");
    const unusedKeysRes = await queryOne("SELECT COUNT(*) as count FROM activation_keys WHERE status IN ('UNUSED', 'INACTIVE', 'NON-ACTIVE', 'NON_ACTIVE') AND NOT EXISTS (SELECT 1 FROM activations WHERE activations.key_id = activation_keys.id AND (activations.status = 'ACTIVE' OR activations.is_active = 1))");
    const expiredKeysRes = await queryOne("SELECT COUNT(*) as count FROM activation_keys WHERE status = 'EXPIRED'");
    const revokedKeysRes = await queryOne("SELECT COUNT(*) as count FROM activation_keys WHERE status = 'REVOKED'");
    const suspendedKeysRes = await queryOne("SELECT COUNT(*) as count FROM activation_keys WHERE status IN ('SUSPENDED', 'PAUSED')");
    const customersRes = await queryOne('SELECT COUNT(*) as count FROM customers');
    const devicesRes = await queryOne("SELECT COUNT(*) as count FROM activations WHERE status = 'ACTIVE' OR is_active = 1");

    const nonActiveCount = Number(unusedKeysRes?.count || 0);
    const pausedCount = Number(suspendedKeysRes?.count || 0);

    return {
        total_keys: Number(totalKeysRes?.count || 0),
        active_keys: Number(activeKeysRes?.count || 0),
        unused_keys: nonActiveCount,
        non_active_keys: nonActiveCount,
        expired_keys: Number(expiredKeysRes?.count || 0),
        revoked_keys: Number(revokedKeysRes?.count || 0),
        suspended_keys: pausedCount,
        paused_keys: pausedCount,
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
        if (isPostgres) {
            await query('INSERT INTO audit_logs (event_type, details, ip_address) VALUES (?, ?, ?)', [
                eventType,
                detailsStr,
                ip
            ]);
        } else {
            await query('INSERT INTO audit_logs (action, event_type, details, ip_address) VALUES (?, ?, ?, ?)', [
                eventType,
                eventType,
                detailsStr,
                ip
            ]);
        }
    } catch (e) {
        console.error('[AUDIT] Failed to write log:', e.message);
    }
}

async function getRecentLogs(limit = 50) {
    try {
        const res = await query('SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?', [limit]);
        return res.rows.map(r => ({
            ...r,
            action: r.action || r.event_type,
            event_type: r.event_type || r.action,
            details: typeof r.details === 'string' ? (() => { try { return JSON.parse(r.details); } catch { return r.details; } })() : r.details
        }));
    } catch {
        return [];
    }
}

async function createLicense({
    licenseKey,
    durationDays = 30,
    durationHours = null,
    maxActivations = 1,
    notes = '',
    status = 'ACTIVE'
}) {
    const product = await getOrCreateProduct('Zexora');
    let effectiveHours = 720;
    if (durationHours !== null && durationHours !== undefined) {
        effectiveHours = parseInt(durationHours, 10);
    } else if (durationDays !== null && durationDays !== undefined) {
        const d = parseInt(durationDays, 10);
        effectiveHours = d === 1 ? 24 : d === 7 ? 168 : d === 30 ? 720 : d * 24;
    }
    const ALLOWED_DURATIONS = [1, 24, 168, 720];
    if (!ALLOWED_DURATIONS.includes(effectiveHours)) {
        effectiveHours = 720;
    }
    return await createActivationKey({
        keyString: licenseKey,
        productId: product.id,
        durationHours: effectiveHours,
        maxDevices: maxActivations,
        customerName: 'MADARA FF User',
        notes: notes
    });
}

// App Releases & Versioning
async function saveAppRelease(data) {
    const {
        latest_version,
        version_code,
        min_version = '1.0.0',
        title = 'Z E X O Update Available',
        release_notes = '',
        apk_filename = 'RootOptimizer.apk',
        download_url = '/api/app/download',
        file_size_bytes = 0,
        sha256 = ''
    } = data;

    const sql = isPostgres
        ? `INSERT INTO app_releases (latest_version, version_code, min_version, title, release_notes, apk_filename, download_url, file_size_bytes, sha256)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING *`
        : `INSERT INTO app_releases (latest_version, version_code, min_version, title, release_notes, apk_filename, download_url, file_size_bytes, sha256)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`;

    const res = await query(sql, [
        latest_version,
        parseInt(version_code, 10),
        min_version,
        title,
        release_notes,
        apk_filename,
        download_url,
        file_size_bytes,
        sha256
    ]);

    if (isPostgres && res.rows[0]) {
        return res.rows[0];
    }
    return queryOne('SELECT * FROM app_releases WHERE id = ?', [res.lastID]);
}

async function getLatestAppRelease() {
    return queryOne('SELECT * FROM app_releases WHERE is_active = 1 ORDER BY version_code DESC, id DESC LIMIT 1');
}

async function getAllAppReleases(limit = 10) {
    const res = await query('SELECT * FROM app_releases ORDER BY version_code DESC, id DESC LIMIT ?', [limit]);
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
    createLicense,
    getKeyByHash,
    getKeyById,
    getKeyByIdOrString,
    getKeyByDeviceOrSession,
    getAllKeys,
    updateKeyStatus,
    updateKeyDetails,
    extendKeyExpiry,
    reduceKeyTime,
    deleteKey,
    isKeyDeleted,
    getAllDeletedKeys,
    clearExpiredKeys,
    deleteActiveKeys,
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
    // App Releases
    saveAppRelease,
    getLatestAppRelease,
    getAllAppReleases,
    // Stats & Logs
    getDashboardStats,
    logAuditEvent,
    getRecentLogs,
    getAuditLogs: getRecentLogs,
    // Persistence
    exportSeedKeys,
    importSeedKeys
};
