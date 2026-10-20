const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const fs = require('node:fs');
const http = require('node:http');

// Isolate test database and seed file
const testDbPath = path.join(__dirname, 'test-release-hardening.db');
const testSeedPath = path.join(__dirname, 'test-release-hardening-seed.json');
process.env.SQLITE_DB_PATH = testDbPath;
process.env.SEED_FILE_PATH = testSeedPath;
process.env.NODE_ENV = 'test';

const { app } = require('../server');
const db = require('../db');
const { config } = require('../config');

function makeRequest(server, options = {}) {
    return new Promise((resolve, reject) => {
        const addr = server.address();
        const req = http.request({
            host: '127.0.0.1',
            port: addr.port,
            path: options.path || '/',
            method: options.method || 'GET',
            headers: options.headers || {}
        }, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                let parsed = data;
                try { parsed = JSON.parse(data); } catch {}
                resolve({ status: res.statusCode, headers: res.headers, body: parsed });
            });
        });
        req.on('error', reject);
        if (options.body) {
            req.write(typeof options.body === 'string' ? options.body : JSON.stringify(options.body));
        }
        req.end();
    });
}

test('Release & Update Reliability Test Suite (PHASE 11 Verification)', async (t) => {
    let server;
    const testPort = 0;
    const versionFile = path.join(__dirname, '..', 'public', 'downloads', 'version.json');
    let versionBackup = null;
    if (fs.existsSync(versionFile)) {
        versionBackup = fs.readFileSync(versionFile, 'utf8');
    }

    await db.initDatabase();

    await new Promise((resolve) => {
        server = app.listen(testPort, '127.0.0.1', () => resolve());
    });

    const adminSecret = config.adminSecret;
    const authHeaders = {
        'Content-Type': 'application/json',
        'x-admin-key': adminSecret
    };

    t.after(async () => {
        if (server && server.listening) {
            await new Promise(r => server.close(r));
        }
        if (versionBackup && fs.existsSync(versionFile)) {
            fs.writeFileSync(versionFile, versionBackup, 'utf8');
        }
        if (typeof db.closeDatabase === 'function') {
            db.closeDatabase();
        }
        const cleanupFiles = [
            testDbPath,
            `${testDbPath}-wal`,
            `${testDbPath}-shm`,
            testSeedPath
        ];
        for (const f of cleanupFiles) {
            try { if (fs.existsSync(f)) fs.unlinkSync(f); } catch {}
        }
    });

    await t.test('1. Baseline release published cleanly and verified via update API', async () => {
        const res = await makeRequest(server, {
            path: '/api/app/publish',
            method: 'POST',
            headers: authHeaders,
            body: {
                latest_version: '1.4.3',
                version_code: 45,
                min_version: '1.0.0',
                release_notes: 'Initial test baseline',
                force_republish: true,
                allow_downgrade: true
            }
        });
        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.body.success, true);
        assert.strictEqual(res.body.config.latest_version, '1.4.3');
        assert.strictEqual(res.body.config.version_code, 45);

        // Verify update API contract for existing APK client
        const updateCheck = await makeRequest(server, {
            path: '/api/app/update?version_code=44'
        });
        assert.strictEqual(updateCheck.status, 200);
        assert.strictEqual(updateCheck.body.success, true);
        assert.strictEqual(updateCheck.body.update_available, true);
        assert.strictEqual(updateCheck.body.latest_version, '1.4.3');
        assert.strictEqual(updateCheck.body.version_code, 45);
        assert.ok(updateCheck.body.download_url);
        assert.ok(updateCheck.body.file_size_bytes > 0);
        assert.ok(updateCheck.body.sha256);
    });

    await t.test('2. Accidental downgrade is blocked and previous release remains active', async () => {
        const downgradeRes = await makeRequest(server, {
            path: '/api/app/publish',
            method: 'POST',
            headers: authHeaders,
            body: {
                latest_version: '1.4.0',
                version_code: 40,
                release_notes: 'Attempted downgrade'
            }
        });
        assert.strictEqual(downgradeRes.status, 400);
        assert.ok(downgradeRes.body.error.includes('downgrade prevented'));

        // Confirm active release was NOT changed
        const check = await makeRequest(server, { path: '/api/app/version' });
        assert.strictEqual(check.body.version_code, 45);
        assert.strictEqual(check.body.latest_version, '1.4.3');
    });

    await t.test('3. Duplicate release without force_republish is rejected with 409 Conflict', async () => {
        const dupRes = await makeRequest(server, {
            path: '/api/app/publish',
            method: 'POST',
            headers: authHeaders,
            body: {
                latest_version: '1.4.3',
                version_code: 45
            }
        });
        assert.strictEqual(dupRes.status, 409);
        assert.ok(dupRes.body.error.includes('already published'));
    });

    await t.test('4. Checksum mismatch rejects publication and protects previous release', async () => {
        const badHashRes = await makeRequest(server, {
            path: '/api/app/publish',
            method: 'POST',
            headers: authHeaders,
            body: {
                latest_version: '1.4.4',
                version_code: 46,
                sha256: 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
                download_url: '/api/app/download'
            }
        });
        assert.strictEqual(badHashRes.status, 400);
        assert.ok(badHashRes.body.error.includes('Checksum mismatch'));

        // Ensure release v1.4.4 was not published
        const check = await makeRequest(server, { path: '/api/app/version' });
        assert.strictEqual(check.body.version_code, 45);
    });

    await t.test('5. Unauthorized publish attempt fails with 401 and does not alter state', async () => {
        const unauthRes = await makeRequest(server, {
            path: '/api/app/publish',
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: {
                latest_version: '1.4.4',
                version_code: 46
            }
        });
        assert.strictEqual(unauthRes.status, 401);

        const check = await makeRequest(server, { path: '/api/app/version' });
        assert.strictEqual(check.body.version_code, 45);
    });

    await t.test('6. Valid subsequent release (v1.4.4, code 46) commits atomically', async () => {
        const validRes = await makeRequest(server, {
            path: '/api/app/publish',
            method: 'POST',
            headers: authHeaders,
            body: {
                latest_version: '1.4.4',
                version_code: 46,
                release_notes: 'Valid incremental release with automatic SHA256 resolution',
                download_url: '/api/app/download'
            }
        });
        assert.strictEqual(validRes.status, 200);
        assert.strictEqual(validRes.body.config.latest_version, '1.4.4');
        assert.strictEqual(validRes.body.config.version_code, 46);
        assert.ok(validRes.body.config.sha256);

        // Confirm endpoint reflects newly published release
        const check = await makeRequest(server, { path: '/api/app/version?version_code=45' });
        assert.strictEqual(check.body.update_available, true);
        assert.strictEqual(check.body.version_code, 46);
        assert.strictEqual(check.body.latest_version, '1.4.4');
    });

    await t.test('7. Client license validation operates safely before and after updates', async () => {
        // Generate a license key in test db
        const prod = await db.getOrCreateProduct('Z E X O');
        const key = await db.createActivationKey({
            product_id: prod.id,
            duration_hours: 24,
            customer_name: 'Update Client Test',
            notes: 'Test key across update lifecycle'
        });

        assert.ok(key && key.key_display);

        // First activate the key on the client device
        const activateRes = await makeRequest(server, {
            path: '/api/activate',
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: {
                key: key.key_display,
                device_id: 'test_client_device_101',
                model: 'Xiaomi 2412DPC0AI',
                app_identifier: 'com.example.rootoptimizer'
            }
        });

        assert.strictEqual(activateRes.status, 200, 'Activation must succeed');
        assert.strictEqual(activateRes.body.success, true);

        // Then validate key status as client does on periodic heartbeats
        const validateRes = await makeRequest(server, {
            path: '/api/activation/status',
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: {
                license_key: key.key_display,
                device_id: 'test_client_device_101',
                model: 'Xiaomi 2412DPC0AI'
            }
        });

        assert.strictEqual(validateRes.status, 200, 'Validation must return 200');
        assert.strictEqual(validateRes.body.valid, true);
    });
});
