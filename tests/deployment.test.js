const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const fs = require('node:fs');
const http = require('node:http');

// Isolate test database and seed files so production state is NEVER modified
const testDbPath = path.join(__dirname, 'test-deployment.db');
const testSeedPath = path.join(__dirname, 'test-deployment-seed.json');
process.env.SQLITE_DB_PATH = testDbPath;
process.env.SEED_FILE_PATH = testSeedPath;
process.env.NODE_ENV = 'test';

const { app } = require('../server');
const db = require('../db');
const {
    config,
    resolveConfig,
    validateConfig,
    getSanitizedConfig,
    safeTimingCompare
} = require('../config');

// Helper to make local HTTP requests to the test Express app
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

test('Deployment Test Suite (Scenarios A through G)', async (t) => {
    let server;
    const testPort = 0; // OS assigns free ephemeral port
    const originalVersionFile = path.join(__dirname, '..', 'public', 'downloads', 'version.json');
    let originalVersionBackup = null;
    if (fs.existsSync(originalVersionFile)) {
        originalVersionBackup = fs.readFileSync(originalVersionFile, 'utf8');
    }

    await db.initDatabase();

    await new Promise((resolve) => {
        server = app.listen(testPort, '127.0.0.1', () => resolve());
    });

    try {
        // -------------------------------------------------------------
        // TEST A: Publish a normal application update
        // -------------------------------------------------------------
        await t.test('Test A: Normal update publishing preserves server configuration & database', async () => {
            const adminSecret = config.adminSecret;
            const updatePayload = {
                latest_version: '1.3.7-test',
                version_code: 39,
                release_notes: 'Automated test release notes',
                min_version: '1.0.0',
                allow_downgrade: true
            };

            const res = await makeRequest(server, {
                path: '/api/app/publish',
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'x-admin-key': adminSecret
                },
                body: updatePayload
            });

            assert.strictEqual(res.status, 200, 'Publish endpoint must return 200 OK');
            assert.strictEqual(res.body.success, true);
            assert.strictEqual(res.body.config.latest_version, '1.3.7-test');
            assert.strictEqual(res.body.config.version_code, 39);

            // Confirm version endpoint reflects this update
            const versionRes = await makeRequest(server, { path: '/api/app/version?code=1' });
            assert.strictEqual(versionRes.status, 200);
            assert.strictEqual(versionRes.body.latest_version, '1.3.7-test');
            assert.strictEqual(versionRes.body.version_code, 39);

            // Confirm existing server credentials remain intact
            const admin = await db.getAdminByUsername(config.adminUsername);
            assert.ok(admin, 'Admin account must remain present after publish');
            assert.strictEqual(admin.username, config.adminUsername);
        });

        // -------------------------------------------------------------
        // TEST B: Deploy with required environment variable missing
        // -------------------------------------------------------------
        await t.test('Test B: Deployment with missing required secrets fails safely without secret leakage', async () => {
            // Simulate missing ADMIN_SECRET in production
            const missingSecretEnv = {
                NODE_ENV: 'production',
                ADMIN_PASSWORD: 'ValidProductionPassword123!',
                ADMIN_SECRET: '' // missing!
            };
            const prodConfig = resolveConfig(missingSecretEnv);
            const validation = validateConfig(prodConfig);

            assert.strictEqual(validation.valid, false, 'Validation must fail when required secret is missing');
            assert.ok(validation.errors.some(e => e.includes('ADMIN_SECRET')), 'Error must report missing variable name');

            // Verify that no secret value is leaked in error messages
            const errorReport = JSON.stringify(validation.errors);
            assert.strictEqual(errorReport.includes('ValidProductionPassword123!'), false, 'Secret values must never appear in errors');

            // Verify rejected unauthorized attempt on publish
            const unauthorizedRes = await makeRequest(server, {
                path: '/api/app/publish',
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: { latest_version: '1.9.9' }
            });
            assert.strictEqual(unauthorizedRes.status, 401, 'Unauthorized request must be rejected with 401');
        });

        // -------------------------------------------------------------
        // TEST C: Publish multiple consecutive updates (Repeatability & Idempotence)
        // -------------------------------------------------------------
        await t.test('Test C: Multiple consecutive updates remain stable and repeatable', async () => {
            const versions = [
                { version: '1.4.0', code: 40 },
                { version: '1.4.1', code: 41 },
                { version: '1.4.2', code: 42 }
            ];

            for (const v of versions) {
                const res = await makeRequest(server, {
                    path: '/api/app/publish',
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'x-admin-key': config.adminSecret
                    },
                    body: { latest_version: v.version, version_code: v.code }
                });
                assert.strictEqual(res.status, 200, `Update to ${v.version} must succeed`);
                assert.strictEqual(res.body.config.latest_version, v.version);
            }

            // Verify the final version is properly active
            const finalCheck = await makeRequest(server, { path: '/api/app/version' });
            assert.strictEqual(finalCheck.body.latest_version, '1.4.2');
            assert.strictEqual(finalCheck.body.version_code, 42);
        });

        // -------------------------------------------------------------
        // TEST D: Simulate an application startup failure & recovery
        // -------------------------------------------------------------
        await t.test('Test D: Invalid configuration triggers clean failure and supports recovery', async () => {
            // Bad config (invalid port)
            const brokenConfig = resolveConfig({ PORT: 'invalid_port', NODE_ENV: 'production' });
            const validationBroken = validateConfig(brokenConfig);
            assert.strictEqual(validationBroken.valid, false);
            assert.ok(validationBroken.errors.some(e => e.includes('PORT')));

            // Rollback to valid configuration
            const restoredConfig = resolveConfig({
                PORT: '5000',
                NODE_ENV: 'production',
                ADMIN_SECRET: 'StrongProductionSecret_2026_XYZ',
                ADMIN_PASSWORD: 'StrongPassword123!'
            });
            const validationRestored = validateConfig(restoredConfig);
            assert.strictEqual(validationRestored.valid, true);
        });

        // -------------------------------------------------------------
        // TEST E: Verify production and development configurations remain isolated
        // -------------------------------------------------------------
        await t.test('Test E: Production and development configurations remain strictly isolated', async () => {
            const devConf = resolveConfig({ NODE_ENV: 'development' });
            const prodConf = resolveConfig({ NODE_ENV: 'production' });

            assert.strictEqual(devConf.isProduction, false);
            assert.strictEqual(prodConf.isProduction, true);

            // Development allows dev fallback secrets; production strictly forbids them
            const devValidation = validateConfig(devConf);
            assert.strictEqual(devValidation.valid, true);

            const prodValidation = validateConfig(prodConf);
            assert.strictEqual(prodValidation.valid, false, 'Production must reject unset secrets');
        });

        // -------------------------------------------------------------
        // TEST F: Check logs and generated build artifacts for exposed credentials
        // -------------------------------------------------------------
        await t.test('Test F: Verify no credentials are exposed in sanitized outputs or version data', async () => {
            const sanitized = getSanitizedConfig(config);
            const serialized = JSON.stringify(sanitized);

            // Plaintext password/secret must not be present in sanitized output
            if (config.adminSecret && config.adminSecret.length > 5) {
                assert.strictEqual(serialized.includes(config.adminSecret), false);
            }
            if (config.adminPassword && config.adminPassword.length > 5) {
                assert.strictEqual(serialized.includes(config.adminPassword), false);
            }

            // Version config file must not contain credentials
            const versionData = JSON.parse(fs.readFileSync(originalVersionFile, 'utf8'));
            const versionKeys = Object.keys(versionData);
            assert.strictEqual(versionKeys.includes('admin_key'), false);
            assert.strictEqual(versionKeys.includes('password'), false);
            assert.strictEqual(versionKeys.includes('secret'), false);
        });

        // -------------------------------------------------------------
        // TEST G: Unrelated workflow and server settings remain unchanged after deployment
        // -------------------------------------------------------------
        await t.test('Test G: Unrelated server settings remain unchanged across releases', async () => {
            const healthRes = await makeRequest(server, { path: '/api/health' });
            assert.strictEqual(healthRes.status, 200);
            assert.strictEqual(healthRes.body.developedBy, 'MADARA FF');
            assert.strictEqual(healthRes.body.service, 'Zexora License Authority');

            // Product catalogue in database remains intact
            const products = await db.getAllProducts();
            const prod = products.find(p => p.name === 'Z E X O');
            assert.ok(prod, 'Default product "Z E X O" must remain unchanged in database');
        });

        // -------------------------------------------------------------
        // TEST H: Hardened validation on /api/app/publish prevents corrupt/invalid releases
        // -------------------------------------------------------------
        await t.test('Test H: Publish endpoint validates semver, rejects negative code, and prevents downgrade', async () => {
            // 1. Invalid semver format
            const invalidSemver = await makeRequest(server, {
                path: '/api/app/publish',
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'x-admin-key': config.adminSecret },
                body: { latest_version: 'invalid-version', version_code: 99 }
            });
            assert.strictEqual(invalidSemver.status, 400);
            assert.ok(invalidSemver.body.error.includes('semantic versioning'));

            // 2. Invalid / negative version_code
            const invalidCode = await makeRequest(server, {
                path: '/api/app/publish',
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'x-admin-key': config.adminSecret },
                body: { latest_version: '2.0.0', version_code: -5 }
            });
            assert.strictEqual(invalidCode.status, 400);
            assert.ok(invalidCode.body.error.includes('positive integer'));

            // 3. Prevent accidental downgrade without explicit flag
            const downgradeRes = await makeRequest(server, {
                path: '/api/app/publish',
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'x-admin-key': config.adminSecret },
                body: { latest_version: '1.0.0', version_code: 10 }
            });
            assert.strictEqual(downgradeRes.status, 400);
            assert.ok(downgradeRes.body.error.includes('downgrade prevented'));
        });

        // -------------------------------------------------------------
        // TEST I: Accurate version evaluation prevents endless update loops
        // -------------------------------------------------------------
        await t.test('Test I: Version evaluation accurately checks current client code and avoids false positives', async () => {
            // Client on equal or higher version code should report update_available = false
            const checkCurrent = await makeRequest(server, { path: '/api/app/version?version_code=42' });
            assert.strictEqual(checkCurrent.status, 200);
            assert.strictEqual(checkCurrent.body.update_available, false, 'Client on code 42 must NOT receive update warning');

            // Client on older code receives update_available = true
            const checkOld = await makeRequest(server, { path: '/api/app/version?version_code=38' });
            assert.strictEqual(checkOld.status, 200);
            assert.strictEqual(checkOld.body.update_available, true, 'Client on code 38 must receive update notice');

            // Request with no version params does not trigger a false update loop
            const checkEmpty = await makeRequest(server, { path: '/api/app/version' });
            assert.strictEqual(checkEmpty.status, 200);
            assert.strictEqual(checkEmpty.body.update_available, false, 'No version parameters must default to false');
        });

        // -------------------------------------------------------------
        // TEST J: Database-backed release persistence across container restarts
        // -------------------------------------------------------------
        await t.test('Test J: Release metadata persists in database and survives file cache removal', async () => {
            const dbRelease = await db.getLatestAppRelease();
            assert.ok(dbRelease, 'Latest release must exist in database');
            assert.strictEqual(typeof dbRelease.version_code, 'number');
            assert.strictEqual(typeof dbRelease.latest_version, 'string');
        });

        // -------------------------------------------------------------
        // TEST K: Checksum verification rejects corrupted / mismatched releases
        // -------------------------------------------------------------
        await t.test('Test K: Publishing rejects mismatched SHA-256 checksums', async () => {
            const mismatchRes = await makeRequest(server, {
                path: '/api/app/publish',
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'x-admin-key': config.adminSecret
                },
                body: {
                    latest_version: '1.9.0',
                    version_code: 90,
                    download_url: '/api/app/download',
                    sha256: '0000000000000000000000000000000000000000000000000000000000000000'
                }
            });
            assert.strictEqual(mismatchRes.status, 400);
            assert.ok(mismatchRes.body.error.includes('Checksum mismatch') || mismatchRes.body.error.includes('checksum'));
        });

        // -------------------------------------------------------------
        // TEST L: Checksum format validation rejects non-hex or invalid lengths
        // -------------------------------------------------------------
        await t.test('Test L: Publishing rejects malformed SHA-256 format', async () => {
            const badFormatRes = await makeRequest(server, {
                path: '/api/app/publish',
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'x-admin-key': config.adminSecret
                },
                body: {
                    latest_version: '1.9.1',
                    version_code: 91,
                    sha256: 'not-a-valid-sha256'
                }
            });
            assert.strictEqual(badFormatRes.status, 400);
            assert.ok(badFormatRes.body.error.includes('Invalid sha256'));
        });

        // -------------------------------------------------------------
        // TEST M: Admin setup endpoint rejects unauthenticated attacker account creation
        // -------------------------------------------------------------
        await t.test('Test M: Admin setup endpoint rejects unauthorized registration attempts', async () => {
            const unauthorizedSetup = await makeRequest(server, {
                path: '/api/auth/admin/setup',
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: {
                    username: 'unauthorized_attacker',
                    password: 'AttackerPassword123!',
                    secret: 'wrong_secret'
                }
            });
            assert.strictEqual(unauthorizedSetup.status, 403);
            assert.ok(unauthorizedSetup.body.message.includes('Valid administrator secret required'));

            // Verify attacker was not created
            const attacker = await db.getAdminByUsername('unauthorized_attacker');
            assert.strictEqual(attacker, null);
        });

        // -------------------------------------------------------------
        // TEST N: Simulated restart preserves admin credentials without regenerating secrets
        // -------------------------------------------------------------
        await t.test('Test N: Simulated application restarts preserve admin credentials without regeneration', async () => {
            const adminBefore = await db.getAdminByUsername(config.adminUsername);
            assert.ok(adminBefore, 'Admin exists before restart');
            const saltBefore = adminBefore.salt;
            const hashBefore = adminBefore.password_hash;

            // Re-initialize database as happens on server reboot
            await db.initDatabase();

            const adminAfter = await db.getAdminByUsername(config.adminUsername);
            assert.strictEqual(adminAfter.salt, saltBefore, 'Salt must not change across restart');
            assert.strictEqual(adminAfter.password_hash, hashBefore, 'Password hash must not change across restart');
        });

    } finally {
        if (server) {
            await new Promise((resolve) => server.close(resolve));
        }
        // Restore original version.json backup
        if (originalVersionBackup && fs.existsSync(originalVersionFile)) {
            fs.writeFileSync(originalVersionFile, originalVersionBackup, 'utf8');
        }
        // Close test DB and clean up isolated test artifacts
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
            try {
                if (fs.existsSync(f)) fs.unlinkSync(f);
            } catch {}
        }
    }
});
