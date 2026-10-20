const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const fs = require('node:fs');
const http = require('node:http');

// Isolate test database and seed files so production state is NEVER modified
const testDbPath = path.join(__dirname, 'test-key-mgmt.db');
const testSeedPath = path.join(__dirname, 'test-key-mgmt-seed.json');
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

test('Key Management & UI Test Suite', async (t) => {
    let server;
    let adminToken;
    const testAdminHeader = () => ({
        'Authorization': `Bearer ${adminToken}`,
        'Content-Type': 'application/json'
    });

    await db.initDatabase();

    await new Promise((resolve) => {
        server = app.listen(0, '127.0.0.1', () => resolve());
    });

    t.after(async () => {
        if (server && server.listening) {
            server.close();
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
            try {
                if (fs.existsSync(f)) fs.unlinkSync(f);
            } catch {}
        }
    });

    // Obtain admin token
    const loginRes = await makeRequest(server, {
        path: '/api/auth/admin/login',
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: {
            username: config.adminUsername,
            password: config.adminPassword
        }
    });
    assert.strictEqual(loginRes.status, 200, 'Admin login should succeed');
    adminToken = loginRes.body.token;
    assert.ok(adminToken, 'Admin token should be returned');

    async function createTestKey(params = {}) {
        const res = await makeRequest(server, {
            path: '/api/keys/generate',
            method: 'POST',
            headers: testAdminHeader(),
            body: {
                duration_hours: params.durationHours || 24,
                customer_name: params.customerName || 'Test Customer',
                notes: params.notes || 'Test Notes',
                max_devices: params.maxDevices || 1
            }
        });
        assert.strictEqual(res.status, 200, 'Key generation API should succeed');
        return res.body;
    }

    await t.test('1. Discord Link: updated everywhere and old link removed', async () => {
        const indexHtmlPath = path.join(__dirname, '..', 'public', 'index.html');
        const content = fs.readFileSync(indexHtmlPath, 'utf8');

        // Verify new link is present
        assert.ok(content.includes('https://discord.gg/z8HCwPPDZZ'), 'public/index.html must contain new discord link');

        // Verify old links are NOT present
        assert.strictEqual(content.includes('CM3KgmuHm'), false, 'public/index.html must not contain old discord invite link CM3KgmuHm');
        assert.strictEqual(content.includes('hBvx4Avpe'), false, 'public/index.html must not contain old discord invite link hBvx4Avpe');
    });

    await t.test('2. UI Key View Statuses & Non-Active renaming', async () => {
        const indexHtmlPath = path.join(__dirname, '..', 'public', 'index.html');
        const content = fs.readFileSync(indexHtmlPath, 'utf8');

        // Check Non-Active stat card & chip exist
        assert.ok(content.includes('Non-Active'), 'public/index.html must show Non-Active label');
        assert.ok(content.includes('metricInactiveKeys'), 'Metric element for non-active keys must exist');
        assert.ok(content.includes('metricPausedKeys'), 'Metric element for paused keys must exist');
        assert.ok(content.includes('metricRevokedKeys'), 'Metric element for revoked keys must exist');

        // Check computeKeyStatus handles statuses
        assert.ok(content.includes("'NON-ACTIVE'"), 'computeKeyStatus must return NON-ACTIVE');
        assert.ok(content.includes("'PAUSED'"), 'computeKeyStatus must return PAUSED');
        assert.ok(content.includes("'REVOKED'"), 'computeKeyStatus must return REVOKED');
    });

    await t.test('3. Key Statuses in Dashboard Stats & Logical Distinction', async () => {
        // Generate test keys with various statuses
        const activeKey = await createTestKey({
            durationHours: 24,
            customerName: 'Test Active',
            notes: 'Active key test'
        });
        // Activate key
        await db.updateKeyDetails(activeKey.id, {
            status: 'ACTIVE',
            activatedAt: new Date().toISOString(),
            expiresAt: new Date(Date.now() + 24 * 3600 * 1000).toISOString()
        });

        const unactivatedKey = await createTestKey({
            durationHours: 24,
            customerName: 'Test Non-Active',
            notes: 'Non-Active key test'
        });

        const pausedKey = await createTestKey({
            durationHours: 24,
            customerName: 'Test Paused',
            notes: 'Paused key test'
        });
        await db.updateKeyStatus(pausedKey.id, 'PAUSED');

        const revokedKey = await createTestKey({
            durationHours: 24,
            customerName: 'Test Revoked',
            notes: 'Revoked key test'
        });
        await db.updateKeyStatus(revokedKey.id, 'REVOKED');

        const statsRes = await makeRequest(server, {
            path: '/api/dashboard/stats',
            method: 'GET',
            headers: testAdminHeader()
        });
        assert.strictEqual(statsRes.status, 200);
        const stats = statsRes.body.stats;

        assert.ok(stats.total_keys >= 4, 'Total keys count should reflect all keys');
        assert.ok(stats.non_active_keys >= 1, 'Non-active keys should include unactivated keys');
        assert.ok(stats.paused_keys >= 1, 'Paused keys should be counted');
        assert.ok(stats.revoked_keys >= 1, 'Revoked keys should be counted');

        // Ensure paused & revoked keys are strictly excluded from active_keys
        const pausedKeyCheck = await db.getKeyById(pausedKey.id);
        assert.strictEqual(pausedKeyCheck.status, 'PAUSED');
        const revokedKeyCheck = await db.getKeyById(revokedKey.id);
        assert.strictEqual(revokedKeyCheck.status, 'REVOKED');

        // Cleanup
        await db.deleteKey(activeKey.id, 'test');
        await db.deleteKey(unactivatedKey.id, 'test');
        await db.deleteKey(pausedKey.id, 'test');
        await db.deleteKey(revokedKey.id, 'test');
    });

    await t.test('4. Key Editing Latency & Safety: Rejection of Lifetime Extension and Revoked Reactivation', async () => {
        const testKey = await createTestKey({
            durationHours: 24,
            customerName: 'Editing Test',
            notes: 'Original note'
        });

        // 4a. Attempting to set duration_hours = -1 via edit must be rejected (400)
        const rejectPermRes = await makeRequest(server, {
            path: `/api/keys/${testKey.id}`,
            method: 'PATCH',
            headers: testAdminHeader(),
            body: { duration_hours: -1 }
        });
        assert.strictEqual(rejectPermRes.status, 400, 'Setting duration_hours: -1 via key edit must be rejected with 400');
        assert.ok(rejectPermRes.body.message.includes('Permanent') || rejectPermRes.body.message.includes('lifetime'));

        // 4b. Editing normal attributes (customer name, notes, max devices) succeeds quickly and preserves expiration
        const initialExpiresAt = new Date(Date.now() + 48 * 3600 * 1000).toISOString();
        await db.updateKeyDetails(testKey.id, {
            status: 'ACTIVE',
            activatedAt: new Date().toISOString(),
            expiresAt: initialExpiresAt
        });

        const updateRes = await makeRequest(server, {
            path: `/api/keys/${testKey.id}`,
            method: 'PATCH',
            headers: testAdminHeader(),
            body: {
                customer_name: 'Updated Customer',
                notes: 'Updated note'
            }
        });
        assert.strictEqual(updateRes.status, 200, 'Normal edit should succeed');
        assert.strictEqual(updateRes.body.key.customer_name, 'Updated Customer');
        assert.strictEqual(updateRes.body.key.notes, 'Updated note');
        // Expiration must be preserved
        assert.strictEqual(updateRes.body.key.expires_at, initialExpiresAt, 'Expiration timestamp must be preserved on ordinary edit');

        // 4c. Revoking a key and trying to reactivate it via ordinary edit must be rejected (400)
        await db.updateKeyStatus(testKey.id, 'REVOKED');
        const reactivateRes = await makeRequest(server, {
            path: `/api/keys/${testKey.id}`,
            method: 'PATCH',
            headers: testAdminHeader(),
            body: { status: 'ACTIVE' }
        });
        assert.strictEqual(reactivateRes.status, 400, 'Reactivating a revoked key via edit must be rejected with 400');

        // 4d. Permanent key generation attempt must be rejected (400)
        const rejectGenPermRes = await makeRequest(server, {
            path: '/api/keys/generate',
            method: 'POST',
            headers: testAdminHeader(),
            body: { duration_hours: -1, count: 1 }
        });
        assert.strictEqual(rejectGenPermRes.status, 400, 'Generating a permanent key (-1) must be rejected with 400');

        // 4e. Valid temporary key generation produces time-limited key with is_permanent: false
        const validGenRes = await makeRequest(server, {
            path: '/api/keys/generate',
            method: 'POST',
            headers: testAdminHeader(),
            body: { duration_hours: 24, count: 1 }
        });
        assert.strictEqual(validGenRes.status, 200, 'Generating a 24h key must succeed');
        assert.strictEqual(validGenRes.body.duration_hours, 24);
        assert.strictEqual(validGenRes.body.is_permanent, false, 'Generated key must have is_permanent: false');

        await db.deleteKey(testKey.id, 'test');
        if (validGenRes.body.id) await db.deleteKey(validGenRes.body.id, 'test');
    });

    await t.test('5. Reduce Time Feature: shortening validity with validation, past-date expiration, and audit logging', async () => {
        const testKey = await createTestKey({
            durationHours: 24,
            customerName: 'Reduce Time Test'
        });

        const now = Date.now();
        const initialExp = new Date(now + 48 * 3600 * 1000).toISOString();
        await db.updateKeyDetails(testKey.id, {
            status: 'ACTIVE',
            activatedAt: new Date(now).toISOString(),
            expiresAt: initialExp
        });

        // 5a. Reduce by 12 hours
        const reduceRes1 = await makeRequest(server, {
            path: `/api/keys/${testKey.id}/reduce-time`,
            method: 'POST',
            headers: testAdminHeader(),
            body: { amount: 12, unit: 'hours' }
        });
        assert.strictEqual(reduceRes1.status, 200, 'Reducing by 12 hours should succeed');
        assert.strictEqual(reduceRes1.body.success, true);
        const updatedExp1 = new Date(reduceRes1.body.key.expires_at).getTime();
        const expectedExp1 = new Date(initialExp).getTime() - (12 * 3600 * 1000);
        assert.strictEqual(Math.abs(updatedExp1 - expectedExp1) < 1000, true, 'Expiration should be shortened by exactly 12 hours');
        assert.strictEqual(reduceRes1.body.key.status, 'ACTIVE');

        // 5b. Reduce by 1 day (24 hours)
        const reduceRes2 = await makeRequest(server, {
            path: `/api/keys/${testKey.id}/reduce-time`,
            method: 'POST',
            headers: testAdminHeader(),
            body: { amount: 1, unit: 'days' }
        });
        assert.strictEqual(reduceRes2.status, 200, 'Reducing by 1 day should succeed');
        const updatedExp2 = new Date(reduceRes2.body.key.expires_at).getTime();
        const expectedExp2 = expectedExp1 - (24 * 3600 * 1000);
        assert.strictEqual(Math.abs(updatedExp2 - expectedExp2) < 1000, true, 'Expiration should be shortened by 24 hours');

        // 5c. Validation: negative or zero amount rejected
        const invalidRes1 = await makeRequest(server, {
            path: `/api/keys/${testKey.id}/reduce-time`,
            method: 'POST',
            headers: testAdminHeader(),
            body: { amount: -5, unit: 'hours' }
        });
        assert.strictEqual(invalidRes1.status, 400, 'Negative reduction amount must be rejected');

        const invalidRes2 = await makeRequest(server, {
            path: `/api/keys/${testKey.id}/reduce-time`,
            method: 'POST',
            headers: testAdminHeader(),
            body: { amount: 0, unit: 'hours' }
        });
        assert.strictEqual(invalidRes2.status, 400, 'Zero reduction amount must be rejected');

        const invalidRes3 = await makeRequest(server, {
            path: `/api/keys/${testKey.id}/reduce-time`,
            method: 'POST',
            headers: testAdminHeader(),
            body: { amount: 5, unit: 'months' }
        });
        assert.strictEqual(invalidRes3.status, 400, 'Unsupported unit must be rejected');

        // 5d. Resulting expiration in past auto-marks key as EXPIRED
        const expireRes = await makeRequest(server, {
            path: `/api/keys/${testKey.id}/reduce-time`,
            method: 'POST',
            headers: testAdminHeader(),
            body: { amount: 100, unit: 'days' }
        });
        assert.strictEqual(expireRes.status, 200, 'Large reduction should succeed');
        assert.strictEqual(expireRes.body.key.status, 'EXPIRED', 'Resulting past expiration must set status to EXPIRED');

        // 5e. Rejection on revoked key
        await db.updateKeyStatus(testKey.id, 'REVOKED');
        const revokedReduceRes = await makeRequest(server, {
            path: `/api/keys/${testKey.id}/reduce-time`,
            method: 'POST',
            headers: testAdminHeader(),
            body: { amount: 1, unit: 'hours' }
        });
        assert.strictEqual(revokedReduceRes.status, 400, 'Reducing validity on revoked key must be rejected');

        // 5f. Audit log verification
        const auditLogs = await db.getAuditLogs(10);
        const reduceLog = auditLogs.find(l => l.action === 'KEY_TIME_REDUCED' && l.details?.key_id === testKey.id);
        assert.ok(reduceLog, 'KEY_TIME_REDUCED must be recorded in audit logs');
        assert.ok(reduceLog.details.previous_expires_at, 'Audit log must record previous expiration');
        assert.ok(reduceLog.details.new_expires_at, 'Audit log must record new expiration');

        await db.deleteKey(testKey.id, 'test');
    });

    await t.test('6. Server-Side License Validation & Client Activation: Paused and Revoked keys rejected with 403', async () => {
        // Create active key and register device
        const keyObj = await createTestKey({
            durationHours: 24,
            customerName: 'Client Access Test'
        });

        // 6a. Activate key for device
        const actRes = await makeRequest(server, {
            path: '/api/activate',
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: {
                key: keyObj.key || keyObj.key_display,
                device_id: 'test_device_999',
                device_model: 'Pixel 8 Pro'
            }
        });
        assert.strictEqual(actRes.status, 200, 'Initial activation should succeed');
        assert.strictEqual(actRes.body.success, true);
        const sessionToken = actRes.body.session_token;

        // 6b. License validation passes when active
        const valRes1 = await makeRequest(server, {
            path: '/api/license/validate',
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: {
                key: keyObj.key || keyObj.key_display,
                device_id: 'test_device_999',
                token: sessionToken
            }
        });
        assert.strictEqual(valRes1.status, 200, 'Validation should succeed for active key');
        assert.strictEqual(valRes1.body.valid, true);

        // 6c. Pause key -> /api/license/validate & /api/activate must return 403
        await db.updateKeyStatus(keyObj.id, 'PAUSED');

        const valPausedRes = await makeRequest(server, {
            path: '/api/license/validate',
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: {
                key: keyObj.key || keyObj.key_display,
                device_id: 'test_device_999',
                token: sessionToken
            }
        });
        assert.strictEqual(valPausedRes.status, 403, 'Validation must return 403 on paused key');
        assert.strictEqual(valPausedRes.body.valid, false);

        const actPausedRes = await makeRequest(server, {
            path: '/api/activate',
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: {
                key: keyObj.key || keyObj.key_display,
                device_id: 'test_device_999'
            }
        });
        assert.strictEqual(actPausedRes.status, 403, 'Activation must return 403 on paused key');

        // 6d. Revoke key -> /api/license/validate & /api/activate must return 403
        await db.updateKeyStatus(keyObj.id, 'REVOKED');

        const valRevokedRes = await makeRequest(server, {
            path: '/api/license/validate',
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: {
                key: keyObj.key || keyObj.key_display,
                device_id: 'test_device_999',
                token: sessionToken
            }
        });
        assert.strictEqual(valRevokedRes.status, 403, 'Validation must return 403 on revoked key');
        assert.strictEqual(valRevokedRes.body.valid, false);

        const actRevokedRes = await makeRequest(server, {
            path: '/api/activate',
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: {
                key: keyObj.key || keyObj.key_display,
                device_id: 'test_device_999'
            }
        });
        assert.strictEqual(actRevokedRes.status, 403, 'Activation must return 403 on revoked key');

        await db.deleteKey(keyObj.id, 'test');
    });
});
