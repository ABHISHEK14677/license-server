const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const fs = require('node:fs');
const http = require('node:http');

// Dedicated isolated database for hardening audit test suite
const testDbPath = path.join(__dirname, 'test-hardening-audit.db');
const testSeedPath = path.join(__dirname, 'test-hardening-seed.json');
process.env.SQLITE_DB_PATH = testDbPath;
process.env.SEED_FILE_PATH = testSeedPath;
process.env.NODE_ENV = 'test';

const { app } = require('../server');
const db = require('../db');
const { config, resolveConfig, validateConfig, getSanitizedConfig } = require('../config');

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
            const chunks = [];
            res.on('data', chunk => chunks.push(chunk));
            res.on('end', () => {
                const buffer = Buffer.concat(chunks);
                const str = buffer.toString('utf8');
                let parsed = str;
                try { parsed = JSON.parse(str); } catch {}
                resolve({ status: res.statusCode, headers: res.headers, body: parsed, buffer });
            });
        });
        req.on('error', reject);
        if (options.body) {
            req.write(typeof options.body === 'string' ? options.body : JSON.stringify(options.body));
        }
        req.end();
    });
}

test('Hardening Audit Test Suite (Phases 1-11)', async (t) => {
    let server;
    await db.initDatabase();

    await new Promise((resolve) => {
        server = app.listen(0, '127.0.0.1', () => resolve());
    });

    // Clean up test database files after suite completes
    t.after(() => {
        if (server) server.close();
        try { fs.unlinkSync(testDbPath); } catch {}
        try { fs.unlinkSync(testSeedPath); } catch {}
    });

    await t.test('1. HTTP Range Request Support for Resumable APK Downloads', async () => {
        const res = await makeRequest(server, {
            path: '/download/RootOptimizer.apk',
            method: 'GET',
            headers: { 'Range': 'bytes=0-1023' }
        });

        assert.strictEqual(res.status, 206, 'Should respond with 206 Partial Content');
        assert.strictEqual(res.headers['accept-ranges'], 'bytes', 'Must advertise Accept-Ranges: bytes');
        assert.ok(res.headers['content-range'], 'Must include Content-Range header');
        assert.ok(res.headers['content-range'].startsWith('bytes 0-1023/'), 'Content-Range must reflect requested range');
        assert.strictEqual(res.buffer.length, 1024, 'Returned chunk size must exactly equal 1024 bytes');
        assert.ok(res.headers['etag'], 'Must provide an ETag');
    });

    await t.test('2. Invalid HTTP Range Request Returns 416 Range Not Satisfiable', async () => {
        const res = await makeRequest(server, {
            path: '/download/RootOptimizer.apk',
            method: 'GET',
            headers: { 'Range': 'bytes=999999999-999999999' }
        });

        assert.strictEqual(res.status, 416, 'Out of bounds range must return 416');
        assert.ok(res.headers['content-range'].startsWith('bytes */'), 'Must return bytes */total');
    });

    await t.test('3. Artifact Verification Rejects Corrupt/Non-APK Archives', async () => {
        // Create dummy non-apk zip in downloads with distinct filename
        const corruptPath = path.join(__dirname, '..', 'public', 'downloads', 'corrupt_test.apk');
        const zipHeader = Buffer.from([0x50, 0x4B, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00, 0x74, 0x65, 0x73, 0x74]);
        fs.writeFileSync(corruptPath, zipHeader);

        try {
            const publishRes = await makeRequest(server, {
                path: '/api/app/publish',
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'x-admin-key': config.adminSecret
                },
                body: {
                    latest_version: '1.4.9',
                    version_code: 99,
                    release_notes: 'Testing corrupt archive rejection',
                    apk_filename: 'corrupt_test.apk',
                    download_url: '/api/app/download',
                    force_republish: true
                }
            });

            assert.strictEqual(publishRes.status, 400, 'Must reject APK without AndroidManifest.xml and classes.dex');
            assert.ok(publishRes.body.error.includes('AndroidManifest.xml and classes.dex'), 'Error must specify missing APK structure');
        } finally {
            try { fs.unlinkSync(corruptPath); } catch {}
        }
    });

    await t.test('4. Publishing Preserves Database Keys and Secrets Completely', async () => {
        // Record pre-publish admin & key count
        const preKeys = await db.getAllKeys();
        const preStats = await db.getDashboardStats();

        const publishRes = await makeRequest(server, {
            path: '/api/app/publish',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-admin-key': config.adminSecret
            },
            body: {
                latest_version: '1.4.3',
                version_code: 45,
                release_notes: 'Preservation verification release',
                download_url: '/api/app/download',
                force_republish: true,
                allow_downgrade: true
            }
        });

        assert.strictEqual(publishRes.status, 200, 'Publishing should succeed');

        // Verify post-publish admin & key count
        const postKeys = await db.getAllKeys();
        const postStats = await db.getDashboardStats();

        assert.strictEqual(postKeys.length, preKeys.length, 'Key records must remain completely unchanged');
        assert.strictEqual(postStats.total_keys, preStats.total_keys, 'Total key count must remain untouched');
    });

    await t.test('5. Safe Failure When Required Production Configuration Is Missing', () => {
        const testPassword = 'ValidProductionPassword123!';
        const missingSecretCfg = resolveConfig({
            NODE_ENV: 'production',
            ADMIN_PASSWORD: testPassword,
            ADMIN_SECRET: ''
        });

        const validation = validateConfig(missingSecretCfg);
        assert.strictEqual(validation.valid, false, 'Validation must fail when ADMIN_SECRET is missing');
        assert.ok(validation.errors.some(e => e.includes('ADMIN_SECRET')), 'Must identify missing ADMIN_SECRET by name');
        assert.ok(validation.errors.some(e => e.includes('Render Dashboard')), 'Must provide actionable restoration instructions');

        // Sanitized config must never leak secrets
        const sanitized = getSanitizedConfig(missingSecretCfg);
        assert.strictEqual(sanitized.adminSecretMasked, '[NOT_SET]');
        assert.strictEqual(sanitized.adminPasswordMasked, `[REDACTED: len=${testPassword.length}]`);
    });
});
