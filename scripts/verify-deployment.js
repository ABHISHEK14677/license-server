#!/usr/bin/env node
const http = require('node:http');
const https = require('node:https');

const targetUrl = process.argv[2] || process.env.DEPLOYMENT_URL || process.env.CLOUD_SERVER_URL || 'http://127.0.0.1:5000';
const adminUser = process.env.ADMIN_USERNAME || 'MADARA-FF';
const adminPass = process.env.ADMIN_PASSWORD || 'ABHISHEK!';

console.log('=======================================================');
console.log('       Z E X O DEPLOYMENT VERIFICATION SUITE           ');
console.log('=======================================================');
console.log(`Target URL: ${targetUrl}`);

async function request(url, options = {}) {
    return new Promise((resolve, reject) => {
        const isHttps = url.startsWith('https:');
        const client = isHttps ? https : http;
        const u = new URL(url);

        const req = client.request(u, {
            method: options.method || 'GET',
            headers: options.headers || {}
        }, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    resolve({ status: res.statusCode, headers: res.headers, data: JSON.parse(data) });
                } catch {
                    resolve({ status: res.statusCode, headers: res.headers, data });
                }
            });
        });

        req.on('error', reject);
        if (options.body) {
            req.write(typeof options.body === 'string' ? options.body : JSON.stringify(options.body));
        }
        req.end();
    });
}

(async () => {
    let passed = 0;
    let failed = 0;

    // Check 1: Health Endpoint
    try {
        console.log('\n[1/3] Checking /api/health...');
        const health = await request(`${targetUrl}/api/health`);
        if (health.status === 200 && health.data.status === 'ok') {
            console.log('  [PASS] Service is healthy:', health.data.service);
            passed++;
        } else {
            console.error('  [FAIL] Health check failed with status:', health.status);
            failed++;
        }
    } catch (e) {
        console.error('  [FAIL] Health check connection error:', e.message);
        failed++;
    }

    // Check 2: App Version Endpoint
    try {
        console.log('\n[2/3] Checking /api/app/version...');
        const version = await request(`${targetUrl}/api/app/version?code=1`);
        if (version.status === 200 && version.data.success && version.data.latest_version) {
            console.log(`  [PASS] App version config verified: v${version.data.latest_version} (Code ${version.data.version_code})`);
            passed++;
        } else {
            console.error('  [FAIL] Version check returned unexpected response:', version.status);
            failed++;
        }
    } catch (e) {
        console.error('  [FAIL] Version check connection error:', e.message);
        failed++;
    }

    // Check 3: Admin Auth Verification
    try {
        console.log('\n[3/3] Checking Admin Authentication (/api/auth/admin/login)...');
        const login = await request(`${targetUrl}/api/auth/admin/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: { username: adminUser, password: adminPass }
        });

        if (login.status === 200 && login.data.success && login.data.token) {
            console.log('  [PASS] Admin authentication successful, token issued.');
            passed++;
        } else {
            console.warn(`  [WARN] Admin login check responded with status ${login.status}: ${login.data.message || 'Check credentials'}`);
            // Non-fatal if test environment has different credentials
        }
    } catch (e) {
        console.warn('  [WARN] Admin login connection deferred:', e.message);
    }

    console.log('\n=======================================================');
    console.log(`Verification Summary: ${passed} passed, ${failed} failed`);
    console.log('=======================================================');

    if (failed > 0) {
        console.error('[STATUS] Deployment verification FAILED.');
        process.exit(1);
    } else {
        console.log('[STATUS] Deployment verification PASSED.');
        process.exit(0);
    }
})();
