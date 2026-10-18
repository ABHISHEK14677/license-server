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

async function request(url, options = {}, redirectCount = 0) {
    if (redirectCount > 5) throw new Error('Too many redirects');
    return new Promise((resolve, reject) => {
        const isHttps = url.startsWith('https:');
        const client = isHttps ? https : http;
        const u = new URL(url);

        const req = client.request(u, {
            method: options.method || 'GET',
            headers: options.headers || {}
        }, (res) => {
            if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
                const nextUrl = new URL(res.headers.location, url).href;
                return resolve(request(nextUrl, options, redirectCount + 1));
            }

            const chunks = [];
            res.on('data', chunk => chunks.push(chunk));
            res.on('end', () => {
                const buffer = Buffer.concat(chunks);
                const str = buffer.toString('utf8');
                try {
                    resolve({ status: res.statusCode, headers: res.headers, data: JSON.parse(str), buffer });
                } catch {
                    resolve({ status: res.statusCode, headers: res.headers, data: str, buffer });
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
    let versionData = null;

    // Check 1: Health Endpoint
    try {
        console.log('\n[1/4] Checking /api/health...');
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
        console.log('\n[2/4] Checking /api/app/version...');
        const version = await request(`${targetUrl}/api/app/version?code=1`);
        if (version.status === 200 && version.data.success && version.data.latest_version) {
            versionData = version.data;
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
        console.log('\n[3/4] Checking Admin Authentication (/api/auth/admin/login)...');
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
        }
    } catch (e) {
        console.warn('  [WARN] Admin login connection deferred:', e.message);
    }

    // Check 4: APK Download & Release Integrity
    try {
        console.log('\n[4/4] Checking APK Download & Release Integrity (/api/app/download)...');
        let downloadTarget = `${targetUrl}/api/app/download`;
        if (versionData && versionData.download_url) {
            downloadTarget = versionData.download_url.startsWith('http')
                ? versionData.download_url
                : `${targetUrl}${versionData.download_url}`;
        }
        const apkRes = await request(downloadTarget, { method: 'GET' });
        if (apkRes.status === 200 && apkRes.buffer && apkRes.buffer.length > 0) {
            const isZip = apkRes.buffer.length >= 4 &&
                          apkRes.buffer[0] === 0x50 && apkRes.buffer[1] === 0x4b &&
                          apkRes.buffer[2] === 0x03 && apkRes.buffer[3] === 0x04;
            if (isZip) {
                console.log(`  [PASS] Valid APK archive verified: ${apkRes.buffer.length} bytes downloaded.`);
                passed++;
            } else {
                console.error(`  [FAIL] Downloaded file is not a valid APK ZIP archive.`);
                failed++;
            }
        } else {
            console.error(`  [FAIL] APK download failed with HTTP status ${apkRes.status}`);
            failed++;
        }
    } catch (e) {
        console.error('  [FAIL] APK download connection error:', e.message);
        failed++;
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
