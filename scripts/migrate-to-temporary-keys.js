#!/usr/bin/env node
const fs = require('node:fs');
const path = require('node:path');
const db = require('../db');
const { hashKey, getKeyLast4 } = require('../auth');
const { config } = require('../config');

const V143_ACTIVE_KEYS = [
    { key: 'MADARA-FF-5HAQ-MB8E-VCGH-WVMC', customer: 'MADARA FF', notes: 'v1.4.3 Active Key - 1 Day' },
    { key: 'MADARA-FF-B2K5-UV4X-YTRN-F8M8', customer: 'TRIAL', notes: 'v1.4.3 Active Key - 1 Day' },
    { key: 'MADARA-FF-JFFL-JCHQ-D3AX-4MLC', customer: 'MUKESH', notes: 'v1.4.3 Active Key - 1 Day' },
    { key: 'MADARA-FF-53D5-EFGY-6ST5-RMB6', customer: 'KAVISH', notes: 'v1.4.3 Active Key - 1 Day' },
    { key: 'MADARA-FF-PSVB-9C3H-FY6W-KEXZ', customer: 'DHARSHAN', notes: 'v1.4.3 Active Key - 1 Day' },
    { key: 'MADARA-FF-4W2B-M4KF-T9QS-KEV2', customer: 'SRINIVASAN', notes: 'v1.4.3 Active Key - 1 Day' }
];

const KEEP_SET = new Set(V143_ACTIVE_KEYS.map(k => k.key.trim().toUpperCase()));
const DURATION_HOURS = 24; // 1 Day

(async () => {
    try {
        console.log('=======================================================');
        console.log(' MIGRATE TO 1-DAY TEMPORARY KEYS & PURGE ALL OTHERS   ');
        console.log('=======================================================');
        const now = Date.now();
        const expiresAtIso = new Date(now + DURATION_HOURS * 3600 * 1000).toISOString();
        const nowIso = new Date(now).toISOString();

        console.log(`Duration: ${DURATION_HOURS} hours (1 day)`);
        console.log(`New Expiration (24h from now): ${expiresAtIso}`);

        console.log('\n[1/5] Initializing local database...');
        await db.initDatabase();

        let defaultProduct = await db.queryOne('SELECT id FROM products WHERE name = ?', ['Z E X O']) ||
                             await db.queryOne('SELECT id FROM products WHERE name = ?', ['Zexora']) ||
                             await db.queryOne('SELECT id FROM products LIMIT 1');
        const prodId = defaultProduct ? defaultProduct.id : 1;

        console.log('\n[2/5] Updating the 6 preserved keys to 1-day temporary validity...');
        for (const item of V143_ACTIVE_KEYS) {
            const kUpper = item.key.trim().toUpperCase();
            const khash = hashKey(kUpper);
            const last4 = getKeyLast4(kUpper);

            await db.query('DELETE FROM deleted_keys WHERE key_hash = ? OR key_display = ?', [khash, kUpper]);

            const existing = await db.queryOne('SELECT id, key_display FROM activation_keys WHERE key_hash = ?', [khash]);
            if (!existing) {
                await db.query(`
                    INSERT INTO activation_keys (
                        key_hash, key_last4, key_display, product_id, status, duration_hours,
                        created_at, activated_at, expires_at, max_devices, customer_name, notes
                    ) VALUES (?, ?, ?, ?, 'ACTIVE', ?, ?, ?, ?, 5, ?, ?)
                `, [khash, last4, kUpper, prodId, DURATION_HOURS, nowIso, nowIso, expiresAtIso, item.customer, item.notes]);
                console.log(`  [CREATED 1-DAY] ${kUpper} (${item.customer})`);
            } else {
                await db.query(`
                    UPDATE activation_keys
                    SET status = 'ACTIVE',
                        duration_hours = ?,
                        activated_at = COALESCE(activated_at, ?),
                        expires_at = ?,
                        max_devices = 5,
                        customer_name = ?,
                        notes = ?
                    WHERE id = ?
                `, [DURATION_HOURS, nowIso, expiresAtIso, item.customer, item.notes, existing.id]);
                console.log(`  [UPDATED 1-DAY] ${kUpper} (${item.customer})`);
            }
        }

        // Clean up synthetic test devices from local DB, preserving real devices
        await db.query(`
            DELETE FROM activations 
            WHERE device_id IN (
                SELECT id FROM devices 
                WHERE device_identifier = 'VALIDATION-VERIFY-001' 
                   OR device_identifier LIKE 'TEST-%'
                   OR device_identifier LIKE 'LIVE-TEST-%'
                   OR device_identifier = 'UNASSOCIATED-DEV-999'
            )
        `);

        // Register Xiaomi phone activation locally on MADARA FF key
        const madaraKeyRecord = await db.queryOne('SELECT id FROM activation_keys WHERE key_display = ?', ['MADARA-FF-5HAQ-MB8E-VCGH-WVMC']);
        if (madaraKeyRecord) {
            const xiaomiHwid = 'a4d730c3f070a8df87aceba36db6dff91f8462cce8346da70272d32a0fd5ecd3';
            const customer = await db.getOrCreateCustomer('MADARA FF');
            const device = await db.getOrCreateDevice(customer.id, xiaomiHwid, 'Xiaomi 2412DPC0AI', 'com.example.rootoptimizer', 'Android');
            const existingAct = await db.findActivation(madaraKeyRecord.id, device.id);
            if (!existingAct) {
                await db.recordActivation({
                    keyId: madaraKeyRecord.id,
                    customerId: customer.id,
                    deviceId: device.id,
                    expiresAt: expiresAtIso,
                    sessionToken: '31c6ce2f6e1aea6205e8cf18edf52a591755e92d256e012be03ea1d750d869c3'
                });
                console.log('  [PRESERVED DEVICE] Xiaomi 2412DPC0AI registered on MADARA FF key.');
            } else {
                await db.query('UPDATE activations SET expires_at = ?, status = ? WHERE id = ?', [expiresAtIso, 'ACTIVE', existingAct.id]);
                console.log('  [UPDATED DEVICE] Xiaomi 2412DPC0AI expiration updated.');
            }
        }

        console.log('\n[3/5] Permanently deleting all other keys from local database...');
        const allKeys = await db.getAllKeys({ limit: 500 });
        let localPurged = 0;
        for (const k of allKeys) {
            const kUpper = (k.key_display || '').trim().toUpperCase();
            if (!KEEP_SET.has(kUpper)) {
                await db.deleteKey(k.id, 'admin', 'Permanent administrative purge - non-preserved key');
                localPurged++;
                console.log(`  [PURGED LOCAL] ${kUpper} (ID: ${k.id})`);
            }
        }
        console.log(`Local purge complete: ${localPurged} non-preserved keys erased.`);

        console.log('\n[4/5] Regenerating seed-keys.json with 1-day temporary keys...');
        const exported = await db.exportSeedKeys();
        const seedPath = path.join(__dirname, '..', 'seed-keys.json');
        fs.writeFileSync(seedPath, JSON.stringify(exported, null, 2), 'utf8');
        console.log(`Saved ${exported.length} keys into seed-keys.json with 1-day duration.`);

        const delRows = await db.query('SELECT key_hash, key_display, deleted_by, reason, deleted_at FROM deleted_keys');
        const delPath = path.join(__dirname, '..', 'deleted-keys.json');
        fs.writeFileSync(delPath, JSON.stringify(delRows.rows, null, 2), 'utf8');
        console.log(`Saved ${delRows.rows.length} erased keys into deleted-keys.json.`);

        console.log('\n[5/5] Propagating 1-day temporary keys and purge to Render Cloud...');
        const cloudUrl = config.cloudServerUrl;
        const adminUser = config.adminUsername;
        const adminPass = config.adminPassword;

        const loginRes = await fetch(`${cloudUrl}/api/auth/admin/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: adminUser, password: adminPass })
        });
        const loginData = await loginRes.json();
        if (!loginData.success || !loginData.token) {
            throw new Error(`Failed to login to cloud: ${loginData.message || 'unknown error'}`);
        }
        const cloudToken = loginData.token;

        // Fetch remote keys from Cloud
        const cloudKeysRes = await fetch(`${cloudUrl}/api/keys?limit=500`, {
            headers: { 'Authorization': `Bearer ${cloudToken}` }
        });
        const cloudKeysData = await cloudKeysRes.json();

        if (cloudKeysData.success && Array.isArray(cloudKeysData.keys)) {
            for (const ck of cloudKeysData.keys) {
                const ckDisplay = (ck.key_display || '').trim().toUpperCase();
                if (!KEEP_SET.has(ckDisplay)) {
                    try {
                        const delRes = await fetch(`${cloudUrl}/api/keys/${ck.id}`, {
                            method: 'DELETE',
                            headers: { 'Authorization': `Bearer ${cloudToken}` }
                        });
                        const delData = await delRes.json();
                        if (delData.success) {
                            console.log(`  [PURGED CLOUD] ${ckDisplay} (ID: ${ck.id})`);
                        }
                    } catch (delErr) {
                        console.warn(`  [CLOUD PURGE WARN] ${ckDisplay}: ${delErr.message}`);
                    }
                } else {
                    // Update the preserved key on Cloud to duration: 24, expires_at: expiresAtIso
                    try {
                        const patchRes = await fetch(`${cloudUrl}/api/keys/${ck.id}`, {
                            method: 'PATCH',
                            headers: {
                                'Content-Type': 'application/json',
                                'Authorization': `Bearer ${cloudToken}`
                            },
                            body: JSON.stringify({
                                duration_hours: DURATION_HOURS,
                                expires_at: expiresAtIso,
                                status: 'ACTIVE'
                            })
                        });
                        const patchData = await patchRes.json();
                        if (patchData.success) {
                            console.log(`  [CLOUD UPDATED 24h] ${ckDisplay} -> Expires: ${expiresAtIso}`);
                        }
                    } catch (patchErr) {
                        console.warn(`  [CLOUD PATCH WARN] ${ckDisplay}: ${patchErr.message}`);
                    }
                }
            }
        }

        // Push the updated 1-day keys to Render Cloud
        console.log('\nSyncing 1-day keys to Render Cloud...');
        const pushRes = await fetch(`${cloudUrl}/api/keys/import`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${cloudToken}`
            },
            body: JSON.stringify({ keys: exported })
        });
        const pushData = await pushRes.json();
        console.log(`Cloud Import result: ${pushData.message} (Count: ${pushData.count})`);

        // Verify final state on Cloud
        const verifyRes = await fetch(`${cloudUrl}/api/keys?limit=100`, {
            headers: { 'Authorization': `Bearer ${cloudToken}` }
        });
        const verifyData = await verifyRes.json();
        console.log('\n=======================================================');
        console.log('FINAL RESULTS:');
        console.log(`  Local Active Keys:  ${exported.length}`);
        console.log(`  Local Erased Keys:  ${delRows.rows.length}`);
        console.log(`  Cloud Active Keys:  ${verifyData.keys ? verifyData.keys.length : 0}`);
        if (verifyData.keys) {
            for (const k of verifyData.keys) {
                console.log(`    - ${k.key_display} | ${k.customer_name || 'N/A'} | Status: ${k.status} | Duration: ${k.duration_hours}h | Expires: ${k.expires_at}`);
            }
        }
        console.log('=======================================================');

        await db.closeDatabase();
        process.exit(0);
    } catch (err) {
        console.error('[FATAL ERROR]', err);
        process.exit(1);
    }
})();
