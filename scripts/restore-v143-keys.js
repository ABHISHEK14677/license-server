#!/usr/bin/env node
const fs = require('node:fs');
const path = require('node:path');
const db = require('../db');
const { hashKey, getKeyLast4 } = require('../auth');
const { config } = require('../config');

const V143_ACTIVE_KEYS = [
    { key: 'MADARA-FF-5HAQ-MB8E-VCGH-WVMC', customer: 'MADARA FF', notes: 'v1.4.3 Active Key' },
    { key: 'MADARA-FF-B2K5-UV4X-YTRN-F8M8', customer: 'TRIAL', notes: 'v1.4.3 Active Key' },
    { key: 'MADARA-FF-JFFL-JCHQ-D3AX-4MLC', customer: 'MUKESH', notes: 'v1.4.3 Active Key' },
    { key: 'MADARA-FF-53D5-EFGY-6ST5-RMB6', customer: 'KAVISH', notes: 'v1.4.3 Active Key' },
    { key: 'MADARA-FF-PSVB-9C3H-FY6W-KEXZ', customer: 'DHARSHAN', notes: 'v1.4.3 Active Key' },
    { key: 'MADARA-FF-4W2B-M4KF-T9QS-KEV2', customer: 'SRINIVASAN', notes: 'v1.4.3 Active Key' }
];

const KEEP_SET = new Set(V143_ACTIVE_KEYS.map(k => k.key.trim().toUpperCase()));

(async () => {
    try {
        console.log('=======================================================');
        console.log('   RESTORE v1.4.3 ACTIVE KEYS & PERMANENT KEY PURGE   ');
        console.log('=======================================================');
        console.log(`Active v1.4.3 keys to restore: ${V143_ACTIVE_KEYS.length}`);
        for (const k of V143_ACTIVE_KEYS) {
            console.log(`  [TARGET] ${k.key} (${k.customer})`);
        }

        console.log('\n[1/5] Initializing local database...');
        await db.initDatabase();

        // Step 1: Ensure default product exists
        let defaultProduct = await db.queryOne('SELECT id FROM products WHERE name = ?', ['Z E X O']) ||
                             await db.queryOne('SELECT id FROM products WHERE name = ?', ['Zexora']) ||
                             await db.queryOne('SELECT id FROM products LIMIT 1');
        const prodId = defaultProduct ? defaultProduct.id : 1;

        // Step 2: Restore the 6 keys as ACTIVE & PERMANENT
        console.log('\n[2/5] Creating / Restoring the 6 active v1.4.3 keys in local database...');
        for (const item of V143_ACTIVE_KEYS) {
            const kUpper = item.key.trim().toUpperCase();
            const khash = hashKey(kUpper);
            const last4 = getKeyLast4(kUpper);

            // Remove from deleted_keys blacklist if previously blacklisted
            await db.query('DELETE FROM deleted_keys WHERE key_hash = ? OR key_display = ?', [khash, kUpper]);

            const existing = await db.queryOne('SELECT id, key_display FROM activation_keys WHERE key_hash = ?', [khash]);
            if (!existing) {
                await db.query(`
                    INSERT INTO activation_keys (
                        key_hash, key_last4, key_display, product_id, status, duration_hours,
                        created_at, activated_at, expires_at, max_devices, customer_name, notes
                    ) VALUES (?, ?, ?, ?, 'ACTIVE', -1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, NULL, 5, ?, ?)
                `, [khash, last4, kUpper, prodId, item.customer, item.notes]);
                console.log(`  [CREATED ACTIVE] ${kUpper} -> Customer: ${item.customer}`);
            } else {
                await db.query(`
                    UPDATE activation_keys
                    SET status = 'ACTIVE',
                        duration_hours = -1,
                        expires_at = NULL,
                        max_devices = 5,
                        customer_name = ?,
                        notes = ?
                    WHERE id = ?
                `, [item.customer, item.notes, existing.id]);
                console.log(`  [UPDATED ACTIVE] ${kUpper} -> Customer: ${item.customer}`);
            }
        }

        // Step 3: Delete all other keys from local database permanently
        console.log('\n[3/5] Permanently deleting all other keys from local database...');
        const allKeys = await db.getAllKeys({ limit: 500 });
        let localPurged = 0;
        for (const k of allKeys) {
            const kUpper = (k.key_display || '').trim().toUpperCase();
            if (!KEEP_SET.has(kUpper)) {
                await db.deleteKey(k.id, 'admin', 'Permanent administrative purge - non-v1.4.3 key');
                localPurged++;
                console.log(`  [PURGED LOCAL] ${kUpper} (ID: ${k.id})`);
            }
        }
        console.log(`Local purge complete: ${localPurged} non-v1.4.3 keys permanently erased.`);

        // Step 4: Export clean seed-keys.json with only the 6 active keys
        console.log('\n[4/5] Regenerating seed-keys.json with active keys only...');
        const exported = await db.exportSeedKeys();
        const seedPath = path.join(__dirname, '..', 'seed-keys.json');
        fs.writeFileSync(seedPath, JSON.stringify(exported, null, 2), 'utf8');
        console.log(`Saved ${exported.length} active keys into seed-keys.json.`);

        // Export all deleted keys to deleted-keys.json
        const delRows = await db.query('SELECT key_hash, key_display, deleted_by, reason, deleted_at FROM deleted_keys');
        const delPath = path.join(__dirname, '..', 'deleted-keys.json');
        fs.writeFileSync(delPath, JSON.stringify(delRows.rows, null, 2), 'utf8');
        console.log(`Saved ${delRows.rows.length} erased keys into deleted-keys.json.`);

        // Step 5: Synchronize with Render Cloud
        console.log('\n[5/5] Propagating active keys and purge to Render Cloud...');
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

        let cloudPurged = 0;
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
                            cloudPurged++;
                            console.log(`  [PURGED CLOUD] ${ckDisplay} (ID: ${ck.id})`);
                        }
                    } catch (delErr) {
                        console.warn(`  [CLOUD PURGE WARN] ${ckDisplay}: ${delErr.message}`);
                    }
                }
            }
        }

        // Push the 6 active keys to Render Cloud
        console.log('\nPushing 6 active v1.4.3 keys to Render Cloud...');
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
        console.log(`FINAL RESULTS:`);
        console.log(`  Local Active Keys:  ${exported.length}`);
        console.log(`  Local Erased Keys:  ${delRows.rows.length}`);
        console.log(`  Cloud Active Keys:  ${verifyData.keys ? verifyData.keys.length : 0}`);
        if (verifyData.keys) {
            for (const k of verifyData.keys) {
                console.log(`    - ${k.key_display} | ${k.customer_name || 'N/A'} | Status: ${k.status}`);
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
