#!/usr/bin/env node
const fs = require('node:fs');
const path = require('node:path');
const db = require('../db');
const { config } = require('../config');

const ACTIVE_KEYS_TO_KEEP = [
    'MADARA-FF-H5YU-Z7N6-GDC4-GCLG', // Xiaomi User - Primary Phone Key
    'MADARA-FF-CKQ8-SMW6-XTKV-GAY2', // Permanent Key (TEST-DEVICE-01)
    'MADARA-FF-W2F3-BXAA-V46Z-FVMQ', // Self-Healed Device User
    'MADARA-FF-RR5P-6MMG-2D8E-U9VJ', // Self-Healed Device User
    'MADARA-FF-8KDJ-95K9-YC85-H833', // Xiaomi 2412DPC0AI (user_0f3968c6)
    'MADARA-FF-4XEP-M48H-2A82-N33T', // Active Key
    'MADARA-FF-Q4EG-WAG4-3FG3-T29Y'  // Xiaomi 2412DPC0AI (session until 2030)
];

const KEEP_SET = new Set(ACTIVE_KEYS_TO_KEEP.map(k => k.trim().toUpperCase()));

(async () => {
    try {
        console.log('=======================================================');
        console.log('   PERMANENT KEY PURGE & ACTIVE KEY RESTORATION       ');
        console.log('=======================================================');
        console.log(`Active keys to retain: ${ACTIVE_KEYS_TO_KEEP.length}`);
        for (const k of ACTIVE_KEYS_TO_KEEP) {
            console.log(`  [KEEP] ${k}`);
        }

        console.log('\n[1/5] Initializing local database...');
        await db.initDatabase();

        // Step 1: Ensure the 7 active keys are properly configured as ACTIVE & PERMANENT
        console.log('\n[2/5] Hardening retention for active keys...');
        for (const keyStr of ACTIVE_KEYS_TO_KEEP) {
            const keyRecord = await db.getKeyByIdOrString(keyStr);
            if (keyRecord) {
                await db.query(`
                    UPDATE activation_keys
                    SET status = 'ACTIVE',
                        duration_hours = -1,
                        expires_at = NULL,
                        max_devices = COALESCE(max_devices, 5)
                    WHERE id = ?
                `, [keyRecord.id]);

                // Ensure active sessions in activations are active
                await db.query(`
                    UPDATE activations
                    SET status = 'ACTIVE',
                        is_active = 1,
                        expires_at = '2030-12-31T23:59:59.000Z'
                    WHERE key_id = ? OR license_id = ?
                `, [keyRecord.id, keyRecord.id]);
                console.log(`  [CONFIRMED ACTIVE] ${keyStr} (ID: ${keyRecord.id})`);
            } else {
                console.warn(`  [WARN] Expected active key not found in DB: ${keyStr}`);
            }
        }

        // Step 2: Delete all other keys from local database permanently
        console.log('\n[3/5] Permanently erasing all non-active keys from local database...');
        const allLocalKeys = await db.getAllKeys({ limit: 500 });
        let localErased = 0;

        for (const k of allLocalKeys) {
            const keyDisplay = (k.key_display || '').trim().toUpperCase();
            if (!KEEP_SET.has(keyDisplay)) {
                await db.deleteKey(k.id, 'admin', 'Permanent administrative purge - non-active key');
                localErased++;
                console.log(`  [PURGED] ${keyDisplay} (ID: ${k.id})`);
            }
        }
        console.log(`Local purge complete: ${localErased} non-active keys permanently erased.`);

        // Step 3: Export clean seed-keys.json with ONLY the 7 active keys
        console.log('\n[4/5] Regenerating seed-keys.json with active keys only...');
        const exported = await db.exportSeedKeys();
        console.log(`Saved ${exported.length} active keys into seed-keys.json.`);

        // Step 4: Synchronize purge to Render Cloud Server
        console.log('\n[5/5] Propagating permanent purge to Render Cloud...');
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

        // Fetch all keys from Cloud
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
                            console.log(`  [CLOUD PURGED] ${ckDisplay} (ID: ${ck.id})`);
                        } else {
                            console.warn(`  [CLOUD PURGE FAILED] ${ckDisplay}: ${delData.message}`);
                        }
                    } catch (delErr) {
                        console.warn(`  [CLOUD PURGE ERROR] ${ckDisplay}: ${delErr.message}`);
                    }
                }
            }
        }

        // Push clean active keys to Cloud to ensure device activations & active status are synchronized
        console.log('\nSynchronizing 7 active keys to Render Cloud...');
        const importRes = await fetch(`${cloudUrl}/api/keys/import`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${cloudToken}`
            },
            body: JSON.stringify({ keys: exported })
        });
        const importData = await importRes.json();
        console.log(`Cloud Import result: ${importData.message}`);

        // Verify final state on Cloud
        const finalCloudRes = await fetch(`${cloudUrl}/api/keys?limit=100`, {
            headers: { 'Authorization': `Bearer ${cloudToken}` }
        });
        const finalCloudData = await finalCloudRes.json();
        console.log('\n=======================================================');
        console.log(`FINAL RESULT:`);
        console.log(`  Local Active Keys:  ${exported.length}`);
        console.log(`  Local Erased Keys:  ${localErased}`);
        console.log(`  Cloud Active Keys:  ${finalCloudData.keys ? finalCloudData.keys.length : 0}`);
        console.log(`  Cloud Erased Keys:  ${cloudPurged}`);
        console.log('=======================================================');

        await db.closeDatabase();
        process.exit(0);
    } catch (err) {
        console.error('[PURGE ERROR]', err);
        process.exit(1);
    }
})();
