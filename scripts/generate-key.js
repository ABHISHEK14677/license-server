#!/usr/bin/env node
const { generateLicenseKey } = require('../auth');
const db = require('../db');
const { config } = require('../config');

let durationHours = 720; // default 30d
let maxActivations = 1;
let notes = `Key generated on ${new Date().toISOString()}`;
let prefix = 'MADARA-FF';

const args = process.argv.slice(2);
for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--1h') {
        durationHours = 1;
    } else if (arg === '--1d') {
        durationHours = 24;
    } else if (arg === '--7d') {
        durationHours = 168;
    } else if (arg === '--30d') {
        durationHours = 720;
    } else if (arg === '--lifetime') {
        durationHours = -1;
    } else if (arg === '--days' || arg === '-d') {
        const d = parseInt(args[++i], 10);
        durationHours = d === -1 ? -1 : d * 24;
    } else if (arg === '--hours' || arg === '-h') {
        durationHours = parseInt(args[++i], 10);
    } else if (arg === '--max' || arg === '--devices' || arg === '-m') {
        maxActivations = parseInt(args[++i], 10);
    } else if (arg === '--notes' || arg === '-n') {
        notes = args[++i];
    } else if (arg === '--prefix' || arg === '-p') {
        prefix = args[++i];
    } else if (arg === '--product') {
        i++; // skip product name argument
    } else if (!arg.startsWith('-')) {
        if (i === 0) {
            const val = arg.toLowerCase();
            if (val === '1h') durationHours = 1;
            else if (val === '1d') durationHours = 24;
            else if (val === '7d') durationHours = 168;
            else if (val === '30d') durationHours = 720;
            else if (val === 'lifetime') durationHours = -1;
            else if (!isNaN(parseInt(arg, 10))) {
                durationHours = parseInt(arg, 10);
            }
        }
        else if (i === 1 && !isNaN(parseInt(arg, 10))) maxActivations = parseInt(arg, 10);
        else if (i === 2) notes = arg;
        else if (i === 3) prefix = arg;
    }
}

async function main() {
    try {
        await db.initDatabase();
        const key = generateLicenseKey(prefix);
        await db.createLicenseKey({
            licenseKey: key,
            durationHours,
            maxActivations,
            notes,
            status: 'UNUSED'
        });

        let cloudStatus = 'Local Database (Offline / Standalone)';
        if (!config.isRender && config.autoSyncCloud) {
            try {
                const cloudUrl = config.cloudServerUrl;
                const adminUser = config.adminUsername;
                const adminPass = config.adminPassword;
                const loginRes = await fetch(`${cloudUrl}/api/auth/admin/login`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: adminUser, password: adminPass })
                });
                const loginData = await loginRes.json();
                if (loginData.success && loginData.token) {
                    await fetch(`${cloudUrl}/api/keys/import`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${loginData.token}`
                        },
                        body: JSON.stringify({
                            keys: [{
                                key,
                                duration_hours: durationHours,
                                max_devices: maxActivations,
                                notes
                            }]
                        })
                    });
                    cloudStatus = '✓ Synced to Render Cloud (Worldwide Ready)';
                } else {
                    cloudStatus = `⚠ Cloud response: ${loginData.message || 'Login failed'}`;
                }
            } catch (cloudErr) {
                cloudStatus = `⚠ Cloud sync deferred (${cloudErr.message})`;
            }
        }

        const durationDisplay = durationHours === -1 
            ? 'Lifetime' 
            : (durationHours >= 24 ? `${durationHours / 24} Days` : `${durationHours} Hours`);

        console.log(`=======================================================`);
        console.log(`                NEW Z E X O LICENSE KEY                `);
        console.log(`              Developed by MADARA FF                   `);
        console.log(`=======================================================`);
        console.log(`License Key:     ${key}`);
        console.log(`Duration:        ${durationDisplay}`);
        console.log(`Active Timer:    Starts upon user activation`);
        console.log(`Status:          UNUSED (Timer starts on activation)`);
        console.log(`Max Devices:     ${maxActivations}`);
        console.log(`Cloud Status:    ${cloudStatus}`);
        console.log(`Notes:           ${notes}`);
        console.log(`Copyright:       © Developed by MADARA FF`);
        console.log(`=======================================================`);
        process.exit(0);
    } catch (err) {
        console.error(`[ERROR] Failed to generate license:`, err.message);
        process.exit(1);
    }
}

main();
