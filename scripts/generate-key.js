#!/usr/bin/env node
const { generateLicenseKey } = require('../auth');
const { createLicense } = require('../db');

let durationDays = 30;
let maxActivations = 1;
let notes = `Key generated on ${new Date().toISOString()}`;
let prefix = 'MADARA-FF';

const args = process.argv.slice(2);
for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--permanent' || arg === '-P') {
        durationDays = -1;
    } else if (arg === '--days' || arg === '-d') {
        durationDays = parseInt(args[++i], 10);
    } else if (arg === '--hours' || arg === '-h') {
        const hours = parseInt(args[++i], 10);
        durationDays = hours === -1 ? -1 : Math.max(1, Math.ceil(hours / 24));
    } else if (arg === '--max' || arg === '--devices' || arg === '-m') {
        maxActivations = parseInt(args[++i], 10);
    } else if (arg === '--notes' || arg === '-n') {
        notes = args[++i];
    } else if (arg === '--prefix' || arg === '-p') {
        prefix = args[++i];
    } else if (arg === '--product') {
        i++; // skip product name argument
    } else if (!arg.startsWith('-')) {
        // Positional fallback: durationDays, maxActivations, notes, prefix
        if (i === 0 && !isNaN(parseInt(arg, 10))) durationDays = parseInt(arg, 10);
        else if (i === 1 && !isNaN(parseInt(arg, 10))) maxActivations = parseInt(arg, 10);
        else if (i === 2) notes = arg;
        else if (i === 3) prefix = arg;
    }
}

async function main() {
    try {
        const key = generateLicenseKey(prefix);
        await createLicense({
            licenseKey: key,
            durationDays,
            maxActivations,
            notes,
            status: 'UNUSED'
        });



        // 2. Sync to Render cloud server online
        let cloudStatus = '✓ Synced to Render Cloud (Worldwide Ready)';
        try {
            const cloudUrl = process.env.CLOUD_SERVER_URL || 'https://optimizer-stzd.onrender.com';
            const adminUser = process.env.ADMIN_USERNAME || 'MADARA-FF';
            const adminPass = process.env.ADMIN_PASSWORD || 'ABHISHEK!';
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
                            duration_hours: durationDays === -1 ? -1 : durationDays * 24,
                            max_devices: maxActivations,
                            notes
                        }]
                    })
                });
            } else {
                cloudStatus = `⚠ Cloud response: ${loginData.message || 'Login failed'}`;
            }
        } catch (cloudErr) {
            cloudStatus = `⚠ Cloud sync deferred (${cloudErr.message})`;
        }

        console.log(`=======================================================`);
        console.log(`              NEW OPTIMIZER LICENSE KEY                `);
        console.log(`              Developed by MADARA FF                   `);
        console.log(`=======================================================`);
        console.log(`License Key:     ${key}`);
        console.log(`Duration:        ${durationDays === -1 ? 'Lifetime' : durationDays + ' Days'}`);
        console.log(`Active Timer:    Starts upon user activation`);
        console.log(`Status:          UNUSED (Timer starts on activation)`);
        console.log(`Max Devices:     ${maxActivations}`);
        console.log(`Cloud Access:    ${cloudStatus}`);
        console.log(`Notes:           ${notes}`);
        console.log(`Copyright:       © Developed by MADARA FF`);
        console.log(`=======================================================`);
    } catch (err) {
        console.error(`[ERROR] Failed to generate license:`, err.message);
        process.exit(1);
    }
}

main();
