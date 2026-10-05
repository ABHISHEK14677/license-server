#!/usr/bin/env node
const { generateLicenseKey } = require('../auth');
const { createLicense } = require('../db');

const args = process.argv.slice(2);
const durationDays = args[0] !== undefined ? parseInt(args[0], 10) : 30;
const maxActivations = args[1] !== undefined ? parseInt(args[1], 10) : 1;
const notes = args[2] || `Key generated on ${new Date().toISOString()}`;

try {
    const key = generateLicenseKey();
    createLicense({
        licenseKey: key,
        durationDays,
        maxActivations,
        notes,
        status: 'ACTIVE'
    });
    console.log(`=======================================================`);
    console.log(`           NEW ROOTOPTIMIZER LICENSE KEY               `);
    console.log(`=======================================================`);
    console.log(`License Key:     ${key}`);
    console.log(`Duration:        ${durationDays === -1 ? 'Lifetime' : durationDays + ' Days'}`);
    console.log(`Max Devices:     ${maxActivations}`);
    console.log(`Notes:           ${notes}`);
    console.log(`=======================================================`);
} catch (err) {
    console.error(`[ERROR] Failed to generate license:`, err.message);
    process.exit(1);
}
