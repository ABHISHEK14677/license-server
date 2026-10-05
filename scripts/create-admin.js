#!/usr/bin/env node
const { createAdmin, getAdminByUsername } = require('../db');

const args = process.argv.slice(2);
if (args.length < 2) {
    console.error('Usage: node scripts/create-admin.js <username> <password>');
    process.exit(1);
}

const [username, password] = args;

try {
    const existing = getAdminByUsername(username);
    if (existing) {
        console.error(`Error: Admin username "${username}" already exists.`);
        process.exit(1);
    }

    createAdmin(username, password);
    console.log(`[SUCCESS] Admin user "${username}" created successfully!`);
} catch (err) {
    console.error(`[ERROR] Failed to create admin:`, err.message);
    process.exit(1);
}
