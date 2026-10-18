#!/usr/bin/env node
const { resolveConfig, validateConfig, getSanitizedConfig } = require('../config');

const args = process.argv.slice(2);
const isStrict = args.includes('--strict');
const isProd = args.includes('--production') || process.env.NODE_ENV === 'production';

console.log('=======================================================');
console.log('       Z E X O CONFIGURATION VALIDATION ENGINE         ');
console.log('=======================================================');

const cfg = resolveConfig();
const validation = validateConfig(cfg, { isProduction: isProd, strict: isStrict });
const sanitized = getSanitizedConfig(cfg);

console.log(`Environment:      ${sanitized.environment}`);
console.log(`Platform Target:  ${sanitized.isRender ? 'Render Cloud' : 'Local / Standalone'}`);
console.log(`Database Adapter: ${sanitized.databaseType}`);
console.log(`Port:             ${sanitized.port}`);
console.log(`Admin User:       ${sanitized.adminUsername}`);
console.log(`Admin Secret:     ${sanitized.adminSecretSet ? 'Set ' + sanitized.adminSecretMasked : 'MISSING'}`);
console.log(`Admin Password:   ${sanitized.adminPasswordSet ? 'Set ' + sanitized.adminPasswordMasked : 'MISSING'}`);
console.log(`App Release:      v${sanitized.appLatestVersion} (Code ${sanitized.appVersionCode})`);
console.log('-------------------------------------------------------');

if (validation.warnings.length > 0) {
    console.log('WARNINGS:');
    for (const w of validation.warnings) {
        console.warn(` [!] ${w}`);
    }
}

if (!validation.valid) {
    console.error('\nFAILED: Configuration validation errors detected:');
    for (const e of validation.errors) {
        console.error(` [X] ${e}`);
    }
    console.error('\nDeployment or startup aborted to protect application reliability.');
    process.exit(1);
} else {
    console.log('\n[SUCCESS] Configuration verified clean and secure.');
    process.exit(0);
}
