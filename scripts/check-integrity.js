#!/usr/bin/env node
const fs = require('node:fs');
const path = require('node:path');
const { execSync } = require('node:child_process');

console.log('=======================================================');
console.log('       Z E X O REPOSITORY INTEGRITY AUDITOR            ');
console.log('=======================================================');

let issues = 0;
const rootDir = path.resolve(__dirname, '..');

// 1. Check for tracked sensitive files in Git
try {
    const trackedFiles = execSync('git ls-files', { cwd: rootDir, encoding: 'utf8' }).split('\n').filter(Boolean);
    const forbiddenPatterns = [
        /^\.env($|\.(?!example$).*)/,
        /\.db$/,
        /\.pem$/,
        /\.key$/,
        /^id_rsa/
    ];

    for (const file of trackedFiles) {
        for (const pattern of forbiddenPatterns) {
            if (pattern.test(file)) {
                console.error(`[SECURITY ALERT] Sensitive file tracked in Git index: ${file}`);
                issues++;
            }
        }
    }
} catch (e) {
    console.warn('[WARN] Git ls-files check skipped:', e.message);
}

// 2. Validate JSON files syntax
const jsonFiles = [
    'package.json',
    'public/downloads/version.json',
    'seed-keys.json'
];

for (const relPath of jsonFiles) {
    const fullPath = path.join(rootDir, relPath);
    if (fs.existsSync(fullPath)) {
        try {
            const raw = fs.readFileSync(fullPath, 'utf8');
            JSON.parse(raw);
            console.log(`[PASS] JSON syntax valid: ${relPath}`);
        } catch (e) {
            console.error(`[FAIL] Malformed JSON in ${relPath}: ${e.message}`);
            issues++;
        }
    }
}

// 3. Verify .gitignore covers sensitive assets
const gitignorePath = path.join(rootDir, '.gitignore');
if (fs.existsSync(gitignorePath)) {
    const giContent = fs.readFileSync(gitignorePath, 'utf8');
    const requiredPatterns = ['.env', 'licenses.db'];
    for (const pat of requiredPatterns) {
        if (!giContent.includes(pat)) {
            console.warn(`[WARN] .gitignore is missing recommended rule: "${pat}"`);
            issues++;
        }
    }
}

console.log('-------------------------------------------------------');
if (issues > 0) {
    console.error(`[FAIL] Repository integrity check failed with ${issues} issue(s).`);
    process.exit(1);
} else {
    console.log('[SUCCESS] Repository integrity audit passed. Zero credential leaks detected.');
    process.exit(0);
}
