const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const fs = require('node:fs');
const {
    resolveConfig,
    validateConfig,
    getSanitizedConfig,
    safeTimingCompare,
    parseEnvFile
} = require('../config');

test('Config: Robust parsing of .env formatting (quotes, comments, whitespace)', (t) => {
    const tempEnvPath = path.join(__dirname, 'temp_test.env');
    fs.writeFileSync(tempEnvPath, [
        '# Sample comment line',
        'EXPORTED_VAR="quoted_value"',
        'SINGLE_QUOTED=\'single_value\'',
        'UNQUOTED=raw_value # inline comment',
        'PORT=8080\r\n',
        'export KEY_WITH_EXPORT=exported'
    ].join('\n'));

    try {
        const parsed = parseEnvFile(tempEnvPath);
        assert.strictEqual(parsed.EXPORTED_VAR, 'quoted_value');
        assert.strictEqual(parsed.SINGLE_QUOTED, 'single_value');
        assert.strictEqual(parsed.UNQUOTED, 'raw_value');
        assert.strictEqual(parsed.PORT, '8080');
        assert.strictEqual(parsed.KEY_WITH_EXPORT, 'exported');
    } finally {
        if (fs.existsSync(tempEnvPath)) fs.unlinkSync(tempEnvPath);
    }
});

test('Config: Development configuration provides safe defaults', () => {
    const devConfig = resolveConfig({ NODE_ENV: 'development' });
    assert.strictEqual(devConfig.isProduction, false);
    assert.strictEqual(devConfig.adminUsername, 'MADARA-FF');
    assert.ok(devConfig.adminSecret.length > 0);

    const validation = validateConfig(devConfig);
    assert.strictEqual(validation.valid, true);
    assert.ok(validation.warnings.length > 0); // warns about dev defaults
});

test('Config: Production configuration strictly requires dedicated secrets', () => {
    // Missing secrets in production
    const prodConfigMissing = resolveConfig({ NODE_ENV: 'production' });
    const validationMissing = validateConfig(prodConfigMissing);
    assert.strictEqual(validationMissing.valid, false);
    assert.ok(validationMissing.errors.some(e => e.includes('ADMIN_SECRET')));
    assert.ok(validationMissing.errors.some(e => e.includes('ADMIN_PASSWORD')));

    // Insecure placeholder defaults produce warnings (not fatal errors) so the
    // server can still start on Render when the user hasn't rotated credentials yet.
    const prodConfigDefaults = resolveConfig({
        NODE_ENV: 'production',
        ADMIN_SECRET: 'rootoptimizer_secret_2026',
        ADMIN_PASSWORD: 'ABHISHEK!'
    });
    const validationDefaults = validateConfig(prodConfigDefaults);
    assert.strictEqual(validationDefaults.valid, true);
    assert.ok(validationDefaults.warnings.some(w => w.includes('ADMIN_SECRET') && w.includes('known default')));
    assert.ok(validationDefaults.warnings.some(w => w.includes('ADMIN_PASSWORD') && w.includes('known default')));

    // Valid production configuration
    const prodConfigValid = resolveConfig({
        NODE_ENV: 'production',
        ADMIN_SECRET: 'StrongProductionSecret_2026_XYZ_987',
        ADMIN_PASSWORD: 'SuperStrongPassword2026!',
        DATABASE_URL: 'postgres://user:pass@localhost:5432/zexo_db'
    });
    const validationValid = validateConfig(prodConfigValid);
    assert.strictEqual(validationValid.valid, true);
    assert.strictEqual(validationValid.errors.length, 0);
});

test('Config: getSanitizedConfig strictly masks secret values', () => {
    const rawSecret = 'MySuperSensitiveProductionSecret';
    const rawPassword = 'MySecretPassword123';
    const cfg = resolveConfig({
        ADMIN_SECRET: rawSecret,
        ADMIN_PASSWORD: rawPassword
    });

    const sanitized = getSanitizedConfig(cfg);
    assert.strictEqual(sanitized.adminSecretSet, true);
    assert.strictEqual(sanitized.adminPasswordSet, true);

    // Verify raw secrets are nowhere in the output
    const jsonStr = JSON.stringify(sanitized);
    assert.strictEqual(jsonStr.includes(rawSecret), false);
    assert.strictEqual(jsonStr.includes(rawPassword), false);
    assert.ok(sanitized.adminSecretMasked.startsWith('[REDACTED'));
});

test('Config: safeTimingCompare prevents timing side-channels and validates correctly', () => {
    assert.strictEqual(safeTimingCompare('secret123', 'secret123'), true);
    assert.strictEqual(safeTimingCompare('secret123', 'secret124'), false);
    assert.strictEqual(safeTimingCompare('short', 'longer_secret'), false);
    assert.strictEqual(safeTimingCompare(null, 'secret123'), false);
    assert.strictEqual(safeTimingCompare(undefined, 'secret123'), false);
});
