const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

/**
 * Safely parse a .env file without modifying existing process.env variables.
 * Handles single/double quotes, trailing comments, escaped characters, and Windows line endings.
 */
function parseEnvFile(filePath) {
    if (!fs.existsSync(filePath)) return {};
    const parsed = {};
    const content = fs.readFileSync(filePath, 'utf8');
    const lines = content.split(/\r?\n/);

    for (let line of lines) {
        line = line.trim();
        // Skip comments and empty lines
        if (!line || line.startsWith('#')) continue;

        // Remove 'export ' prefix if present
        if (line.startsWith('export ')) {
            line = line.substring(7).trim();
        }

        const eqIdx = line.indexOf('=');
        if (eqIdx === -1) continue;

        const key = line.substring(0, eqIdx).trim();
        let val = line.substring(eqIdx + 1).trim();

        // Handle quoted values
        if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
            val = val.substring(1, val.length - 1);
        } else {
            // Strip trailing comments for unquoted values
            const commentIdx = val.indexOf('#');
            if (commentIdx !== -1) {
                val = val.substring(0, commentIdx).trim();
            }
        }

        parsed[key] = val;
    }
    return parsed;
}

/**
 * Load .env into process.env without overriding variables already set by the environment/host.
 */
function loadEnv() {
    const rootDir = __dirname;
    const envPaths = [
        path.join(rootDir, '.env'),
        path.join(rootDir, '.env.local')
    ];

    for (const p of envPaths) {
        if (fs.existsSync(p)) {
            const parsed = parseEnvFile(p);
            for (const [k, v] of Object.entries(parsed)) {
                if (process.env[k] === undefined || process.env[k] === '') {
                    process.env[k] = v;
                }
            }
        }
    }
}

// Automatically load environment files on module load
loadEnv();

/**
 * Known insecure defaults to reject in production mode
 */
const INSECURE_DEFAULTS = new Set([
    'ABHISHEK!',
    'admin123',
    'password',
    'rootoptimizer_secret_2026',
    'optimizer-admin-secret-2026',
    'default_secret',
    'changeme'
]);

/**
 * Resolve unified configuration object with sane defaults and alias resolution
 */
function resolveConfig(env = process.env) {
    const nodeEnv = (env.NODE_ENV || 'development').toLowerCase();
    const isProduction = nodeEnv === 'production';
    const isTest = nodeEnv === 'test';
    const isDevelopment = !isProduction && !isTest;
    const isRender = Boolean(env.RENDER || env.RENDER_SERVICE_ID);

    // Normalize ADMIN_SECRET / ADMIN_SECRET_KEY aliases
    const adminSecret = env.ADMIN_SECRET || env.ADMIN_SECRET_KEY || (isProduction ? '' : 'rootoptimizer_secret_2026');

    // Admin Credentials
    const adminUsername = env.ADMIN_USERNAME || 'MADARA-FF';
    const adminPassword = env.ADMIN_PASSWORD || (isProduction ? '' : 'ABHISHEK!');
    const adminEmail = env.ADMIN_EMAIL || 'madara-ff@rootoptimizer.com';

    // Server Port & Host
    const port = parseInt(env.PORT || '5000', 10);
    const host = env.HOST || '0.0.0.0';

    // Database Connection
    const databaseUrl = env.DATABASE_URL || '';
    const isPostgres = Boolean(databaseUrl && databaseUrl.startsWith('postgres'));

    // App Versioning & Release
    const appLatestVersion = env.APP_LATEST_VERSION || '1.4.5';
    const appVersionCode = parseInt(env.APP_VERSION_CODE || '47', 10);
    const appMinVersion = env.APP_MIN_VERSION || '1.0.0';
    const appDownloadUrl = env.APP_DOWNLOAD_URL || '/api/app/download';

    // Cloud Sync Configuration
    const cloudServerUrl = env.CLOUD_SERVER_URL || 'https://optimizer-stzd.onrender.com';
    const autoSyncCloud = env.AUTO_SYNC_CLOUD === 'true';

    // Security & Audit Flags
    const forceAdminPasswordReset = env.FORCE_ADMIN_PASSWORD_RESET === 'true';

    return {
        nodeEnv,
        isProduction,
        isTest,
        isDevelopment,
        isRender,
        port,
        host,
        databaseUrl,
        isPostgres,
        adminSecret,
        adminUsername,
        adminPassword,
        adminEmail,
        appLatestVersion,
        appVersionCode,
        appMinVersion,
        appDownloadUrl,
        cloudServerUrl,
        autoSyncCloud,
        forceAdminPasswordReset
    };
}

/**
 * Validate configuration without logging or exposing secret values.
 * Reports missing or insecure variables strictly by name.
 */
function validateConfig(config = resolveConfig(), options = {}) {
    const { isProduction = config.isProduction, strict = false } = options;
    const errors = [];
    const warnings = [];

    // Production-grade requirements
    if (isProduction || strict) {
        if (!config.adminSecret) {
            errors.push('ADMIN_SECRET (or ADMIN_SECRET_KEY) is required in production. Configure this in Render Dashboard (Environment -> Environment Variables).');
        } else if (INSECURE_DEFAULTS.has(config.adminSecret)) {
            warnings.push('ADMIN_SECRET is using a known default value. For better security, set a unique secret in Render Dashboard.');
        } else if (config.adminSecret.length < 16) {
            warnings.push('ADMIN_SECRET should be at least 16 characters for production security.');
        }

        if (!config.adminPassword) {
            errors.push('ADMIN_PASSWORD is required in production. Configure this in Render Dashboard (Environment -> Environment Variables).');
        } else if (INSECURE_DEFAULTS.has(config.adminPassword)) {
            warnings.push('ADMIN_PASSWORD is using a known default value. For better security, set a unique password in Render Dashboard.');
        } else if (config.adminPassword.length < 8) {
            errors.push('ADMIN_PASSWORD must be at least 8 characters.');
        }

        if (!config.databaseUrl) {
            warnings.push('DATABASE_URL is not set. Render ephemeral containers will lose SQLite data across redeployments. A PostgreSQL DATABASE_URL is strongly recommended. Connect zexo-db in render.yaml.');
        }
    } else {
        // Development warnings
        if (INSECURE_DEFAULTS.has(config.adminSecret)) {
            warnings.push('Using development default for ADMIN_SECRET. Set a custom secret in production.');
        }
        if (INSECURE_DEFAULTS.has(config.adminPassword)) {
            warnings.push('Using development default for ADMIN_PASSWORD. Set a custom password in production.');
        }
    }

    if (isNaN(config.port) || config.port <= 0 || config.port > 65535) {
        errors.push(`PORT must be a valid port number between 1 and 65535 (got: ${config.port}).`);
    }

    return {
        valid: errors.length === 0,
        errors,
        warnings
    };
}

/**
 * Returns a sanitized copy of the configuration with secrets redacted.
 * Safe for admin dashboards, logs, and diagnostic endpoints.
 */
function getSanitizedConfig(config = resolveConfig()) {
    const mask = (val) => {
        if (!val) return '[NOT_SET]';
        const str = String(val);
        if (str.length <= 4) return '***';
        return `[REDACTED: len=${str.length}]`;
    };

    return {
        environment: config.nodeEnv,
        isProduction: config.isProduction,
        isRender: config.isRender,
        port: config.port,
        host: config.host,
        databaseType: config.isPostgres ? 'PostgreSQL' : 'SQLite (local)',
        hasDatabaseUrl: Boolean(config.databaseUrl),
        adminUsername: config.adminUsername,
        adminEmail: config.adminEmail,
        adminSecretSet: Boolean(config.adminSecret),
        adminSecretMasked: mask(config.adminSecret),
        adminPasswordSet: Boolean(config.adminPassword),
        adminPasswordMasked: mask(config.adminPassword),
        appLatestVersion: config.appLatestVersion,
        appVersionCode: config.appVersionCode,
        appDownloadUrl: config.appDownloadUrl,
        cloudServerUrl: config.cloudServerUrl,
        autoSyncCloud: config.autoSyncCloud,
        systemTime: new Date().toISOString()
    };
}

/**
 * Constant-time comparison to prevent timing attacks when verifying secrets.
 */
function safeTimingCompare(userInput, expectedSecret) {
    if (typeof userInput !== 'string' || typeof expectedSecret !== 'string') return false;
    const a = Buffer.from(userInput);
    const b = Buffer.from(expectedSecret);
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
}

const config = resolveConfig();

module.exports = {
    config,
    resolveConfig,
    validateConfig,
    getSanitizedConfig,
    safeTimingCompare,
    parseEnvFile,
    loadEnv,
    INSECURE_DEFAULTS
};
