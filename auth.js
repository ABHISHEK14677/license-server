const crypto = require('node:crypto');

// Cryptographically secure license key generator
// Format: ADB-XXXX-XXXX-XXXX-XXXX (16 chars, 4 blocks)
const KEY_CHARSET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // Excludes ambiguous chars: 0, O, 1, I

function generateLicenseKey(prefix = 'ADB') {
    const segments = 4;
    const segmentLength = 4;
    const parts = [prefix.toUpperCase()];

    for (let s = 0; s < segments; s++) {
        let segment = '';
        const bytes = crypto.randomBytes(segmentLength);
        for (let i = 0; i < segmentLength; i++) {
            segment += KEY_CHARSET[bytes[i] % KEY_CHARSET.length];
        }
        parts.push(segment);
    }

    return parts.join('-');
}

function hashKey(key) {
    if (!key) return '';
    const normalized = key.trim().toUpperCase();
    return crypto.createHash('sha256').update(normalized).digest('hex');
}

function getKeyLast4(key) {
    if (!key) return '';
    const clean = key.trim().replace(/-/g, '').toUpperCase();
    return clean.slice(-4);
}

function isValidKeyFormat(key) {
    if (!key || typeof key !== 'string') return false;
    const trimmed = key.trim().toUpperCase();
    // ADB-XXXX-XXXX-XXXX-XXXX or RO-XXXX-XXXX-XXXX-XXXX
    return /^[A-Z0-9]{2,5}(-[A-Z0-9]{4}){4}$/.test(trimmed) || /^[A-Z0-9]{16,24}$/.test(trimmed);
}

function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
    return { salt, hash };
}

function verifyPassword(password, salt, storedHash) {
    if (!password || !salt || !storedHash) return false;
    const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
    const bufferA = Buffer.from(hash, 'hex');
    const bufferB = Buffer.from(storedHash, 'hex');
    if (bufferA.length !== bufferB.length) return false;
    return crypto.timingSafeEqual(bufferA, bufferB);
}

function generateToken() {
    return crypto.randomBytes(32).toString('hex');
}

// Sliding window rate limiter
class RateLimiter {
    constructor(maxRequests = 30, windowMs = 60 * 1000) {
        this.maxRequests = maxRequests;
        this.windowMs = windowMs;
        this.requests = new Map();
        // Cleanup old entries every 5 minutes
        setInterval(() => this.cleanup(), 5 * 60 * 1000).unref();
    }

    isRateLimited(ip) {
        const now = Date.now();
        const timestamps = this.requests.get(ip) || [];
        const windowStart = now - this.windowMs;
        const validTimestamps = timestamps.filter(t => t > windowStart);

        if (validTimestamps.length >= this.maxRequests) {
            return true;
        }

        validTimestamps.push(now);
        this.requests.set(ip, validTimestamps);
        return false;
    }

    cleanup() {
        const now = Date.now();
        const windowStart = now - this.windowMs;
        for (const [ip, timestamps] of this.requests.entries()) {
            const valid = timestamps.filter(t => t > windowStart);
            if (valid.length === 0) {
                this.requests.delete(ip);
            } else {
                this.requests.set(ip, valid);
            }
        }
    }
}

module.exports = {
    generateLicenseKey,
    hashKey,
    getKeyLast4,
    isValidKeyFormat,
    hashPassword,
    verifyPassword,
    generateToken,
    RateLimiter
};
