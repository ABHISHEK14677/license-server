const crypto = require('node:crypto');

// Cryptographically secure license key generator
// Format: RO-XXXX-XXXX-XXXX-XXXX
const KEY_CHARSET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // Excludes 0, O, 1, I for readability

function generateLicenseKey(prefix = 'RO') {
    const segments = 4;
    const segmentLength = 4;
    const parts = [prefix];

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

function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
    return { salt, hash };
}

function verifyPassword(password, salt, storedHash) {
    const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
    const bufferA = Buffer.from(hash, 'hex');
    const bufferB = Buffer.from(storedHash, 'hex');
    if (bufferA.length !== bufferB.length) return false;
    return crypto.timingSafeEqual(bufferA, bufferB);
}

function generateToken() {
    return crypto.randomBytes(32).toString('hex');
}

// Simple sliding window rate limiter
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
    hashPassword,
    verifyPassword,
    generateToken,
    RateLimiter
};
