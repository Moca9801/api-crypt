import { NextFunction, Request, Response } from 'express';
import { timingSafeEqual } from 'crypto';
import { auditLog } from '../../infrastructure/audit/audit-logger';

// ── API Key — Fail-closed policy ──────────────────────────────────────────────

/**
 * Returns the configured API key, applying a strict fail-closed policy:
 *
 * - NODE_ENV === 'development'  → warn + use 'dev-api-key' fallback
 * - Any other env (production, staging, undefined) → process.exit(1) if API_KEY not set
 *
 * Called once at container initialization to fail-fast before routes are mounted.
 */
export function getConfiguredApiKey(): string {
    const configured = process.env.API_KEY?.trim();
    if (!configured) {
        if (process.env.NODE_ENV === 'development') {
            console.warn(
                '\n⚠️  [api-crypt] WARNING: API_KEY is not set.\n' +
                '   Using insecure default "dev-api-key" for local development.\n' +
                '   NEVER run without API_KEY in any non-development environment.\n'
            );
            return 'dev-api-key';
        }
        console.error(
            '\n🚨 [api-crypt] FATAL: API_KEY environment variable is required.\n' +
            '   Generate one with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"\n' +
            '   Then set it in your .env file or environment.\n'
        );
        process.exit(1);
    }
    return configured;
}

// ── Rate limiting ─────────────────────────────────────────────────────────────

const WINDOW_MS = Number(process.env.RATE_LIMIT_WINDOW_MS ?? '60000');
const MAX_REQUESTS = Number(process.env.RATE_LIMIT_MAX ?? '120');

type Bucket = { resetAt: number; count: number };
const buckets = new Map<string, Bucket>();

function getBucket(key: string): Bucket {
    const now = Date.now();
    const current = buckets.get(key);
    if (!current || now >= current.resetAt) {
        const next: Bucket = { count: 0, resetAt: now + WINDOW_MS };
        buckets.set(key, next);
        return next;
    }
    return current;
}

// ── Middlewares ────────────────────────────────────────────────────────────────

export function requireApiKey(req: Request, res: Response, next: NextFunction) {
    const configured = getConfiguredApiKey();
    const headerValue = String(req.header('x-api-key') ?? '').trim();
    const authHeader = String(req.header('authorization') ?? '').trim();
    const bearer = authHeader.toLowerCase().startsWith('bearer ') ? authHeader.slice(7).trim() : '';
    const token = headerValue || bearer;
    const ip = req.ip ?? req.socket.remoteAddress ?? 'unknown';

    // Timing-safe comparison — previene ataques de timing para enumerar la API key
    const isValid =
        token.length > 0 &&
        token.length === configured.length &&
        timingSafeEqual(Buffer.from(token, 'utf8'), Buffer.from(configured, 'utf8'));

    if (!isValid) {
        auditLog({ event: 'auth.failure', ip, reason: token ? 'invalid_key' : 'missing_key' });
        return res.status(401).json({
            ok: false,
            error: 'Unauthorized. Provide x-api-key header (or Bearer token).',
        });
    }
    return next();
}

export function cryptoRateLimit(req: Request, res: Response, next: NextFunction) {
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    const key = ip; // Global rate limit per IP to avoid high cardinality from dynamic paths
    const bucket = getBucket(key);
    const remainingBefore = MAX_REQUESTS - bucket.count;

    res.setHeader('X-RateLimit-Limit', String(MAX_REQUESTS));
    res.setHeader('X-RateLimit-Remaining', String(Math.max(remainingBefore, 0)));
    res.setHeader('X-RateLimit-Reset', String(Math.floor(bucket.resetAt / 1000)));

    if (bucket.count >= MAX_REQUESTS) {
        return res.status(429).json({
            ok: false,
            error: 'Rate limit exceeded',
            windowMs: WINDOW_MS,
            maxRequests: MAX_REQUESTS,
        });
    }

    bucket.count += 1;
    return next();
}

// ── Rate limiter port (extension point for distributed Redis adapter) ──────────
// To implement Redis-backed rate limiting, create a class implementing this
// interface and inject it via REDIS_URL env var.
//
// export interface RateLimiterPort {
//   increment(key: string, windowMs: number): Promise<{ count: number; resetAt: number }>;
// }
