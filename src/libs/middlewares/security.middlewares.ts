import { NextFunction, Request, Response } from 'express';

const DEFAULT_API_KEY = 'dev-api-key';
const WINDOW_MS = Number(process.env.RATE_LIMIT_WINDOW_MS ?? '60000');
const MAX_REQUESTS = Number(process.env.RATE_LIMIT_MAX ?? '120');

type Bucket = {
    resetAt: number;
    count: number;
};

const buckets = new Map<string, Bucket>();

function nowMs(): number {
    return Date.now();
}

function getBucket(key: string): Bucket {
    const now = nowMs();
    const current = buckets.get(key);
    if (!current || now >= current.resetAt) {
        const next: Bucket = { count: 0, resetAt: now + WINDOW_MS };
        buckets.set(key, next);
        return next;
    }
    return current;
}

export function requireApiKey(req: Request, res: Response, next: NextFunction) {
    const configured = (process.env.API_KEY ?? DEFAULT_API_KEY).trim();
    const headerValue = String(req.header('x-api-key') ?? '').trim();
    const authHeader = String(req.header('authorization') ?? '').trim();
    const bearer = authHeader.toLowerCase().startsWith('bearer ') ? authHeader.slice(7).trim() : '';
    const token = headerValue || bearer;

    if (!token || token !== configured) {
        return res.status(401).json({
            ok: false,
            error: 'Unauthorized. Provide x-api-key header (or Bearer token).',
        });
    }
    return next();
}

export function cryptoRateLimit(req: Request, res: Response, next: NextFunction) {
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    const key = `${ip}:${req.method}:${req.route?.path || req.path}`;
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
