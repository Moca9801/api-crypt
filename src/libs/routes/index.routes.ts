import express, { Request, Response } from 'express';
import cryptRoutes from './crypt.routes';
import { getOpenApiDocument } from '../docs/openapi';
import { metricsRegistry } from '../../infrastructure/metrics/metrics-registry';

const v1Router = express.Router();



v1Router.get('/', (_req, res) => {
    res.json({
        ok: true,
        name: 'api-crypt',
        cryptoBase: '/api/v1/crypto',
        auth: {
            header: 'x-api-key',
            note: 'Set API_KEY in .env. Default (development only): dev-api-key',
        },
        endpoints: [
            'GET  /api/v1/health',
            'GET  /api/v1/metrics',
            'GET  /api/v1/docs/openapi.json',
            'POST /api/v1/crypto/keys/managed/create',
            'GET  /api/v1/crypto/keys/managed',
            'GET  /api/v1/crypto/keys/managed/:keyId/public',
            'POST /api/v1/crypto/keys/managed/:keyId/rotate',
            'POST /api/v1/crypto/keys/managed/:keyId/disable',
            'POST /api/v1/crypto/keys/managed/:keyId/policy',
            'GET  /api/v1/crypto/keys/managed/rotation/pending',
            'POST /api/v1/crypto/managed/hybrid/encrypt',
            'POST /api/v1/crypto/managed/hybrid/decrypt',
            'POST /api/v1/crypto/managed/sign/data',
            'POST /api/v1/crypto/managed/sign/verify',
            'POST /api/v1/crypto/keys/generate',
            'POST /api/v1/crypto/keys/fingerprint',
            'POST /api/v1/crypto/hybrid/encrypt',
            'POST /api/v1/crypto/hybrid/decrypt',
            'POST /api/v1/crypto/symmetric/encrypt',
            'POST /api/v1/crypto/symmetric/decrypt',
            'POST /api/v1/crypto/kdf/pbkdf2',
            'POST /api/v1/crypto/hash/sha256',
            'POST /api/v1/crypto/hash/combine',
            'POST /api/v1/crypto/hmac/sign',
            'POST /api/v1/crypto/hmac/verify',
            'POST /api/v1/crypto/tokens/signed/create',
            'POST /api/v1/crypto/tokens/signed/verify',
            'POST /api/v1/crypto/sealed/create',
            'POST /api/v1/crypto/sealed/open',
            'GET  /api/v1/crypto/random/bytes?length=32',
            'GET  /api/v1/crypto/random/uuid',
            'POST /api/v1/crypto/sign/data',
            'POST /api/v1/crypto/sign/verify',
            'POST /api/v1/crypto/utils/timing-safe-equal',
        ],
    });
});

v1Router.get('/docs/openapi.json', (_req, res) => {
    res.json(getOpenApiDocument());
});

// ── /metrics — Prometheus scrape endpoint ─────────────────────────────────────
// No requiere API key, pero solo accesible desde IPs permitidas.
const METRICS_ALLOWED = (process.env.METRICS_ALLOWED_IPS ?? '127.0.0.1,::1')
    .split(',').map((ip) => ip.trim()).filter(Boolean);

v1Router.get('/metrics', (req: Request, res: Response) => {
    const clientIp = req.ip ?? req.socket.remoteAddress ?? '';
    const allowed = METRICS_ALLOWED.some((allowed) =>
        clientIp === allowed || clientIp.endsWith(allowed) || allowed === '0.0.0.0'
    );
    if (!allowed) {
        return res.status(403).json({ ok: false, error: 'Metrics endpoint access denied.' });
    }
    res.setHeader('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
    return res.send(metricsRegistry.toPrometheusText());
});

v1Router.use('/crypto', cryptRoutes);

export default v1Router;