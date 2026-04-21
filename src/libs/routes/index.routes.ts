import express from 'express';
import cryptRoutes from './crypt.routes';
import { getOpenApiDocument } from '../docs/openapi';

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
            'GET  /api/v1/docs/openapi.json',
            'POST /api/v1/crypto/keys/managed/create',
            'GET  /api/v1/crypto/keys/managed',
            'GET  /api/v1/crypto/keys/managed/:keyId/public',
            'POST /api/v1/crypto/keys/managed/:keyId/rotate',
            'POST /api/v1/crypto/keys/managed/:keyId/disable',
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

v1Router.use('/crypto', cryptRoutes);

export default v1Router;