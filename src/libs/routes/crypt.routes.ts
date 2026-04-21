import { Router, Request, Response } from 'express';
import {
    CryptServiceError,
    combineHashes,
    createSignedToken,
    generateKeyPair,
    getRandomBytes,
    getRandomUuid,
    hmacSign,
    hmacVerify,
    hybridDecrypt,
    hybridEncrypt,
    KeyGenOptions,
    pbkdf2Derive,
    publicKeyFingerprint,
    sealPayload,
    SealedBlob,
    sha256Digest,
    signData,
    symmetricDecrypt,
    symmetricEncrypt,
    timingSafeCompareHex,
    unsealPayload,
    verifySignature,
    verifySignedToken,
} from '../services/crypt.service';
import {
    createManagedKey,
    disableManagedKey,
    getManagedPublicKey,
    listManagedKeys,
    managedHybridDecrypt,
    managedHybridEncrypt,
    managedSignData,
    managedVerifySignature,
    rotateManagedKey,
} from '../services/managed-key.service';
import { cryptoRateLimit, requireApiKey } from '../middlewares/security.middlewares';

type KeyGenReqBody = {
    type?: string;
    passphrase?: string;
    modulusLength?: 2048 | 3072 | 4096;
    namedCurve?: 'prime256v1' | 'secp384r1';
};

const router = Router();
router.use(requireApiKey);
router.use(cryptoRateLimit);
const legacyRoutesDisabled =
    (process.env.DISABLE_LEGACY_CRYPTO_ROUTES ?? (process.env.NODE_ENV === 'production' ? 'true' : 'false')) ===
    'true';

function sendError(res: Response, err: unknown) {
    if (err instanceof CryptServiceError) {
        return res.status(400).json({ ok: false, error: err.message, code: err.code });
    }
    console.error(err);
    return res.status(500).json({ ok: false, error: 'Internal server error' });
}

function blockLegacyRoute(_req: Request, res: Response, next: () => void) {
    if (!legacyRoutesDisabled) {
        return next();
    }
    return res.status(403).json({
        ok: false,
        error: 'This legacy crypto route is disabled. Use managed keyId routes instead.',
        code: 'LEGACY_ROUTE_DISABLED',
    });
}

function getKeyGenOptions(body: KeyGenReqBody): KeyGenOptions {
    const passphrase = typeof body.passphrase === 'string' ? body.passphrase : undefined;
    if (body.type === 'rsa') {
        return {
            type: 'rsa',
            modulusLength: body.modulusLength === 3072 || body.modulusLength === 4096 ? body.modulusLength : 2048,
            passphrase,
        };
    }
    return {
        type: 'ec',
        namedCurve:
            body.namedCurve === 'secp384r1' || body.namedCurve === 'prime256v1' ? body.namedCurve : 'prime256v1',
        passphrase,
    };
}

/** POST /keys/managed/create */
router.post('/keys/managed/create', (req: Request, res: Response) => {
    try {
        const body = req.body as KeyGenReqBody & { keyId?: string };
        if (!body || (body.type !== 'rsa' && body.type !== 'ec')) {
            return res.status(400).json({ ok: false, error: 'body.type must be "rsa" or "ec"' });
        }
        const keyId = typeof body.keyId === 'string' ? body.keyId : undefined;
        const created = createManagedKey(getKeyGenOptions(body), keyId);
        return res.json({ ok: true, ...created });
    } catch (err) {
        return sendError(res, err);
    }
});

/** GET /keys/managed */
router.get('/keys/managed', (_req: Request, res: Response) => {
    try {
        return res.json({ ok: true, keys: listManagedKeys() });
    } catch (err) {
        return sendError(res, err);
    }
});

/** GET /keys/managed/:keyId/public */
router.get('/keys/managed/:keyId/public', (req: Request, res: Response) => {
    try {
        return res.json({ ok: true, ...getManagedPublicKey(req.params.keyId) });
    } catch (err) {
        return sendError(res, err);
    }
});

/** POST /keys/managed/:keyId/rotate */
router.post('/keys/managed/:keyId/rotate', (req: Request, res: Response) => {
    try {
        const body = req.body as Partial<KeyGenReqBody>;
        const rotated = rotateManagedKey(req.params.keyId, {
            passphrase: typeof body.passphrase === 'string' ? body.passphrase : undefined,
            modulusLength: body.modulusLength,
            namedCurve: body.namedCurve,
        });
        return res.json({ ok: true, ...rotated });
    } catch (err) {
        return sendError(res, err);
    }
});

/** POST /keys/managed/:keyId/disable */
router.post('/keys/managed/:keyId/disable', (req: Request, res: Response) => {
    try {
        return res.json({ ok: true, metadata: disableManagedKey(req.params.keyId) });
    } catch (err) {
        return sendError(res, err);
    }
});

/** POST /managed/hybrid/encrypt */
router.post('/managed/hybrid/encrypt', (req: Request, res: Response) => {
    try {
        const { keyId, plaintext } = req.body as { keyId?: string; plaintext?: string };
        if (typeof keyId !== 'string' || typeof plaintext !== 'string') {
            return res.status(400).json({ ok: false, error: 'keyId and plaintext are required' });
        }
        return res.json({ ok: true, ...managedHybridEncrypt(keyId, plaintext) });
    } catch (err) {
        return sendError(res, err);
    }
});

/** POST /managed/hybrid/decrypt */
router.post('/managed/hybrid/decrypt', (req: Request, res: Response) => {
    try {
        const body = req.body as {
            keyId?: string;
            encryptedAesKey?: string;
            iv?: string;
            authTag?: string;
            ciphertext?: string;
        };
        const { keyId, encryptedAesKey, iv, authTag, ciphertext } = body;
        if (
            typeof keyId !== 'string' ||
            typeof encryptedAesKey !== 'string' ||
            typeof iv !== 'string' ||
            typeof authTag !== 'string' ||
            typeof ciphertext !== 'string'
        ) {
            return res.status(400).json({
                ok: false,
                error: 'keyId, encryptedAesKey, iv, authTag, ciphertext are required',
            });
        }
        const plaintext = managedHybridDecrypt(keyId, { encryptedAesKey, iv, authTag, ciphertext });
        return res.json({ ok: true, plaintext });
    } catch (err) {
        return sendError(res, err);
    }
});

/** POST /managed/sign/data */
router.post('/managed/sign/data', (req: Request, res: Response) => {
    try {
        const { keyId, dataBase64, algorithm } = req.body as {
            keyId?: string;
            dataBase64?: string;
            algorithm?: string;
        };
        if (typeof keyId !== 'string' || typeof dataBase64 !== 'string') {
            return res.status(400).json({ ok: false, error: 'keyId and dataBase64 are required' });
        }
        const alg = algorithm === 'ECDSA-SHA256' ? 'ECDSA-SHA256' : 'RSA-SHA256';
        return res.json({ ok: true, signatureBase64: managedSignData(keyId, dataBase64, alg) });
    } catch (err) {
        return sendError(res, err);
    }
});

/** POST /managed/sign/verify */
router.post('/managed/sign/verify', (req: Request, res: Response) => {
    try {
        const { keyId, dataBase64, signatureBase64, algorithm } = req.body as {
            keyId?: string;
            dataBase64?: string;
            signatureBase64?: string;
            algorithm?: string;
        };
        if (typeof keyId !== 'string' || typeof dataBase64 !== 'string' || typeof signatureBase64 !== 'string') {
            return res.status(400).json({
                ok: false,
                error: 'keyId, dataBase64, signatureBase64 are required',
            });
        }
        const alg = algorithm === 'ECDSA-SHA256' ? 'ECDSA-SHA256' : 'RSA-SHA256';
        return res.json({ ok: true, valid: managedVerifySignature(keyId, dataBase64, signatureBase64, alg) });
    } catch (err) {
        return sendError(res, err);
    }
});

/** POST /keys/generate */
router.post('/keys/generate', blockLegacyRoute, (req: Request, res: Response) => {
    try {
        const body = req.body as KeyGenReqBody;
        if (!body || (body.type !== 'rsa' && body.type !== 'ec')) {
            return res.status(400).json({ ok: false, error: 'body.type must be "rsa" or "ec"' });
        }
        return res.json({ ok: true, ...generateKeyPair(getKeyGenOptions(body)) });
    } catch (err) {
        return sendError(res, err);
    }
});

/** POST /keys/fingerprint */
router.post('/keys/fingerprint', blockLegacyRoute, (req: Request, res: Response) => {
    try {
        const { publicKeyPem } = req.body as { publicKeyPem?: string };
        if (!publicKeyPem || typeof publicKeyPem !== 'string') {
            return res.status(400).json({ ok: false, error: 'publicKeyPem is required' });
        }
        return res.json({ ok: true, fingerprintSha256Hex: publicKeyFingerprint(publicKeyPem) });
    } catch (err) {
        return sendError(res, err);
    }
});

/** POST /hybrid/encrypt */
router.post('/hybrid/encrypt', blockLegacyRoute, (req: Request, res: Response) => {
    try {
        const { plaintext, publicKeyPem } = req.body as { plaintext?: string; publicKeyPem?: string };
        if (typeof plaintext !== 'string' || typeof publicKeyPem !== 'string') {
            return res.status(400).json({ ok: false, error: 'plaintext and publicKeyPem (RSA PEM) are required' });
        }
        return res.json({ ok: true, ...hybridEncrypt(plaintext, publicKeyPem) });
    } catch (err) {
        return sendError(res, err);
    }
});

/** POST /hybrid/decrypt */
router.post('/hybrid/decrypt', blockLegacyRoute, (req: Request, res: Response) => {
    try {
        const b = req.body as {
            encryptedAesKey?: string;
            iv?: string;
            authTag?: string;
            ciphertext?: string;
            privateKeyPem?: string;
            passphrase?: string;
        };
        const { encryptedAesKey, iv, authTag, ciphertext, privateKeyPem } = b;
        if (
            typeof encryptedAesKey !== 'string' ||
            typeof iv !== 'string' ||
            typeof authTag !== 'string' ||
            typeof ciphertext !== 'string' ||
            typeof privateKeyPem !== 'string'
        ) {
            return res.status(400).json({
                ok: false,
                error: 'encryptedAesKey, iv, authTag, ciphertext, privateKeyPem are required',
            });
        }
        const plaintext = hybridDecrypt(encryptedAesKey, iv, authTag, ciphertext, privateKeyPem, b.passphrase);
        return res.json({ ok: true, plaintext });
    } catch (err) {
        return sendError(res, err);
    }
});

/** POST /symmetric/encrypt */
router.post('/symmetric/encrypt', (req: Request, res: Response) => {
    try {
        const { plaintext, key } = req.body as { plaintext?: string; key?: string };
        if (typeof plaintext !== 'string') {
            return res.status(400).json({ ok: false, error: 'plaintext is required' });
        }
        const keyOpt = typeof key === 'string' ? key : undefined;
        return res.json({ ok: true, ...symmetricEncrypt(plaintext, keyOpt) });
    } catch (err) {
        return sendError(res, err);
    }
});

/** POST /symmetric/decrypt */
router.post('/symmetric/decrypt', (req: Request, res: Response) => {
    try {
        const { iv, authTag, ciphertext, key } = req.body as {
            iv?: string;
            authTag?: string;
            ciphertext?: string;
            key?: string;
        };
        if (
            typeof iv !== 'string' ||
            typeof authTag !== 'string' ||
            typeof ciphertext !== 'string' ||
            typeof key !== 'string'
        ) {
            return res.status(400).json({ ok: false, error: 'iv, authTag, ciphertext, key (base64) are required' });
        }
        const plaintext = symmetricDecrypt(iv, authTag, ciphertext, key);
        return res.json({ ok: true, plaintext });
    } catch (err) {
        return sendError(res, err);
    }
});

/** POST /kdf/pbkdf2 */
router.post('/kdf/pbkdf2', (req: Request, res: Response) => {
    try {
        const { password, salt, iterations } = req.body as {
            password?: string;
            salt?: string;
            iterations?: number;
        };
        if (typeof password !== 'string') {
            return res.status(400).json({ ok: false, error: 'password is required' });
        }
        const saltOpt = typeof salt === 'string' ? salt : undefined;
        const iter = typeof iterations === 'number' && iterations > 0 ? iterations : undefined;
        return res.json({ ok: true, ...pbkdf2Derive(password, saltOpt, iter) });
    } catch (err) {
        return sendError(res, err);
    }
});

/** POST /hash/sha256 */
router.post('/hash/sha256', (req: Request, res: Response) => {
    try {
        const { data, inputEncoding } = req.body as { data?: string; inputEncoding?: 'utf8' | 'base64' };
        if (typeof data !== 'string') {
            return res.status(400).json({ ok: false, error: 'data is required' });
        }
        const enc = inputEncoding === 'base64' ? 'base64' : 'utf8';
        return res.json({ ok: true, hex: sha256Digest(data, enc) });
    } catch (err) {
        return sendError(res, err);
    }
});

/** POST /hash/combine */
router.post('/hash/combine', (req: Request, res: Response) => {
    try {
        const { hashA, hashB, mode, hmacSecret } = req.body as {
            hashA?: string;
            hashB?: string;
            mode?: string;
            hmacSecret?: string;
        };
        if (typeof hashA !== 'string' || typeof hashB !== 'string') {
            return res.status(400).json({ ok: false, error: 'hashA and hashB (64-char hex SHA-256) are required' });
        }
        if (mode !== 'concat-sha256' && mode !== 'hmac-sha256') {
            return res.status(400).json({ ok: false, error: 'mode must be concat-sha256 or hmac-sha256' });
        }
        const hmacOpt = typeof hmacSecret === 'string' ? hmacSecret : undefined;
        return res.json({ ok: true, ...combineHashes(hashA, hashB, mode, hmacOpt) });
    } catch (err) {
        return sendError(res, err);
    }
});

/** POST /hmac/sign */
router.post('/hmac/sign', (req: Request, res: Response) => {
    try {
        const { data, secret } = req.body as { data?: string; secret?: string };
        if (typeof data !== 'string' || typeof secret !== 'string') {
            return res.status(400).json({ ok: false, error: 'data and secret (base64) are required' });
        }
        return res.json({ ok: true, signatureHex: hmacSign(data, secret) });
    } catch (err) {
        return sendError(res, err);
    }
});

/** POST /hmac/verify */
router.post('/hmac/verify', (req: Request, res: Response) => {
    try {
        const { data, secret, signatureHex } = req.body as { data?: string; secret?: string; signatureHex?: string };
        if (typeof data !== 'string' || typeof secret !== 'string' || typeof signatureHex !== 'string') {
            return res.status(400).json({ ok: false, error: 'data, secret, signatureHex are required' });
        }
        return res.json({ ok: true, valid: hmacVerify(data, signatureHex, secret) });
    } catch (err) {
        return sendError(res, err);
    }
});

/** POST /tokens/signed/create */
router.post('/tokens/signed/create', (req: Request, res: Response) => {
    try {
        const { payload, secret, expiresInSeconds } = req.body as {
            payload?: Record<string, unknown>;
            secret?: string;
            expiresInSeconds?: number;
        };
        if (!payload || typeof payload !== 'object' || typeof secret !== 'string') {
            return res.status(400).json({ ok: false, error: 'payload (object) and secret (string) are required' });
        }
        const exp =
            typeof expiresInSeconds === 'number' && expiresInSeconds > 0 ? expiresInSeconds : undefined;
        return res.json({ ok: true, token: createSignedToken(payload, secret, exp) });
    } catch (err) {
        return sendError(res, err);
    }
});

/** POST /tokens/signed/verify */
router.post('/tokens/signed/verify', (req: Request, res: Response) => {
    try {
        const { token, secret } = req.body as { token?: string; secret?: string };
        if (typeof token !== 'string' || typeof secret !== 'string') {
            return res.status(400).json({ ok: false, error: 'token and secret are required' });
        }
        const payload = verifySignedToken(token, secret);
        return res.json({ ok: true, payload });
    } catch (err) {
        return sendError(res, err);
    }
});

/** POST /sealed/create */
router.post('/sealed/create', (req: Request, res: Response) => {
    try {
        const { data, secret, ttlSeconds } = req.body as {
            data?: Record<string, unknown>;
            secret?: string;
            ttlSeconds?: number;
        };
        if (!data || typeof data !== 'object' || typeof secret !== 'string' || typeof ttlSeconds !== 'number') {
            return res.status(400).json({
                ok: false,
                error: 'data (object), secret (string), ttlSeconds (number) are required',
            });
        }
        return res.json({ ok: true, sealed: sealPayload(data, secret, ttlSeconds) });
    } catch (err) {
        return sendError(res, err);
    }
});

/** POST /sealed/open */
router.post('/sealed/open', (req: Request, res: Response) => {
    try {
        const { sealed, secret } = req.body as { sealed?: SealedBlob; secret?: string };
        if (!sealed || typeof secret !== 'string') {
            return res.status(400).json({ ok: false, error: 'sealed (object) and secret are required' });
        }
        const data = unsealPayload(sealed, secret);
        return res.json({ ok: true, data });
    } catch (err) {
        return sendError(res, err);
    }
});

/** GET /random/bytes?length=32 */
router.get('/random/bytes', (req: Request, res: Response) => {
    try {
        const n = parseInt(String(req.query.length ?? '32'), 10);
        const buf = getRandomBytes(Number.isFinite(n) ? n : 32);
        return res.json({ ok: true, base64: buf.toString('base64'), length: buf.length });
    } catch (err) {
        return sendError(res, err);
    }
});

/** GET /random/uuid */
router.get('/random/uuid', (_req: Request, res: Response) => {
    return res.json({ ok: true, uuid: getRandomUuid() });
});

/** POST /sign/data */
router.post('/sign/data', blockLegacyRoute, (req: Request, res: Response) => {
    try {
        const { dataBase64, privateKeyPem, passphrase, algorithm } = req.body as {
            dataBase64?: string;
            privateKeyPem?: string;
            passphrase?: string;
            algorithm?: string;
        };
        if (typeof dataBase64 !== 'string' || typeof privateKeyPem !== 'string') {
            return res.status(400).json({ ok: false, error: 'dataBase64 and privateKeyPem are required' });
        }
        const alg = algorithm === 'ECDSA-SHA256' ? 'ECDSA-SHA256' : 'RSA-SHA256';
        const pass = typeof passphrase === 'string' ? passphrase : undefined;
        return res.json({ ok: true, signatureBase64: signData(dataBase64, privateKeyPem, pass, alg) });
    } catch (err) {
        return sendError(res, err);
    }
});

/** POST /sign/verify */
router.post('/sign/verify', blockLegacyRoute, (req: Request, res: Response) => {
    try {
        const { dataBase64, signatureBase64, publicKeyPem, algorithm } = req.body as {
            dataBase64?: string;
            signatureBase64?: string;
            publicKeyPem?: string;
            algorithm?: string;
        };
        if (
            typeof dataBase64 !== 'string' ||
            typeof signatureBase64 !== 'string' ||
            typeof publicKeyPem !== 'string'
        ) {
            return res.status(400).json({
                ok: false,
                error: 'dataBase64, signatureBase64, publicKeyPem are required',
            });
        }
        const alg = algorithm === 'ECDSA-SHA256' ? 'ECDSA-SHA256' : 'RSA-SHA256';
        return res.json({ ok: true, valid: verifySignature(dataBase64, signatureBase64, publicKeyPem, alg) });
    } catch (err) {
        return sendError(res, err);
    }
});

/** POST /utils/timing-safe-equal */
router.post('/utils/timing-safe-equal', (req: Request, res: Response) => {
    try {
        const { aHex, bHex } = req.body as { aHex?: string; bHex?: string };
        if (typeof aHex !== 'string' || typeof bHex !== 'string') {
            return res.status(400).json({ ok: false, error: 'aHex and bHex are required' });
        }
        return res.json({ ok: true, equal: timingSafeCompareHex(aHex, bHex) });
    } catch (err) {
        return sendError(res, err);
    }
});

export default router;
