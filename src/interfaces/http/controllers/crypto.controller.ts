import { Request, Response } from 'express';
import { CryptoProviderPort } from '../../../core/application/ports/crypto-provider.port';
import { CryptServiceError, KeyGenOptions, SealedBlob, SignAlg } from '../../../libs/services/crypt.service';
import { ManagedUseCases } from '../../../core/application/use-cases/managed/managed-use-cases';
import { RotationPolicy } from '../../../core/domain/managed-key';

type KeyGenReqBody = {
    type?: string;
    passphrase?: string;
    modulusLength?: 2048 | 3072 | 4096;
    namedCurve?: 'prime256v1' | 'secp384r1';
};

export class CryptoController {
    constructor(
        private readonly cryptoProvider: CryptoProviderPort,
        private readonly managedUseCases: ManagedUseCases,
        private readonly legacyRoutesDisabled: boolean
    ) {}

    // ── Shared helpers ────────────────────────────────────────────────────────

    private sendError(res: Response, err: unknown) {
        if (err instanceof CryptServiceError) {
            return res.status(400).json({ ok: false, error: err.message, code: err.code });
        }
        console.error(err);
        return res.status(500).json({ ok: false, error: 'Internal server error' });
    }

    private blockLegacyRoute(res: Response): boolean {
        if (!this.legacyRoutesDisabled) return false;
        res.status(403).json({
            ok: false,
            error: 'This legacy crypto route is disabled. Use managed keyId routes instead.',
            code: 'LEGACY_ROUTE_DISABLED',
        });
        return true;
    }

    private getKeyGenOptions(body: KeyGenReqBody): KeyGenOptions {
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
            namedCurve: body.namedCurve === 'secp384r1' || body.namedCurve === 'prime256v1' ? body.namedCurve : 'prime256v1',
            passphrase,
        };
    }


    // ── Legacy stateless routes (use CryptoProviderPort directly — no managed keys) ──

    keysGenerate = (req: Request, res: Response) => {
        if (this.blockLegacyRoute(res)) return;
        try {
            const body = req.body as KeyGenReqBody;
            if (!body || (body.type !== 'rsa' && body.type !== 'ec')) {
                return res.status(400).json({ ok: false, error: 'body.type must be "rsa" or "ec"' });
            }
            return res.json({ ok: true, ...this.cryptoProvider.generateKeyPair(this.getKeyGenOptions(body)) });
        } catch (err) {
            return this.sendError(res, err);
        }
    };

    keyFingerprint = (req: Request, res: Response) => {
        if (this.blockLegacyRoute(res)) return;
        try {
            const { publicKeyPem } = req.body as { publicKeyPem?: string };
            if (!publicKeyPem || typeof publicKeyPem !== 'string') {
                return res.status(400).json({ ok: false, error: 'publicKeyPem is required' });
            }
            return res.json({ ok: true, fingerprintSha256Hex: this.cryptoProvider.publicKeyFingerprint(publicKeyPem) });
        } catch (err) {
            return this.sendError(res, err);
        }
    };

    hybridEncrypt = (req: Request, res: Response) => {
        if (this.blockLegacyRoute(res)) return;
        try {
            const { plaintext, publicKeyPem } = req.body as { plaintext?: string; publicKeyPem?: string };
            if (typeof plaintext !== 'string' || typeof publicKeyPem !== 'string') {
                return res.status(400).json({ ok: false, error: 'plaintext and publicKeyPem (RSA PEM) are required' });
            }
            return res.json({ ok: true, ...this.cryptoProvider.hybridEncrypt(plaintext, publicKeyPem) });
        } catch (err) {
            return this.sendError(res, err);
        }
    };

    hybridDecrypt = (req: Request, res: Response) => {
        if (this.blockLegacyRoute(res)) return;
        try {
            const b = req.body as {
                encryptedAesKey?: string;
                iv?: string;
                authTag?: string;
                ciphertext?: string;
                privateKeyPem?: string;
                passphrase?: string;
            };
            if (
                typeof b.encryptedAesKey !== 'string' ||
                typeof b.iv !== 'string' ||
                typeof b.authTag !== 'string' ||
                typeof b.ciphertext !== 'string' ||
                typeof b.privateKeyPem !== 'string'
            ) {
                return res.status(400).json({
                    ok: false,
                    error: 'encryptedAesKey, iv, authTag, ciphertext, privateKeyPem are required',
                });
            }
            return res.json({
                ok: true,
                plaintext: this.cryptoProvider.hybridDecrypt(
                    b.encryptedAesKey, b.iv, b.authTag, b.ciphertext, b.privateKeyPem, b.passphrase
                ),
            });
        } catch (err) {
            return this.sendError(res, err);
        }
    };

    symmetricEncrypt = (req: Request, res: Response) => {
        if (this.blockLegacyRoute(res)) return;
        try {
            const { plaintext, key } = req.body as { plaintext?: string; key?: string };
            if (typeof plaintext !== 'string') {
                return res.status(400).json({ ok: false, error: 'plaintext is required' });
            }
            return res.json({ ok: true, ...this.cryptoProvider.symmetricEncrypt(plaintext, typeof key === 'string' ? key : undefined) });
        } catch (err) {
            return this.sendError(res, err);
        }
    };

    symmetricDecrypt = (req: Request, res: Response) => {
        if (this.blockLegacyRoute(res)) return;
        try {
            const { iv, authTag, ciphertext, key } = req.body as { iv?: string; authTag?: string; ciphertext?: string; key?: string };
            if (typeof iv !== 'string' || typeof authTag !== 'string' || typeof ciphertext !== 'string' || typeof key !== 'string') {
                return res.status(400).json({ ok: false, error: 'iv, authTag, ciphertext, key (base64) are required' });
            }
            return res.json({ ok: true, plaintext: this.cryptoProvider.symmetricDecrypt(iv, authTag, ciphertext, key) });
        } catch (err) {
            return this.sendError(res, err);
        }
    };

    pbkdf2 = (req: Request, res: Response) => {
        if (this.blockLegacyRoute(res)) return;
        try {
            const { password, salt, iterations } = req.body as { password?: string; salt?: string; iterations?: number };
            if (typeof password !== 'string') {
                return res.status(400).json({ ok: false, error: 'password is required' });
            }
            return res.json({
                ok: true,
                ...this.cryptoProvider.pbkdf2Derive(
                    password,
                    typeof salt === 'string' ? salt : undefined,
                    typeof iterations === 'number' && iterations > 0 ? iterations : undefined
                ),
            });
        } catch (err) {
            return this.sendError(res, err);
        }
    };

    hashSha256 = (req: Request, res: Response) => {
        if (this.blockLegacyRoute(res)) return;
        try {
            const { data, inputEncoding } = req.body as { data?: string; inputEncoding?: 'utf8' | 'base64' };
            if (typeof data !== 'string') {
                return res.status(400).json({ ok: false, error: 'data is required' });
            }
            return res.json({ ok: true, hex: this.cryptoProvider.sha256Digest(data, inputEncoding === 'base64' ? 'base64' : 'utf8') });
        } catch (err) {
            return this.sendError(res, err);
        }
    };

    hashCombine = (req: Request, res: Response) => {
        if (this.blockLegacyRoute(res)) return;
        try {
            const { hashA, hashB, mode, hmacSecret } = req.body as {
                hashA?: string; hashB?: string; mode?: string; hmacSecret?: string;
            };
            if (typeof hashA !== 'string' || typeof hashB !== 'string') {
                return res.status(400).json({ ok: false, error: 'hashA and hashB (64-char hex SHA-256) are required' });
            }
            if (mode !== 'concat-sha256' && mode !== 'hmac-sha256') {
                return res.status(400).json({ ok: false, error: 'mode must be concat-sha256 or hmac-sha256' });
            }
            return res.json({
                ok: true,
                ...this.cryptoProvider.combineHashes(hashA, hashB, mode, typeof hmacSecret === 'string' ? hmacSecret : undefined),
            });
        } catch (err) {
            return this.sendError(res, err);
        }
    };

    hmacSign = (req: Request, res: Response) => {
        if (this.blockLegacyRoute(res)) return;
        try {
            const { data, secret } = req.body as { data?: string; secret?: string };
            if (typeof data !== 'string' || typeof secret !== 'string') {
                return res.status(400).json({ ok: false, error: 'data and secret (base64) are required' });
            }
            return res.json({ ok: true, signatureHex: this.cryptoProvider.hmacSign(data, secret) });
        } catch (err) {
            return this.sendError(res, err);
        }
    };

    hmacVerify = (req: Request, res: Response) => {
        if (this.blockLegacyRoute(res)) return;
        try {
            const { data, secret, signatureHex } = req.body as { data?: string; secret?: string; signatureHex?: string };
            if (typeof data !== 'string' || typeof secret !== 'string' || typeof signatureHex !== 'string') {
                return res.status(400).json({ ok: false, error: 'data, secret, signatureHex are required' });
            }
            return res.json({ ok: true, valid: this.cryptoProvider.hmacVerify(data, signatureHex, secret) });
        } catch (err) {
            return this.sendError(res, err);
        }
    };

    tokenCreate = (req: Request, res: Response) => {
        if (this.blockLegacyRoute(res)) return;
        try {
            const { payload, secret, expiresInSeconds } = req.body as {
                payload?: Record<string, unknown>; secret?: string; expiresInSeconds?: number;
            };
            if (!payload || typeof payload !== 'object' || typeof secret !== 'string') {
                return res.status(400).json({ ok: false, error: 'payload (object) and secret (string) are required' });
            }
            return res.json({
                ok: true,
                token: this.cryptoProvider.createSignedToken(
                    payload,
                    secret,
                    typeof expiresInSeconds === 'number' && expiresInSeconds > 0 ? expiresInSeconds : undefined
                ),
            });
        } catch (err) {
            return this.sendError(res, err);
        }
    };

    tokenVerify = (req: Request, res: Response) => {
        if (this.blockLegacyRoute(res)) return;
        try {
            const { token, secret } = req.body as { token?: string; secret?: string };
            if (typeof token !== 'string' || typeof secret !== 'string') {
                return res.status(400).json({ ok: false, error: 'token and secret are required' });
            }
            return res.json({ ok: true, payload: this.cryptoProvider.verifySignedToken(token, secret) });
        } catch (err) {
            return this.sendError(res, err);
        }
    };

    sealedCreate = (req: Request, res: Response) => {
        if (this.blockLegacyRoute(res)) return;
        try {
            const { data, secret, ttlSeconds } = req.body as { data?: Record<string, unknown>; secret?: string; ttlSeconds?: number };
            if (!data || typeof data !== 'object' || typeof secret !== 'string' || typeof ttlSeconds !== 'number') {
                return res.status(400).json({ ok: false, error: 'data (object), secret (string), ttlSeconds (number) are required' });
            }
            return res.json({ ok: true, sealed: this.cryptoProvider.sealPayload(data, secret, ttlSeconds) });
        } catch (err) {
            return this.sendError(res, err);
        }
    };

    sealedOpen = (req: Request, res: Response) => {
        if (this.blockLegacyRoute(res)) return;
        try {
            const { sealed, secret } = req.body as { sealed?: SealedBlob; secret?: string };
            if (!sealed || typeof secret !== 'string') {
                return res.status(400).json({ ok: false, error: 'sealed (object) and secret are required' });
            }
            return res.json({ ok: true, data: this.cryptoProvider.unsealPayload(sealed, secret) });
        } catch (err) {
            return this.sendError(res, err);
        }
    };

    randomBytes = (req: Request, res: Response) => {
        if (this.blockLegacyRoute(res)) return;
        try {
            const n = parseInt(String(req.query.length ?? '32'), 10);
            const buf = this.cryptoProvider.getRandomBytes(Number.isFinite(n) ? n : 32);
            return res.json({ ok: true, base64: buf.toString('base64'), length: buf.length });
        } catch (err) {
            return this.sendError(res, err);
        }
    };

    randomUuid = (_req: Request, res: Response) => {
        if (this.blockLegacyRoute(res)) return;
        return res.json({ ok: true, uuid: this.cryptoProvider.getRandomUuid() });
    };

    signData = (req: Request, res: Response) => {
        if (this.blockLegacyRoute(res)) return;
        try {
            const { dataBase64, privateKeyPem, passphrase, algorithm } = req.body as {
                dataBase64?: string; privateKeyPem?: string; passphrase?: string; algorithm?: string;
            };
            if (typeof dataBase64 !== 'string' || typeof privateKeyPem !== 'string') {
                return res.status(400).json({ ok: false, error: 'dataBase64 and privateKeyPem are required' });
            }
            const alg: SignAlg = algorithm === 'ECDSA-SHA256' ? 'ECDSA-SHA256' : 'RSA-SHA256';
            return res.json({
                ok: true,
                signatureBase64: this.cryptoProvider.signData(
                    dataBase64, privateKeyPem, typeof passphrase === 'string' ? passphrase : undefined, alg
                ),
            });
        } catch (err) {
            return this.sendError(res, err);
        }
    };

    signVerify = (req: Request, res: Response) => {
        if (this.blockLegacyRoute(res)) return;
        try {
            const { dataBase64, signatureBase64, publicKeyPem, algorithm } = req.body as {
                dataBase64?: string; signatureBase64?: string; publicKeyPem?: string; algorithm?: string;
            };
            if (typeof dataBase64 !== 'string' || typeof signatureBase64 !== 'string' || typeof publicKeyPem !== 'string') {
                return res.status(400).json({ ok: false, error: 'dataBase64, signatureBase64, publicKeyPem are required' });
            }
            const alg: SignAlg = algorithm === 'ECDSA-SHA256' ? 'ECDSA-SHA256' : 'RSA-SHA256';
            return res.json({ ok: true, valid: this.cryptoProvider.verifySignature(dataBase64, signatureBase64, publicKeyPem, alg) });
        } catch (err) {
            return this.sendError(res, err);
        }
    };

    timingSafeEqual = (req: Request, res: Response) => {
        if (this.blockLegacyRoute(res)) return;
        try {
            const { aHex, bHex } = req.body as { aHex?: string; bHex?: string };
            if (typeof aHex !== 'string' || typeof bHex !== 'string') {
                return res.status(400).json({ ok: false, error: 'aHex and bHex are required' });
            }
            return res.json({ ok: true, equal: this.cryptoProvider.timingSafeCompareHex(aHex, bHex) });
        } catch (err) {
            return this.sendError(res, err);
        }
    };
}
