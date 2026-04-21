import { Request, Response } from 'express';
import { CryptoApplicationService } from '../../../core/application/services/crypto-application.service';
import { CryptServiceError, KeyGenOptions, SealedBlob, SignAlg } from '../../../libs/services/crypt.service';
import { ManagedUseCases } from '../../../core/application/use-cases/managed/managed-use-cases';

type KeyGenReqBody = {
    type?: string;
    passphrase?: string;
    modulusLength?: 2048 | 3072 | 4096;
    namedCurve?: 'prime256v1' | 'secp384r1';
};

export class CryptoController {
    constructor(
        private readonly app: CryptoApplicationService,
        private readonly managedUseCases: ManagedUseCases,
        private readonly legacyRoutesDisabled: boolean
    ) {}

    private sendError(res: Response, err: unknown) {
        if (err instanceof CryptServiceError) {
            return res.status(400).json({ ok: false, error: err.message, code: err.code });
        }
        console.error(err);
        return res.status(500).json({ ok: false, error: 'Internal server error' });
    }

    private blockLegacyRoute(res: Response): boolean {
        if (!this.legacyRoutesDisabled) {
            return false;
        }
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
            namedCurve:
                body.namedCurve === 'secp384r1' || body.namedCurve === 'prime256v1' ? body.namedCurve : 'prime256v1',
            passphrase,
        };
    }

    createManagedKey = (req: Request, res: Response) => {
        try {
            const body = req.body as KeyGenReqBody & { keyId?: string };
            if (!body || (body.type !== 'rsa' && body.type !== 'ec')) {
                return res.status(400).json({ ok: false, error: 'body.type must be "rsa" or "ec"' });
            }
            const result = this.managedUseCases.createManagedKey.execute({
                keyId: typeof body.keyId === 'string' ? body.keyId : undefined,
                type: body.type,
                passphrase: typeof body.passphrase === 'string' ? body.passphrase : undefined,
                modulusLength: body.modulusLength,
                namedCurve: body.namedCurve,
            });
            return res.json({ ok: true, ...result });
        } catch (err) {
            return this.sendError(res, err);
        }
    };

    listManagedKeys = (_req: Request, res: Response) => {
        try {
            return res.json({ ok: true, keys: this.managedUseCases.listManagedKeys.execute() });
        } catch (err) {
            return this.sendError(res, err);
        }
    };

    getManagedPublicKey = (req: Request, res: Response) => {
        try {
            return res.json({ ok: true, ...this.managedUseCases.getManagedPublicKey.execute(req.params.keyId) });
        } catch (err) {
            return this.sendError(res, err);
        }
    };

    rotateManagedKey = (req: Request, res: Response) => {
        try {
            const body = req.body as Partial<KeyGenReqBody>;
            return res.json({
                ok: true,
                ...this.managedUseCases.rotateManagedKey.execute(req.params.keyId, {
                    passphrase: typeof body.passphrase === 'string' ? body.passphrase : undefined,
                    modulusLength: body.modulusLength,
                    namedCurve: body.namedCurve,
                }),
            });
        } catch (err) {
            return this.sendError(res, err);
        }
    };

    disableManagedKey = (req: Request, res: Response) => {
        try {
            return res.json({ ok: true, metadata: this.managedUseCases.disableManagedKey.execute(req.params.keyId) });
        } catch (err) {
            return this.sendError(res, err);
        }
    };

    managedHybridEncrypt = (req: Request, res: Response) => {
        try {
            const { keyId, plaintext } = req.body as { keyId?: string; plaintext?: string };
            if (typeof keyId !== 'string' || typeof plaintext !== 'string') {
                return res.status(400).json({ ok: false, error: 'keyId and plaintext are required' });
            }
            return res.json({ ok: true, ...this.managedUseCases.managedHybridEncrypt.execute(keyId, plaintext) });
        } catch (err) {
            return this.sendError(res, err);
        }
    };

    managedHybridDecrypt = (req: Request, res: Response) => {
        try {
            const body = req.body as {
                keyId?: string;
                encryptedAesKey?: string;
                iv?: string;
                authTag?: string;
                ciphertext?: string;
            };
            if (
                typeof body.keyId !== 'string' ||
                typeof body.encryptedAesKey !== 'string' ||
                typeof body.iv !== 'string' ||
                typeof body.authTag !== 'string' ||
                typeof body.ciphertext !== 'string'
            ) {
                return res.status(400).json({
                    ok: false,
                    error: 'keyId, encryptedAesKey, iv, authTag, ciphertext are required',
                });
            }
            const plaintext = this.managedUseCases.managedHybridDecrypt.execute(body.keyId, {
                encryptedAesKey: body.encryptedAesKey,
                iv: body.iv,
                authTag: body.authTag,
                ciphertext: body.ciphertext,
            });
            return res.json({ ok: true, plaintext });
        } catch (err) {
            return this.sendError(res, err);
        }
    };

    managedSignData = (req: Request, res: Response) => {
        try {
            const { keyId, dataBase64, algorithm } = req.body as { keyId?: string; dataBase64?: string; algorithm?: string };
            if (typeof keyId !== 'string' || typeof dataBase64 !== 'string') {
                return res.status(400).json({ ok: false, error: 'keyId and dataBase64 are required' });
            }
            const alg: SignAlg = algorithm === 'ECDSA-SHA256' ? 'ECDSA-SHA256' : 'RSA-SHA256';
            return res.json({ ok: true, signatureBase64: this.managedUseCases.managedSignData.execute(keyId, dataBase64, alg) });
        } catch (err) {
            return this.sendError(res, err);
        }
    };

    managedSignVerify = (req: Request, res: Response) => {
        try {
            const { keyId, dataBase64, signatureBase64, algorithm } = req.body as {
                keyId?: string;
                dataBase64?: string;
                signatureBase64?: string;
                algorithm?: string;
            };
            if (typeof keyId !== 'string' || typeof dataBase64 !== 'string' || typeof signatureBase64 !== 'string') {
                return res.status(400).json({ ok: false, error: 'keyId, dataBase64, signatureBase64 are required' });
            }
            const alg: SignAlg = algorithm === 'ECDSA-SHA256' ? 'ECDSA-SHA256' : 'RSA-SHA256';
            return res.json({
                ok: true,
                valid: this.managedUseCases.managedVerifySignature.execute(keyId, dataBase64, signatureBase64, alg),
            });
        } catch (err) {
            return this.sendError(res, err);
        }
    };

    keysGenerate = (req: Request, res: Response) => {
        if (this.blockLegacyRoute(res)) return;
        try {
            const body = req.body as KeyGenReqBody;
            if (!body || (body.type !== 'rsa' && body.type !== 'ec')) {
                return res.status(400).json({ ok: false, error: 'body.type must be "rsa" or "ec"' });
            }
            return res.json({ ok: true, ...this.app.generateLegacyKeyPair(this.getKeyGenOptions(body)) });
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
            return res.json({ ok: true, fingerprintSha256Hex: this.app.fingerprintPublicKey(publicKeyPem) });
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
            return res.json({ ok: true, ...this.app.hybridEncrypt(plaintext, publicKeyPem) });
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
                plaintext: this.app.hybridDecrypt(
                    b.encryptedAesKey,
                    b.iv,
                    b.authTag,
                    b.ciphertext,
                    b.privateKeyPem,
                    b.passphrase
                ),
            });
        } catch (err) {
            return this.sendError(res, err);
        }
    };

    symmetricEncrypt = (req: Request, res: Response) => {
        try {
            const { plaintext, key } = req.body as { plaintext?: string; key?: string };
            if (typeof plaintext !== 'string') {
                return res.status(400).json({ ok: false, error: 'plaintext is required' });
            }
            return res.json({ ok: true, ...this.app.symmetricEncrypt(plaintext, typeof key === 'string' ? key : undefined) });
        } catch (err) {
            return this.sendError(res, err);
        }
    };

    symmetricDecrypt = (req: Request, res: Response) => {
        try {
            const { iv, authTag, ciphertext, key } = req.body as { iv?: string; authTag?: string; ciphertext?: string; key?: string };
            if (typeof iv !== 'string' || typeof authTag !== 'string' || typeof ciphertext !== 'string' || typeof key !== 'string') {
                return res.status(400).json({ ok: false, error: 'iv, authTag, ciphertext, key (base64) are required' });
            }
            return res.json({ ok: true, plaintext: this.app.symmetricDecrypt(iv, authTag, ciphertext, key) });
        } catch (err) {
            return this.sendError(res, err);
        }
    };

    pbkdf2 = (req: Request, res: Response) => {
        try {
            const { password, salt, iterations } = req.body as { password?: string; salt?: string; iterations?: number };
            if (typeof password !== 'string') {
                return res.status(400).json({ ok: false, error: 'password is required' });
            }
            return res.json({
                ok: true,
                ...this.app.pbkdf2Derive(
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
        try {
            const { data, inputEncoding } = req.body as { data?: string; inputEncoding?: 'utf8' | 'base64' };
            if (typeof data !== 'string') {
                return res.status(400).json({ ok: false, error: 'data is required' });
            }
            return res.json({ ok: true, hex: this.app.sha256Digest(data, inputEncoding === 'base64' ? 'base64' : 'utf8') });
        } catch (err) {
            return this.sendError(res, err);
        }
    };

    hashCombine = (req: Request, res: Response) => {
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
            return res.json({
                ok: true,
                ...this.app.combineHashes(hashA, hashB, mode, typeof hmacSecret === 'string' ? hmacSecret : undefined),
            });
        } catch (err) {
            return this.sendError(res, err);
        }
    };

    hmacSign = (req: Request, res: Response) => {
        try {
            const { data, secret } = req.body as { data?: string; secret?: string };
            if (typeof data !== 'string' || typeof secret !== 'string') {
                return res.status(400).json({ ok: false, error: 'data and secret (base64) are required' });
            }
            return res.json({ ok: true, signatureHex: this.app.hmacSign(data, secret) });
        } catch (err) {
            return this.sendError(res, err);
        }
    };

    hmacVerify = (req: Request, res: Response) => {
        try {
            const { data, secret, signatureHex } = req.body as { data?: string; secret?: string; signatureHex?: string };
            if (typeof data !== 'string' || typeof secret !== 'string' || typeof signatureHex !== 'string') {
                return res.status(400).json({ ok: false, error: 'data, secret, signatureHex are required' });
            }
            return res.json({ ok: true, valid: this.app.hmacVerify(data, signatureHex, secret) });
        } catch (err) {
            return this.sendError(res, err);
        }
    };

    tokenCreate = (req: Request, res: Response) => {
        try {
            const { payload, secret, expiresInSeconds } = req.body as {
                payload?: Record<string, unknown>;
                secret?: string;
                expiresInSeconds?: number;
            };
            if (!payload || typeof payload !== 'object' || typeof secret !== 'string') {
                return res.status(400).json({ ok: false, error: 'payload (object) and secret (string) are required' });
            }
            return res.json({
                ok: true,
                token: this.app.createSignedToken(
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
        try {
            const { token, secret } = req.body as { token?: string; secret?: string };
            if (typeof token !== 'string' || typeof secret !== 'string') {
                return res.status(400).json({ ok: false, error: 'token and secret are required' });
            }
            return res.json({ ok: true, payload: this.app.verifySignedToken(token, secret) });
        } catch (err) {
            return this.sendError(res, err);
        }
    };

    sealedCreate = (req: Request, res: Response) => {
        try {
            const { data, secret, ttlSeconds } = req.body as { data?: Record<string, unknown>; secret?: string; ttlSeconds?: number };
            if (!data || typeof data !== 'object' || typeof secret !== 'string' || typeof ttlSeconds !== 'number') {
                return res.status(400).json({ ok: false, error: 'data (object), secret (string), ttlSeconds (number) are required' });
            }
            return res.json({ ok: true, sealed: this.app.sealPayload(data, secret, ttlSeconds) });
        } catch (err) {
            return this.sendError(res, err);
        }
    };

    sealedOpen = (req: Request, res: Response) => {
        try {
            const { sealed, secret } = req.body as { sealed?: SealedBlob; secret?: string };
            if (!sealed || typeof secret !== 'string') {
                return res.status(400).json({ ok: false, error: 'sealed (object) and secret are required' });
            }
            return res.json({ ok: true, data: this.app.unsealPayload(sealed, secret) });
        } catch (err) {
            return this.sendError(res, err);
        }
    };

    randomBytes = (req: Request, res: Response) => {
        try {
            const n = parseInt(String(req.query.length ?? '32'), 10);
            const buf = this.app.getRandomBytes(Number.isFinite(n) ? n : 32);
            return res.json({ ok: true, base64: buf.toString('base64'), length: buf.length });
        } catch (err) {
            return this.sendError(res, err);
        }
    };

    randomUuid = (_req: Request, res: Response) => {
        return res.json({ ok: true, uuid: this.app.getRandomUuid() });
    };

    signData = (req: Request, res: Response) => {
        if (this.blockLegacyRoute(res)) return;
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
            const alg: SignAlg = algorithm === 'ECDSA-SHA256' ? 'ECDSA-SHA256' : 'RSA-SHA256';
            return res.json({
                ok: true,
                signatureBase64: this.app.signData(dataBase64, privateKeyPem, typeof passphrase === 'string' ? passphrase : undefined, alg),
            });
        } catch (err) {
            return this.sendError(res, err);
        }
    };

    signVerify = (req: Request, res: Response) => {
        if (this.blockLegacyRoute(res)) return;
        try {
            const { dataBase64, signatureBase64, publicKeyPem, algorithm } = req.body as {
                dataBase64?: string;
                signatureBase64?: string;
                publicKeyPem?: string;
                algorithm?: string;
            };
            if (typeof dataBase64 !== 'string' || typeof signatureBase64 !== 'string' || typeof publicKeyPem !== 'string') {
                return res.status(400).json({ ok: false, error: 'dataBase64, signatureBase64, publicKeyPem are required' });
            }
            const alg: SignAlg = algorithm === 'ECDSA-SHA256' ? 'ECDSA-SHA256' : 'RSA-SHA256';
            return res.json({ ok: true, valid: this.app.verifySignature(dataBase64, signatureBase64, publicKeyPem, alg) });
        } catch (err) {
            return this.sendError(res, err);
        }
    };

    timingSafeEqual = (req: Request, res: Response) => {
        try {
            const { aHex, bHex } = req.body as { aHex?: string; bHex?: string };
            if (typeof aHex !== 'string' || typeof bHex !== 'string') {
                return res.status(400).json({ ok: false, error: 'aHex and bHex are required' });
            }
            return res.json({ ok: true, equal: this.app.timingSafeCompareHex(aHex, bHex) });
        } catch (err) {
            return this.sendError(res, err);
        }
    };
}
