import {
    constants,
    createCipheriv,
    createDecipheriv,
    createHash,
    createHmac,
    createPrivateKey,
    createPublicKey,
    generateKeyPairSync,
    hkdfSync,
    pbkdf2Sync,
    privateDecrypt,
    publicEncrypt,
    randomBytes,
    randomUUID,
    sign,
    timingSafeEqual,
    verify,
} from 'crypto';

const AES_KEY_LEN = 32;
const GCM_IV_LEN = 12;
const HKDF_INFO = Buffer.from('api-crypt-seal-v1', 'utf8');

export class CryptServiceError extends Error {
    constructor(message: string, readonly code = 'CRYPT_ERROR') {
        super(message);
        this.name = 'CryptServiceError';
    }
}

function toBase64(buf: Buffer): string {
    return buf.toString('base64');
}

function fromBase64(b64: string): Buffer {
    try {
        return Buffer.from(b64, 'base64');
    } catch {
        throw new CryptServiceError('Invalid base64');
    }
}

function base64UrlEncode(data: string | Buffer): string {
    const b = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
    return b.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecode(s: string): Buffer {
    let b64 = s.replace(/-/g, '+').replace(/_/g, '/');
    const pad = 4 - (b64.length % 4);
    if (pad !== 4) b64 += '='.repeat(pad);
    try {
        return Buffer.from(b64, 'base64');
    } catch {
        throw new CryptServiceError('Invalid base64url');
    }
}

function loadPrivateKey(pem: string, passphrase?: string) {
    try {
        return createPrivateKey(
            passphrase
                ? { key: pem, passphrase, format: 'pem' as const }
                : { key: pem, format: 'pem' as const }
        );
    } catch {
        throw new CryptServiceError('Invalid private key or passphrase');
    }
}

function loadPublicKey(pem: string) {
    try {
        return createPublicKey({ key: pem, format: 'pem' as const });
    } catch {
        throw new CryptServiceError('Invalid public key PEM');
    }
}

export type KeyGenOptions =
    | { type: 'rsa'; modulusLength?: 2048 | 3072 | 4096; passphrase?: string }
    | { type: 'ec'; namedCurve?: 'prime256v1' | 'secp384r1'; passphrase?: string };

export function generateKeyPair(opts: KeyGenOptions) {
    const passphrase = opts.passphrase;
    if (opts.type === 'rsa') {
        const modulusLength = opts.modulusLength ?? 2048;
        const { publicKey, privateKey } = generateKeyPairSync('rsa', {
            modulusLength,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: passphrase
                ? {
                      type: 'pkcs8',
                      format: 'pem',
                      cipher: 'aes-256-cbc',
                      passphrase,
                  }
                : { type: 'pkcs8', format: 'pem' },
        });
        return { algorithm: `RSA-${modulusLength}`, publicKey, privateKey };
    }
    const namedCurve = opts.namedCurve ?? 'prime256v1';
    const { publicKey, privateKey } = generateKeyPairSync('ec', {
        namedCurve,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: passphrase
            ? {
                  type: 'pkcs8',
                  format: 'pem',
                  cipher: 'aes-256-cbc',
                  passphrase,
              }
            : { type: 'pkcs8', format: 'pem' },
    });
    return { algorithm: `EC-${namedCurve}`, publicKey, privateKey };
}

export interface HybridEncryptResult {
    scheme: 'RSA-OAEP-256_AES-256-GCM';
    encryptedAesKey: string;
    iv: string;
    authTag: string;
    ciphertext: string;
}

export function hybridEncrypt(plaintextUtf8: string, publicKeyPem: string): HybridEncryptResult {
    const aesKey = randomBytes(AES_KEY_LEN);
    const iv = randomBytes(GCM_IV_LEN);
    const cipher = createCipheriv('aes-256-gcm', aesKey, iv);
    const enc = Buffer.concat([cipher.update(plaintextUtf8, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();
    const pub = loadPublicKey(publicKeyPem);
    const encryptedAesKey = publicEncrypt(
        {
            key: pub,
            padding: constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256',
        },
        aesKey
    );
    return {
        scheme: 'RSA-OAEP-256_AES-256-GCM',
        encryptedAesKey: toBase64(encryptedAesKey),
        iv: toBase64(iv),
        authTag: toBase64(authTag),
        ciphertext: toBase64(enc),
    };
}

export function hybridDecrypt(
    encryptedAesKeyB64: string,
    ivB64: string,
    authTagB64: string,
    ciphertextB64: string,
    privateKeyPem: string,
    passphrase?: string
): string {
    const aesKey = privateDecrypt(
        {
            key: loadPrivateKey(privateKeyPem, passphrase),
            padding: constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256',
        },
        fromBase64(encryptedAesKeyB64)
    );
    if (aesKey.length !== AES_KEY_LEN) {
        throw new CryptServiceError('Decrypted AES key length mismatch');
    }
    const iv = fromBase64(ivB64);
    const authTag = fromBase64(authTagB64);
    const ciphertext = fromBase64(ciphertextB64);
    const decipher = createDecipheriv('aes-256-gcm', aesKey, iv);
    decipher.setAuthTag(authTag);
    const dec = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return dec.toString('utf8');
}

export interface SymmetricEncResult {
    iv: string;
    authTag: string;
    ciphertext: string;
    key: string;
}

/** If keyB64 omitted, generates a random 32-byte key (returned in response only for demos). */
export function symmetricEncrypt(plaintextUtf8: string, keyB64?: string): SymmetricEncResult {
    const key = keyB64 ? fromBase64(keyB64) : randomBytes(AES_KEY_LEN);
    if (key.length !== AES_KEY_LEN) {
        throw new CryptServiceError('AES key must be 32 bytes (base64-encoded)');
    }
    const iv = randomBytes(GCM_IV_LEN);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    const enc = Buffer.concat([cipher.update(plaintextUtf8, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return {
        iv: toBase64(iv),
        authTag: toBase64(authTag),
        ciphertext: toBase64(enc),
        key: toBase64(key),
    };
}

export function symmetricDecrypt(ivB64: string, authTagB64: string, ciphertextB64: string, keyB64: string): string {
    const key = fromBase64(keyB64);
    if (key.length !== AES_KEY_LEN) {
        throw new CryptServiceError('AES key must be 32 bytes (base64-encoded)');
    }
    const iv = fromBase64(ivB64);
    const authTag = fromBase64(authTagB64);
    const ciphertext = fromBase64(ciphertextB64);
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}

export function pbkdf2Derive(password: string, saltB64?: string, iterations = 310000) {
    const salt = saltB64 ? fromBase64(saltB64) : randomBytes(16);
    const key = pbkdf2Sync(password, salt, iterations, AES_KEY_LEN, 'sha256');
    return {
        algorithm: 'PBKDF2-HMAC-SHA256',
        iterations,
        salt: toBase64(salt),
        derivedKey: toBase64(key),
    };
}

export function sha256Digest(data: string, input: 'utf8' | 'base64' = 'utf8'): string {
    const buf = input === 'base64' ? fromBase64(data) : Buffer.from(data, 'utf8');
    return createHash('sha256').update(buf).digest('hex');
}

export type CombineMode = 'concat-sha256' | 'hmac-sha256';

export function combineHashes(
    hashAHex: string,
    hashBHex: string,
    mode: CombineMode,
    hmacSecretB64?: string
) {
    const norm = (h: string) => h.trim().toLowerCase().replace(/^0x/, '');
    const a = norm(hashAHex);
    const b = norm(hashBHex);
    if (!/^[0-9a-f]{64}$/.test(a) || !/^[0-9a-f]{64}$/.test(b)) {
        throw new CryptServiceError('Each hash must be 64 hex chars (SHA-256)');
    }
    if (mode === 'concat-sha256') {
        const buf = Buffer.concat([Buffer.from(a + '|' + b, 'utf8')]);
        return { mode, combined: createHash('sha256').update(buf).digest('hex') };
    }
    if (!hmacSecretB64) {
        throw new CryptServiceError('hmac-sha256 mode requires hmacSecret (base64)');
    }
    const secret = fromBase64(hmacSecretB64);
    const h = createHmac('sha256', secret);
    h.update(a, 'utf8');
    h.update('|', 'utf8');
    h.update(b, 'utf8');
    return { mode, combined: h.digest('hex') };
}

export function hmacSign(dataUtf8: string, secretB64: string): string {
    const s = fromBase64(secretB64);
    return createHmac('sha256', s).update(dataUtf8, 'utf8').digest('hex');
}

export function hmacVerify(dataUtf8: string, signatureHex: string, secretB64: string): boolean {
    const expected = hmacSign(dataUtf8, secretB64);
    try {
        return timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(signatureHex.trim().toLowerCase(), 'hex'));
    } catch {
        return false;
    }
}

export function createSignedToken(
    payload: Record<string, unknown>,
    secretUtf8: string,
    expiresInSeconds?: number
): string {
    const iat = Math.floor(Date.now() / 1000);
    const body: Record<string, unknown> = { ...payload, iat };
    if (expiresInSeconds !== undefined && expiresInSeconds > 0) {
        body.exp = iat + expiresInSeconds;
    }
    const header = { alg: 'HS256', typ: 'APICRPT' };
    const p1 = base64UrlEncode(JSON.stringify(header));
    const p2 = base64UrlEncode(JSON.stringify(body));
    const signingInput = `${p1}.${p2}`;
    const sig = createHmac('sha256', Buffer.from(secretUtf8, 'utf8'))
        .update(signingInput, 'utf8')
        .digest();
    const p3 = base64UrlEncode(sig);
    return `${signingInput}.${p3}`;
}

export function verifySignedToken(token: string, secretUtf8: string): Record<string, unknown> {
    const parts = token.split('.');
    if (parts.length !== 3) throw new CryptServiceError('Invalid token format');
    const [p1, p2, p3] = parts;
    const signingInput = `${p1}.${p2}`;
    const expected = createHmac('sha256', Buffer.from(secretUtf8, 'utf8'))
        .update(signingInput, 'utf8')
        .digest();
    const got = base64UrlDecode(p3);
    if (expected.length !== got.length || !timingSafeEqual(expected, got)) {
        throw new CryptServiceError('Invalid token signature');
    }
    const payload = JSON.parse(base64UrlDecode(p2).toString('utf8')) as Record<string, unknown>;
    const exp = payload.exp;
    if (typeof exp === 'number' && exp < Math.floor(Date.now() / 1000)) {
        throw new CryptServiceError('Token expired');
    }
    return payload;
}

export interface SealedBlob {
    v: 1;
    salt: string;
    iv: string;
    authTag: string;
    ciphertext: string;
}

export function sealPayload(
    data: Record<string, unknown>,
    secretUtf8: string,
    ttlSeconds: number
): SealedBlob {
    if (ttlSeconds <= 0 || ttlSeconds > 86400 * 365) {
        throw new CryptServiceError('ttlSeconds must be between 1 and 31536000');
    }
    const salt = randomBytes(16);
    const ikm = Buffer.from(secretUtf8, 'utf8');
    const key = Buffer.from(hkdfSync('sha256', ikm, salt, HKDF_INFO, AES_KEY_LEN));
    const exp = Math.floor(Date.now() / 1000) + ttlSeconds;
    const inner = JSON.stringify({ exp, data });
    const iv = randomBytes(GCM_IV_LEN);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    const enc = Buffer.concat([cipher.update(inner, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return {
        v: 1,
        salt: toBase64(salt),
        iv: toBase64(iv),
        authTag: toBase64(authTag),
        ciphertext: toBase64(enc),
    };
}

export function unsealPayload(blob: SealedBlob, secretUtf8: string): Record<string, unknown> {
    if (blob.v !== 1) throw new CryptServiceError('Unsupported sealed blob version');
    const salt = fromBase64(blob.salt);
    const ikm = Buffer.from(secretUtf8, 'utf8');
    const key = Buffer.from(hkdfSync('sha256', ikm, salt, HKDF_INFO, AES_KEY_LEN));
    const iv = fromBase64(blob.iv);
    const authTag = fromBase64(blob.authTag);
    const ciphertext = fromBase64(blob.ciphertext);
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
    const parsed = JSON.parse(plain) as { exp: number; data: Record<string, unknown> };
    if (typeof parsed.exp !== 'number' || parsed.exp < Math.floor(Date.now() / 1000)) {
        throw new CryptServiceError('Sealed payload expired');
    }
    return parsed.data;
}

export function getRandomBytes(length: number): Buffer {
    if (length < 1 || length > 4096) {
        throw new CryptServiceError('length must be 1–4096');
    }
    return randomBytes(length);
}

export function getRandomUuid(): string {
    return randomUUID();
}

export type SignAlg = 'RSA-SHA256' | 'ECDSA-SHA256';

export function signData(dataB64: string, privateKeyPem: string, passphrase: string | undefined, alg: SignAlg): string {
    const key = loadPrivateKey(privateKeyPem, passphrase);
    const data = fromBase64(dataB64);
    const hashAlg = 'sha256';
    const s = sign(hashAlg, data, key);
    return toBase64(s);
}

export function verifySignature(
    dataB64: string,
    signatureB64: string,
    publicKeyPem: string,
    alg: SignAlg
): boolean {
    const key = loadPublicKey(publicKeyPem);
    const data = fromBase64(dataB64);
    const sig = fromBase64(signatureB64);
    try {
        return verify('sha256', data, key, sig);
    } catch {
        return false;
    }
}

export function publicKeyFingerprint(publicKeyPem: string): string {
    const key = loadPublicKey(publicKeyPem);
    const spki = key.export({ format: 'der', type: 'spki' }) as Buffer;
    return createHash('sha256').update(spki).digest('hex');
}

export function timingSafeCompareHex(aHex: string, bHex: string): boolean {
    try {
        const a = Buffer.from(aHex.trim().toLowerCase(), 'hex');
        const b = Buffer.from(bHex.trim().toLowerCase(), 'hex');
        if (a.length !== b.length) return false;
        return timingSafeEqual(a, b);
    } catch {
        return false;
    }
}
