import { z } from 'zod';

const SignAlgSchema = z.enum(['RSA-SHA256', 'ECDSA-SHA256']).default('RSA-SHA256');
const InputEncodingSchema = z.enum(['utf8', 'base64']).default('utf8');

export const KeyGenSchema = z.object({
    type: z.enum(['rsa', 'ec']),
    passphrase: z.string().min(8).max(256).optional(),
    modulusLength: z.union([z.literal(2048), z.literal(3072), z.literal(4096)]).optional(),
    namedCurve: z.enum(['prime256v1', 'secp384r1']).optional(),
});

export const KeyFingerprintSchema = z.object({
    publicKeyPem: z.string().min(1),
});

export const HybridEncryptStatelessSchema = z.object({
    plaintext: z.string().min(1),
    publicKeyPem: z.string().min(1),
});

export const HybridDecryptStatelessSchema = z.object({
    encryptedAesKey: z.string().min(1),
    iv: z.string().min(1),
    authTag: z.string().min(1),
    ciphertext: z.string().min(1),
    privateKeyPem: z.string().min(1),
    passphrase: z.string().optional(),
});

export const SymmetricEncryptSchema = z.object({
    plaintext: z.string().min(1),
    key: z.string().optional(),
});

export const SymmetricDecryptSchema = z.object({
    iv: z.string().min(1),
    authTag: z.string().min(1),
    ciphertext: z.string().min(1),
    key: z.string().min(1),
});

export const Pbkdf2Schema = z.object({
    password: z.string().min(1),
    salt: z.string().optional(),
    iterations: z.number().int().positive().optional(),
});

export const HashSha256Schema = z.object({
    data: z.string().min(1),
    inputEncoding: InputEncodingSchema,
});

export const HashCombineSchema = z.object({
    hashA: z.string().refine((s) => s.length === 64, 'hashA must be a 64-char hex SHA-256'),
    hashB: z.string().refine((s) => s.length === 64, 'hashB must be a 64-char hex SHA-256'),
    mode: z.enum(['concat-sha256', 'hmac-sha256']),
    hmacSecret: z.string().optional(),
});

export const HmacSignSchema = z.object({
    data: z.string().min(1),
    secret: z.string().min(1),
});

export const HmacVerifySchema = z.object({
    data: z.string().min(1),
    secret: z.string().min(1),
    signatureHex: z.string().min(1),
});

export const TokenCreateSchema = z.object({
    payload: z.record(z.unknown()),
    secret: z.string().min(1),
    expiresInSeconds: z.number().int().positive().optional(),
});

export const TokenVerifySchema = z.object({
    token: z.string().min(1),
    secret: z.string().min(1),
});

export const SealedCreateSchema = z.object({
    data: z.record(z.unknown()),
    secret: z.string().min(1),
    ttlSeconds: z.number().int().positive(),
});

export const SealedOpenSchema = z.object({
    sealed: z.object({
        iv: z.string(),
        authTag: z.string(),
        ciphertext: z.string(),
        expiresAt: z.number(),
        nonce: z.string(),
    }),
    secret: z.string().min(1),
});

export const SignDataStatelessSchema = z.object({
    dataBase64: z.string().min(1),
    privateKeyPem: z.string().min(1),
    passphrase: z.string().optional(),
    algorithm: SignAlgSchema,
});

export const SignVerifyStatelessSchema = z.object({
    dataBase64: z.string().min(1),
    signatureBase64: z.string().min(1),
    publicKeyPem: z.string().min(1),
    algorithm: SignAlgSchema,
});

export const TimingSafeEqualSchema = z.object({
    aHex: z.string().min(1),
    bHex: z.string().min(1),
});
