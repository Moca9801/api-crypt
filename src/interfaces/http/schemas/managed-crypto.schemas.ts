import { z } from 'zod';

const SignAlgSchema = z.enum(['RSA-SHA256', 'ECDSA-SHA256']).default('RSA-SHA256');

export const HybridEncryptSchema = z.object({
    keyId: z.string().min(1),
    plaintext: z.string().min(1).max(1_000_000), // 1MB limit en caracteres
});

export const HybridDecryptSchema = z.object({
    keyId: z.string().min(1),
    encryptedAesKey: z.string().min(1),
    iv: z.string().min(1),
    authTag: z.string().min(1),
    ciphertext: z.string().min(1),
    passphrase: z.string().optional(),
});

export const SignDataSchema = z.object({
    keyId: z.string().min(1),
    dataBase64: z.string().min(1),
    algorithm: SignAlgSchema,
    passphrase: z.string().optional(),
});

export const VerifySignatureSchema = z.object({
    keyId: z.string().min(1),
    dataBase64: z.string().min(1),
    signatureBase64: z.string().min(1),
    algorithm: SignAlgSchema,
});

export type HybridEncryptInput = z.infer<typeof HybridEncryptSchema>;
export type HybridDecryptInput = z.infer<typeof HybridDecryptSchema>;
export type SignDataInput = z.infer<typeof SignDataSchema>;
export type VerifySignatureInput = z.infer<typeof VerifySignatureSchema>;
