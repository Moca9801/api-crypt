import { z } from 'zod';

const RotationPolicySchema = z.object({
    ttlDays: z.number().int().min(1).max(3650),
    onExpiry: z.enum(['disable', 'keep']).default('disable'),
});

export const CreateKeySchema = z.object({
    type: z.enum(['rsa', 'ec']),
    keyId: z.string().min(1).max(128).optional(),
    passphrase: z.string().min(8).max(256).optional(),
    modulusLength: z.union([z.literal(2048), z.literal(3072), z.literal(4096)]).optional(),
    namedCurve: z.enum(['prime256v1', 'secp384r1']).optional(),
    rotationPolicy: RotationPolicySchema.optional(),
});

export const RotateKeySchema = z.object({
    passphrase: z.string().min(8).max(256).optional(),
    modulusLength: z.union([z.literal(2048), z.literal(3072), z.literal(4096)]).optional(),
    namedCurve: z.enum(['prime256v1', 'secp384r1']).optional(),
}).default({});

export const SetRotationPolicySchema = z.object({
    ttlDays: z.number().int().min(1, 'ttlDays must be >= 1').max(3650, 'ttlDays must be <= 3650'),
    onExpiry: z.enum(['disable', 'keep']).default('disable'),
});

export type CreateKeyInput = z.infer<typeof CreateKeySchema>;
export type RotateKeyInput = z.infer<typeof RotateKeySchema>;
export type SetRotationPolicyInput = z.infer<typeof SetRotationPolicySchema>;
