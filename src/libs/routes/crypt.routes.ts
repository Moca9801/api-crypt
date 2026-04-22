import { Router } from 'express';
import { cryptoRateLimit, requireApiKey } from '../middlewares/security.middlewares';
import { getCryptoControllers } from '../../infrastructure/container/crypto.container';
import { validate } from '../../interfaces/http/middleware/validate.middleware';

// Schemas
import { CreateKeySchema, RotateKeySchema, SetRotationPolicySchema } from '../../interfaces/http/schemas/managed-keys.schemas';
import { HybridDecryptSchema, HybridEncryptSchema, SignDataSchema, VerifySignatureSchema } from '../../interfaces/http/schemas/managed-crypto.schemas';
import {
    HashCombineSchema, HashSha256Schema, HmacSignSchema, HmacVerifySchema,
    HybridDecryptStatelessSchema, HybridEncryptStatelessSchema, KeyFingerprintSchema,
    KeyGenSchema, Pbkdf2Schema, SealedCreateSchema, SealedOpenSchema,
    SignDataStatelessSchema, SignVerifyStatelessSchema, SymmetricDecryptSchema,
    SymmetricEncryptSchema, TimingSafeEqualSchema, TokenCreateSchema, TokenVerifySchema
} from '../../interfaces/http/schemas/stateless.schemas';

const router = Router();
router.use(requireApiKey);
router.use(cryptoRateLimit);

const controllers = getCryptoControllers();

// ── Managed key lifecycle ─────────────────────────────────────────────────────
router.post('/keys/managed/create', validate(CreateKeySchema), controllers.managedKeys.createManagedKey);
router.get('/keys/managed', controllers.managedKeys.listManagedKeys);
router.get('/keys/managed/:keyId/public', controllers.managedKeys.getManagedPublicKey);
router.post('/keys/managed/:keyId/rotate', validate(RotateKeySchema), controllers.managedKeys.rotateManagedKey);
router.post('/keys/managed/:keyId/disable', controllers.managedKeys.disableManagedKey);

// ── Rotation policy ────────────────────────────────────────────────────────────
router.post('/keys/managed/:keyId/policy', validate(SetRotationPolicySchema), controllers.managedKeys.setRotationPolicy);
router.delete('/keys/managed/:keyId/policy', controllers.managedKeys.deleteRotationPolicy);
router.get('/keys/managed/rotation/pending', controllers.managedKeys.checkPendingRotations);

// ── Managed crypto operations ─────────────────────────────────────────────────
router.post('/managed/hybrid/encrypt', validate(HybridEncryptSchema), controllers.managedCrypto.managedHybridEncrypt);
router.post('/managed/hybrid/decrypt', validate(HybridDecryptSchema), controllers.managedCrypto.managedHybridDecrypt);
router.post('/managed/sign/data', validate(SignDataSchema), controllers.managedCrypto.managedSignData);
router.post('/managed/sign/verify', validate(VerifySignatureSchema), controllers.managedCrypto.managedSignVerify);

// ── Legacy stateless routes (disabled in production by default) ───────────────
router.post('/keys/generate', validate(KeyGenSchema), controllers.legacy.keysGenerate);
router.post('/keys/fingerprint', validate(KeyFingerprintSchema), controllers.legacy.keyFingerprint);
router.post('/hybrid/encrypt', validate(HybridEncryptStatelessSchema), controllers.legacy.hybridEncrypt);
router.post('/hybrid/decrypt', validate(HybridDecryptStatelessSchema), controllers.legacy.hybridDecrypt);
router.post('/symmetric/encrypt', validate(SymmetricEncryptSchema), controllers.legacy.symmetricEncrypt);
router.post('/symmetric/decrypt', validate(SymmetricDecryptSchema), controllers.legacy.symmetricDecrypt);
router.post('/kdf/pbkdf2', validate(Pbkdf2Schema), controllers.legacy.pbkdf2);
router.post('/hash/sha256', validate(HashSha256Schema), controllers.legacy.hashSha256);
router.post('/hash/combine', validate(HashCombineSchema), controllers.legacy.hashCombine);
router.post('/hmac/sign', validate(HmacSignSchema), controllers.legacy.hmacSign);
router.post('/hmac/verify', validate(HmacVerifySchema), controllers.legacy.hmacVerify);
router.post('/tokens/signed/create', validate(TokenCreateSchema), controllers.legacy.tokenCreate);
router.post('/tokens/signed/verify', validate(TokenVerifySchema), controllers.legacy.tokenVerify);
router.post('/sealed/create', validate(SealedCreateSchema), controllers.legacy.sealedCreate);
router.post('/sealed/open', validate(SealedOpenSchema), controllers.legacy.sealedOpen);
router.get('/random/bytes', controllers.legacy.randomBytes); // no body
router.get('/random/uuid', controllers.legacy.randomUuid);   // no body
router.post('/sign/data', validate(SignDataStatelessSchema), controllers.legacy.signData);
router.post('/sign/verify', validate(SignVerifyStatelessSchema), controllers.legacy.signVerify);
router.post('/utils/timing-safe-equal', validate(TimingSafeEqualSchema), controllers.legacy.timingSafeEqual);

export default router;
