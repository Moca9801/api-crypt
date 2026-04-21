import { Router } from 'express';
import { cryptoRateLimit, requireApiKey } from '../middlewares/security.middlewares';
import { getCryptoController } from '../../infrastructure/container/crypto.container';

const router = Router();
router.use(requireApiKey);
router.use(cryptoRateLimit);
const controller = getCryptoController();

router.post('/keys/managed/create', controller.createManagedKey);
router.get('/keys/managed', controller.listManagedKeys);
router.get('/keys/managed/:keyId/public', controller.getManagedPublicKey);
router.post('/keys/managed/:keyId/rotate', controller.rotateManagedKey);
router.post('/keys/managed/:keyId/disable', controller.disableManagedKey);
router.post('/managed/hybrid/encrypt', controller.managedHybridEncrypt);
router.post('/managed/hybrid/decrypt', controller.managedHybridDecrypt);
router.post('/managed/sign/data', controller.managedSignData);
router.post('/managed/sign/verify', controller.managedSignVerify);

router.post('/keys/generate', controller.keysGenerate);
router.post('/keys/fingerprint', controller.keyFingerprint);
router.post('/hybrid/encrypt', controller.hybridEncrypt);
router.post('/hybrid/decrypt', controller.hybridDecrypt);
router.post('/symmetric/encrypt', controller.symmetricEncrypt);
router.post('/symmetric/decrypt', controller.symmetricDecrypt);
router.post('/kdf/pbkdf2', controller.pbkdf2);
router.post('/hash/sha256', controller.hashSha256);
router.post('/hash/combine', controller.hashCombine);
router.post('/hmac/sign', controller.hmacSign);
router.post('/hmac/verify', controller.hmacVerify);
router.post('/tokens/signed/create', controller.tokenCreate);
router.post('/tokens/signed/verify', controller.tokenVerify);
router.post('/sealed/create', controller.sealedCreate);
router.post('/sealed/open', controller.sealedOpen);
router.get('/random/bytes', controller.randomBytes);
router.get('/random/uuid', controller.randomUuid);
router.post('/sign/data', controller.signData);
router.post('/sign/verify', controller.signVerify);
router.post('/utils/timing-safe-equal', controller.timingSafeEqual);

export default router;
