import { NodeCryptoAdapter } from '../adapters/node-crypto.adapter';
import { FileSystemManagedKeyRepository } from '../repositories/file-system-managed-key.repository';
import { KeyVaultService } from '../crypto/key-vault';
import { ManagedKeyDomainService } from '../../core/application/services/managed-key-domain.service';
import { CreateManagedKeyUseCase } from '../../core/application/use-cases/managed/create-managed-key.usecase';
import { ListManagedKeysUseCase } from '../../core/application/use-cases/managed/list-managed-keys.usecase';
import { GetManagedPublicKeyUseCase } from '../../core/application/use-cases/managed/get-managed-public-key.usecase';
import { RotateManagedKeyUseCase } from '../../core/application/use-cases/managed/rotate-managed-key.usecase';
import { DisableManagedKeyUseCase } from '../../core/application/use-cases/managed/disable-managed-key.usecase';
import { ManagedHybridEncryptUseCase } from '../../core/application/use-cases/managed/managed-hybrid-encrypt.usecase';
import { ManagedHybridDecryptUseCase } from '../../core/application/use-cases/managed/managed-hybrid-decrypt.usecase';
import { ManagedSignDataUseCase } from '../../core/application/use-cases/managed/managed-sign-data.usecase';
import { ManagedVerifySignatureUseCase } from '../../core/application/use-cases/managed/managed-verify-signature.usecase';
import { SetRotationPolicyUseCase } from '../../core/application/use-cases/managed/set-rotation-policy.usecase';
import { CheckPendingRotationsUseCase } from '../../core/application/use-cases/managed/check-pending-rotations.usecase';
import { ManagedUseCases } from '../../core/application/use-cases/managed/managed-use-cases';
import { CryptoController } from '../../interfaces/http/controllers/crypto.controller';
import { ManagedKeysController } from '../../interfaces/http/controllers/managed-keys.controller';
import { ManagedCryptoController } from '../../interfaces/http/controllers/managed-crypto.controller';
import { RotationScheduler } from '../scheduler/rotation-scheduler';
import { updateKeyStoreMetrics } from '../../libs/middlewares/metrics.middleware';
import { getConfiguredApiKey } from '../../libs/middlewares/security.middlewares';

// ── Master Key ──────────────────────────────────────────────────────────────

function getMasterKey(): Buffer {
    const hex = process.env.MASTER_KEY?.trim();
    if (!hex) {
        if (process.env.NODE_ENV === 'production') {
            throw new Error(
                '[api-crypt] FATAL: MASTER_KEY environment variable is required in production.\n' +
                'Generate one with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"'
            );
        }
        console.warn(
            '\n⚠️  [api-crypt] WARNING: MASTER_KEY is not set.\n' +
            '   Using an insecure all-zero development key.\n' +
            '   Private keys stored on disk are NOT securely encrypted.\n' +
            '   Set MASTER_KEY in your .env file before any production use.\n'
        );
        return Buffer.alloc(32, 0);
    }
    const key = Buffer.from(hex, 'hex');
    if (key.length !== 32) {
        throw new Error(
            `[api-crypt] MASTER_KEY must be exactly 64 hex characters (32 bytes). Got ${hex.length} chars.\n` +
            'Generate one with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"'
        );
    }
    return key;
}

// ── Singleton Controllers ────────────────────────────────────────────────────

export interface CryptoControllers {
    managedKeys: ManagedKeysController;
    managedCrypto: ManagedCryptoController;
    legacy: CryptoController;
}

let controllersSingleton: CryptoControllers | undefined;
let schedulerSingleton: RotationScheduler | undefined;

export function getCryptoControllers(): CryptoControllers {
    if (!controllersSingleton) {
        getConfiguredApiKey(); // ← fail-fast: exits if API_KEY not set in non-dev envs
        const masterKey = getMasterKey();
        const dbPath = process.env.KEYS_DB_PATH ?? 'keys.db.json';

        const cryptoProvider = new NodeCryptoAdapter();
        const keyVault = new KeyVaultService(masterKey);
        const keyRepo = new FileSystemManagedKeyRepository(dbPath);
        const managedDomain = new ManagedKeyDomainService(cryptoProvider, keyRepo);

        const setRotationPolicy = new SetRotationPolicyUseCase(keyRepo, managedDomain);
        const checkPendingRotations = new CheckPendingRotationsUseCase(keyRepo, managedDomain);

        const managedUseCases: ManagedUseCases = {
            createManagedKey: new CreateManagedKeyUseCase(cryptoProvider, keyRepo, managedDomain, keyVault),
            listManagedKeys: new ListManagedKeysUseCase(keyRepo, managedDomain),
            getManagedPublicKey: new GetManagedPublicKeyUseCase(managedDomain),
            rotateManagedKey: new RotateManagedKeyUseCase(cryptoProvider, keyRepo, managedDomain, keyVault),
            disableManagedKey: new DisableManagedKeyUseCase(keyRepo, managedDomain),
            managedHybridEncrypt: new ManagedHybridEncryptUseCase(cryptoProvider, managedDomain),
            managedHybridDecrypt: new ManagedHybridDecryptUseCase(cryptoProvider, managedDomain, keyVault),
            managedSignData: new ManagedSignDataUseCase(cryptoProvider, managedDomain, keyVault),
            managedVerifySignature: new ManagedVerifySignatureUseCase(cryptoProvider, managedDomain),
            setRotationPolicy,
            checkPendingRotations,
        };

        const legacyRoutesDisabled =
            (process.env.DISABLE_LEGACY_CRYPTO_ROUTES ?? (process.env.NODE_ENV === 'production' ? 'true' : 'false')) === 'true';

        controllersSingleton = {
            managedKeys: new ManagedKeysController(managedUseCases),
            managedCrypto: new ManagedCryptoController(managedUseCases),
            legacy: new CryptoController(cryptoProvider, managedUseCases, legacyRoutesDisabled),
        };

        // ── Scheduler de rotación automática ──────────────────────────────────
        schedulerSingleton = new RotationScheduler(keyRepo, cryptoProvider, keyVault, managedDomain);
        schedulerSingleton.start();

        // ── Métricas periódicas del key store (cada 30s) ────────────────────
        const metricsTimer = setInterval(async () => {
            const all = await keyRepo.list();
            const active = all.filter((k) => k.status === 'active').length;
            const disabled = all.filter((k) => k.status === 'disabled').length;
            const pending = (await checkPendingRotations.execute(7)).length;
            updateKeyStoreMetrics(active, disabled, pending);
        }, 30_000);
        if (metricsTimer.unref) metricsTimer.unref();
    }
    return controllersSingleton;
}

export function getScheduler(): RotationScheduler | undefined {
    return schedulerSingleton;
}
