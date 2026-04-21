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
import { ManagedUseCases } from '../../core/application/use-cases/managed/managed-use-cases';
import { CryptoController } from '../../interfaces/http/controllers/crypto.controller';

// ── Master Key ──────────────────────────────────────────────────────────────

/**
 * Reads the MASTER_KEY env var and returns a 32-byte Buffer.
 * In production, the key MUST be set. In development, a zero-byte key is used
 * with a loud console warning.
 *
 * Generate a secure key with:
 *   node -e "require('crypto').randomBytes(32).toString('hex') |> console.log"
 *   // or
 *   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
 */
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
        return Buffer.alloc(32, 0); // all-zero: obviously insecure, only for dev
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

// ── Singleton Controller ─────────────────────────────────────────────────────

let controllerSingleton: CryptoController | undefined;

export function getCryptoController(): CryptoController {
    if (!controllerSingleton) {
        const masterKey = getMasterKey();
        const dbPath = process.env.KEYS_DB_PATH ?? 'keys.db.json';

        const cryptoProvider = new NodeCryptoAdapter();
        const keyVault = new KeyVaultService(masterKey);
        const keyRepo = new FileSystemManagedKeyRepository(dbPath);
        const managedDomain = new ManagedKeyDomainService(cryptoProvider, keyRepo);

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
        };

        const legacyRoutesDisabled =
            (process.env.DISABLE_LEGACY_CRYPTO_ROUTES ?? (process.env.NODE_ENV === 'production' ? 'true' : 'false')) === 'true';

        controllerSingleton = new CryptoController(cryptoProvider, managedUseCases, legacyRoutesDisabled);
    }
    return controllerSingleton;
}
