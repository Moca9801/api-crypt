import { CryptServiceError, SignAlg } from '../../../libs/services/crypt.service';
import { ManagedKey, ManagedKeyMetadata } from '../../domain/managed-key';
import { CryptoProviderPort } from '../ports/crypto-provider.port';
import { ManagedKeyRepositoryPort } from '../ports/managed-key-repository.port';

/**
 * Domain service for managed key business rules.
 * Shared across multiple use cases — keeps domain logic DRY.
 */
export class ManagedKeyDomainService {
    constructor(
        private readonly cryptoProvider: CryptoProviderPort,
        private readonly managedKeyRepo: ManagedKeyRepositoryPort
    ) {}

    toMetadata(key: ManagedKey): ManagedKeyMetadata {
        return {
            keyId: key.keyId,
            type: key.type,
            algorithm: key.algorithm,
            status: key.status,
            passphraseProtected: key.passphraseProtected,
            createdAt: key.createdAt,
            rotatedAt: key.rotatedAt,
            fingerprintSha256Hex: this.cryptoProvider.publicKeyFingerprint(key.publicKey),
        };
    }

    getOrThrow(keyId: string): ManagedKey {
        const key = this.managedKeyRepo.getById(keyId);
        if (!key) {
            throw new CryptServiceError(`Unknown keyId: ${keyId}`, 'KEY_NOT_FOUND');
        }
        return key;
    }

    getActiveOrThrow(keyId: string): ManagedKey {
        const key = this.getOrThrow(keyId);
        if (key.status !== 'active') {
            throw new CryptServiceError(`Key ${keyId} is disabled`, 'KEY_DISABLED');
        }
        return key;
    }

    assertSignAlgorithm(key: ManagedKey, algorithm: SignAlg): void {
        const expected: SignAlg = key.type === 'rsa' ? 'RSA-SHA256' : 'ECDSA-SHA256';
        if (algorithm !== expected) {
            throw new CryptServiceError(
                `Algorithm mismatch for key ${key.keyId}. Expected ${expected}.`,
                'ALGORITHM_MISMATCH'
            );
        }
    }
}
