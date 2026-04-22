import { CryptServiceError, SignAlg } from '../../../libs/services/crypt.service';
import { ManagedKey, ManagedKeyMetadata } from '../../domain/managed-key';
import { CryptoProviderPort } from '../ports/crypto-provider.port';
import { ManagedKeyRepositoryPort } from '../ports/managed-key-repository.port';

export class ManagedKeyDomainService {
    constructor(
        private readonly cryptoProvider: CryptoProviderPort,
        private readonly managedKeyRepo: ManagedKeyRepositoryPort
    ) {}

    toMetadata(key: ManagedKey): ManagedKeyMetadata {
        let daysUntilRotation: number | undefined;
        if (key.nextRotationAt) {
            const msLeft = new Date(key.nextRotationAt).getTime() - Date.now();
            daysUntilRotation = Math.max(0, Math.ceil(msLeft / 86_400_000));
        }
        return {
            keyId: key.keyId,
            type: key.type,
            algorithm: key.algorithm,
            status: key.status,
            passphraseProtected: key.passphraseProtected,
            createdAt: key.createdAt,
            rotatedAt: key.rotatedAt,
            rotationPolicy: key.rotationPolicy,
            nextRotationAt: key.nextRotationAt,
            daysUntilRotation,
            fingerprintSha256Hex: this.cryptoProvider.publicKeyFingerprint(key.publicKey),
        };
    }

    async getOrThrow(keyId: string): Promise<ManagedKey> {
        const key = await this.managedKeyRepo.getById(keyId);
        if (!key) throw new CryptServiceError(`Unknown keyId: ${keyId}`, 'KEY_NOT_FOUND');
        return key;
    }

    async getActiveOrThrow(keyId: string): Promise<ManagedKey> {
        const key = await this.getOrThrow(keyId);
        if (key.status !== 'active') throw new CryptServiceError(`Key ${keyId} is disabled`, 'KEY_DISABLED');
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

    computeNextRotationAt(ttlDays: number, fromDate = new Date()): string {
        return new Date(fromDate.getTime() + ttlDays * 86_400_000).toISOString();
    }

    getOriginalAlgorithmParams(key: ManagedKey): { type: 'rsa' | 'ec'; modulusLength?: 2048 | 3072 | 4096; namedCurve?: 'prime256v1' | 'secp384r1' } {
        if (key.type === 'rsa') {
            const parts = key.algorithm.split('-');
            const len = parts.length > 1 ? parseInt(parts[1], 10) : 2048;
            const validLens = [2048, 3072, 4096];
            return { type: 'rsa', modulusLength: validLens.includes(len) ? (len as 2048 | 3072 | 4096) : 2048 };
        }
        if (key.type === 'ec') {
            const parts = key.algorithm.split('-');
            const curve = parts.length > 1 ? parts[1] : 'prime256v1';
            return { type: 'ec', namedCurve: curve === 'secp384r1' ? 'secp384r1' : 'prime256v1' };
        }
        // Fallback for unknown types
        return { type: 'rsa', modulusLength: 2048 };
    }
}
