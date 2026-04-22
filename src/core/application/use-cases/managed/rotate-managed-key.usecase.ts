import { ManagedKey } from '../../../domain/managed-key';
import { CryptoProviderPort } from '../../ports/crypto-provider.port';
import { ManagedKeyRepositoryPort } from '../../ports/managed-key-repository.port';
import { KeyVaultPort } from '../../ports/key-vault.port';
import { ManagedKeyDomainService } from '../../services/managed-key-domain.service';
import { auditLog } from '../../../../infrastructure/audit/audit-logger';

export class RotateManagedKeyUseCase {
    constructor(
        private readonly cryptoProvider: CryptoProviderPort,
        private readonly managedKeyRepo: ManagedKeyRepositoryPort,
        private readonly managedDomain: ManagedKeyDomainService,
        private readonly keyVault: KeyVaultPort
    ) {}

    async execute(keyId: string, opts?: { passphrase?: string; modulusLength?: 2048 | 3072 | 4096; namedCurve?: 'prime256v1' | 'secp384r1' }, clientIp = 'system') {
        const key = await this.managedDomain.getActiveOrThrow(keyId);

        const originalParams = this.managedDomain.getOriginalAlgorithmParams(key);
        const generated = this.cryptoProvider.generateKeyPair(
            key.type === 'rsa'
                ? { type: 'rsa', modulusLength: opts?.modulusLength ?? originalParams.modulusLength, passphrase: opts?.passphrase }
                : { type: 'ec', namedCurve: opts?.namedCurve ?? originalParams.namedCurve, passphrase: opts?.passphrase }
        );

        const nextRotationAt = key.rotationPolicy
            ? this.managedDomain.computeNextRotationAt(key.rotationPolicy.ttlDays)
            : key.nextRotationAt;

        const rotated: ManagedKey = {
            ...key,
            algorithm: generated.algorithm,
            publicKey: generated.publicKey,
            encryptedPrivateKey: this.keyVault.encrypt(generated.privateKey),
            passphraseProtected: typeof opts?.passphrase === 'string',
            rotatedAt: new Date().toISOString(),
            nextRotationAt,
        };

        await this.managedKeyRepo.save(rotated);
        auditLog({ event: 'key.rotated', keyId, ip: clientIp });

        return { keyId: rotated.keyId, publicKey: rotated.publicKey, metadata: this.managedDomain.toMetadata(rotated) };
    }
}
