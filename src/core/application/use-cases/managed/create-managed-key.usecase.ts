import { randomUUID } from 'crypto';
import { ManagedKey } from '../../../domain/managed-key';
import { CryptoProviderPort } from '../../ports/crypto-provider.port';
import { ManagedKeyRepositoryPort } from '../../ports/managed-key-repository.port';
import { KeyVaultPort } from '../../ports/key-vault.port';
import { ManagedKeyDomainService } from '../../services/managed-key-domain.service';
import { CreateManagedKeyInput } from '../../../domain/managed-key';
import { auditLog } from '../../../../infrastructure/audit/audit-logger';

export class CreateManagedKeyUseCase {
    constructor(
        private readonly cryptoProvider: CryptoProviderPort,
        private readonly managedKeyRepo: ManagedKeyRepositoryPort,
        private readonly managedDomain: ManagedKeyDomainService,
        private readonly keyVault: KeyVaultPort
    ) {}

    async execute(input: CreateManagedKeyInput, clientIp = 'system') {
        const generated = this.cryptoProvider.generateKeyPair(
            input.type === 'rsa'
                ? { type: 'rsa', modulusLength: input.modulusLength ?? 2048, passphrase: input.passphrase }
                : { type: 'ec', namedCurve: input.namedCurve ?? 'prime256v1', passphrase: input.passphrase }
        );

        const nextRotationAt = input.rotationPolicy
            ? this.managedDomain.computeNextRotationAt(input.rotationPolicy.ttlDays)
            : undefined;

        const key: ManagedKey = {
            keyId: input.keyId ?? randomUUID(),
            type: input.type,
            algorithm: generated.algorithm,
            status: 'active',
            publicKey: generated.publicKey,
            encryptedPrivateKey: this.keyVault.encrypt(generated.privateKey),
            passphraseProtected: typeof input.passphrase === 'string',
            createdAt: new Date().toISOString(),
            rotationPolicy: input.rotationPolicy,
            nextRotationAt,
        };

        await this.managedKeyRepo.save(key);
        auditLog({ event: 'key.created', keyId: key.keyId, type: key.type, ip: clientIp });

        return { keyId: key.keyId, publicKey: key.publicKey, metadata: this.managedDomain.toMetadata(key) };
    }
}
