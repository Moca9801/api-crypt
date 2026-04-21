import { randomUUID } from 'crypto';
import { CryptServiceError, KeyGenOptions } from '../../../../libs/services/crypt.service';
import { CreateManagedKeyInput, ManagedKey } from '../../../domain/managed-key';
import { CryptoProviderPort } from '../../ports/crypto-provider.port';
import { ManagedKeyRepositoryPort } from '../../ports/managed-key-repository.port';
import { ManagedKeyDomainService } from '../../services/managed-key-domain.service';

export class CreateManagedKeyUseCase {
    constructor(
        private readonly cryptoProvider: CryptoProviderPort,
        private readonly managedKeyRepo: ManagedKeyRepositoryPort,
        private readonly managedDomain: ManagedKeyDomainService
    ) {}

    private buildKeyGenOptions(input: CreateManagedKeyInput): KeyGenOptions {
        if (input.type === 'rsa') {
            return { type: 'rsa', modulusLength: input.modulusLength ?? 2048, passphrase: input.passphrase };
        }
        return { type: 'ec', namedCurve: input.namedCurve ?? 'prime256v1', passphrase: input.passphrase };
    }

    execute(input: CreateManagedKeyInput) {
        const keyId = input.keyId && input.keyId.trim() ? input.keyId.trim() : randomUUID();
        if (this.managedKeyRepo.getById(keyId)) {
            throw new CryptServiceError(`keyId already exists: ${keyId}`, 'KEY_ALREADY_EXISTS');
        }
        const generated = this.cryptoProvider.generateKeyPair(this.buildKeyGenOptions(input));
        const key: ManagedKey = {
            keyId,
            type: input.type,
            algorithm: generated.algorithm,
            status: 'active',
            publicKey: generated.publicKey,
            privateKey: generated.privateKey,
            passphrase: input.passphrase,
            createdAt: new Date().toISOString(),
        };
        this.managedKeyRepo.save(key);
        return { keyId: key.keyId, publicKey: key.publicKey, metadata: this.managedDomain.toMetadata(key) };
    }
}
