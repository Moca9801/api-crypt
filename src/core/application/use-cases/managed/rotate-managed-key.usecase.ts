import { CryptoProviderPort } from '../../ports/crypto-provider.port';
import { ManagedKeyRepositoryPort } from '../../ports/managed-key-repository.port';
import { ManagedKey } from '../../../domain/managed-key';
import { ManagedKeyDomainService } from '../../services/managed-key-domain.service';

export class RotateManagedKeyUseCase {
    constructor(
        private readonly cryptoProvider: CryptoProviderPort,
        private readonly managedKeyRepo: ManagedKeyRepositoryPort,
        private readonly managedDomain: ManagedKeyDomainService
    ) {}

    execute(
        keyId: string,
        opts?: { passphrase?: string; modulusLength?: 2048 | 3072 | 4096; namedCurve?: 'prime256v1' | 'secp384r1' }
    ) {
        const current = this.managedDomain.getActiveOrThrow(keyId);
        const generated = this.cryptoProvider.generateKeyPair(
            current.type === 'rsa'
                ? { type: 'rsa', modulusLength: opts?.modulusLength ?? 2048, passphrase: opts?.passphrase }
                : { type: 'ec', namedCurve: opts?.namedCurve ?? 'prime256v1', passphrase: opts?.passphrase }
        );
        const updated: ManagedKey = {
            ...current,
            algorithm: generated.algorithm,
            publicKey: generated.publicKey,
            privateKey: generated.privateKey,
            passphrase: opts?.passphrase,
            rotatedAt: new Date().toISOString(),
        };
        this.managedKeyRepo.save(updated);
        return { keyId, publicKey: updated.publicKey, metadata: this.managedDomain.toMetadata(updated) };
    }
}
