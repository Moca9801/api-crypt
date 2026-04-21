import { CryptServiceError } from '../../../../libs/services/crypt.service';
import { CryptoProviderPort } from '../../ports/crypto-provider.port';
import { ManagedKeyDomainService } from '../../services/managed-key-domain.service';

export class ManagedHybridEncryptUseCase {
    constructor(
        private readonly cryptoProvider: CryptoProviderPort,
        private readonly managedDomain: ManagedKeyDomainService
    ) {}

    execute(keyId: string, plaintext: string) {
        const key = this.managedDomain.getActiveOrThrow(keyId);
        if (key.type !== 'rsa') {
            throw new CryptServiceError('Hybrid encryption requires an RSA managed key', 'KEY_TYPE_UNSUPPORTED');
        }
        return { keyId, ...this.cryptoProvider.hybridEncrypt(plaintext, key.publicKey) };
    }
}
