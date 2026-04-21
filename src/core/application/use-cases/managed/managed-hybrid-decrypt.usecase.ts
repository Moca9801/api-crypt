import { CryptServiceError } from '../../../../libs/services/crypt.service';
import { CryptoProviderPort } from '../../ports/crypto-provider.port';
import { ManagedKeyDomainService } from '../../services/managed-key-domain.service';

export class ManagedHybridDecryptUseCase {
    constructor(
        private readonly cryptoProvider: CryptoProviderPort,
        private readonly managedDomain: ManagedKeyDomainService
    ) {}

    execute(
        keyId: string,
        payload: { encryptedAesKey: string; iv: string; authTag: string; ciphertext: string }
    ) {
        const key = this.managedDomain.getActiveOrThrow(keyId);
        if (key.type !== 'rsa') {
            throw new CryptServiceError('Hybrid decryption requires an RSA managed key', 'KEY_TYPE_UNSUPPORTED');
        }
        return this.cryptoProvider.hybridDecrypt(
            payload.encryptedAesKey,
            payload.iv,
            payload.authTag,
            payload.ciphertext,
            key.privateKey,
            key.passphrase
        );
    }
}
