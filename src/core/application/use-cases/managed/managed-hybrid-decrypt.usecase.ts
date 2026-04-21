import { CryptServiceError } from '../../../../libs/services/crypt.service';
import { CryptoProviderPort } from '../../ports/crypto-provider.port';
import { KeyVaultPort } from '../../ports/key-vault.port';
import { ManagedKeyDomainService } from '../../services/managed-key-domain.service';

export class ManagedHybridDecryptUseCase {
    constructor(
        private readonly cryptoProvider: CryptoProviderPort,
        private readonly managedDomain: ManagedKeyDomainService,
        private readonly keyVault: KeyVaultPort
    ) {}

    execute(
        keyId: string,
        payload: { encryptedAesKey: string; iv: string; authTag: string; ciphertext: string },
        passphrase?: string
    ) {
        const key = this.managedDomain.getActiveOrThrow(keyId);
        if (key.type !== 'rsa') {
            throw new CryptServiceError('Hybrid decryption requires an RSA managed key', 'KEY_TYPE_UNSUPPORTED');
        }
        if (key.passphraseProtected && !passphrase) {
            throw new CryptServiceError(
                'This key is passphrase-protected. Provide "passphrase" in the request body.',
                'PASSPHRASE_REQUIRED'
            );
        }
        // Decrypt private key from vault at use-time — never held in memory beyond this call
        const privateKeyPem = this.keyVault.decrypt(key.encryptedPrivateKey);
        return this.cryptoProvider.hybridDecrypt(
            payload.encryptedAesKey,
            payload.iv,
            payload.authTag,
            payload.ciphertext,
            privateKeyPem,
            passphrase
        );
    }
}
