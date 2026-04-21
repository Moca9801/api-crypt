import { CryptServiceError, SignAlg } from '../../../../libs/services/crypt.service';
import { CryptoProviderPort } from '../../ports/crypto-provider.port';
import { KeyVaultPort } from '../../ports/key-vault.port';
import { ManagedKeyDomainService } from '../../services/managed-key-domain.service';

export class ManagedSignDataUseCase {
    constructor(
        private readonly cryptoProvider: CryptoProviderPort,
        private readonly managedDomain: ManagedKeyDomainService,
        private readonly keyVault: KeyVaultPort
    ) {}

    execute(keyId: string, dataBase64: string, algorithm: SignAlg, passphrase?: string) {
        const key = this.managedDomain.getActiveOrThrow(keyId);
        this.managedDomain.assertSignAlgorithm(key, algorithm);
        if (key.passphraseProtected && !passphrase) {
            throw new CryptServiceError(
                'This key is passphrase-protected. Provide "passphrase" in the request body.',
                'PASSPHRASE_REQUIRED'
            );
        }
        // Decrypt private key from vault at use-time — never held in memory beyond this call
        const privateKeyPem = this.keyVault.decrypt(key.encryptedPrivateKey);
        return this.cryptoProvider.signData(dataBase64, privateKeyPem, passphrase, algorithm);
    }
}
