import { SignAlg } from '../../../../libs/services/crypt.service';
import { CryptoProviderPort } from '../../ports/crypto-provider.port';
import { ManagedKeyDomainService } from '../../services/managed-key-domain.service';

export class ManagedSignDataUseCase {
    constructor(
        private readonly cryptoProvider: CryptoProviderPort,
        private readonly managedDomain: ManagedKeyDomainService
    ) {}

    execute(keyId: string, dataBase64: string, algorithm: SignAlg) {
        const key = this.managedDomain.getActiveOrThrow(keyId);
        this.managedDomain.assertSignAlgorithm(key, algorithm);
        return this.cryptoProvider.signData(dataBase64, key.privateKey, key.passphrase, algorithm);
    }
}
