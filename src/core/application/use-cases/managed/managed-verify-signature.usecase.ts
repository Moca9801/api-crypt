import { SignAlg } from '../../../../libs/services/crypt.service';
import { CryptoProviderPort } from '../../ports/crypto-provider.port';
import { ManagedKeyDomainService } from '../../services/managed-key-domain.service';

export class ManagedVerifySignatureUseCase {
    constructor(
        private readonly cryptoProvider: CryptoProviderPort,
        private readonly managedDomain: ManagedKeyDomainService
    ) {}

    async execute(keyId: string, dataBase64: string, signatureBase64: string, algorithm: SignAlg) {
        const key = await this.managedDomain.getOrThrow(keyId);
        this.managedDomain.assertSignAlgorithm(key, algorithm);
        return this.cryptoProvider.verifySignature(dataBase64, signatureBase64, key.publicKey, algorithm);
    }
}
