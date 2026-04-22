import { SignAlg } from '../../../../libs/services/crypt.service';
import { CryptoProviderPort } from '../../ports/crypto-provider.port';
import { ManagedKeyDomainService } from '../../services/managed-key-domain.service';
import { KeyVaultPort } from '../../ports/key-vault.port';
import { auditLog } from '../../../../infrastructure/audit/audit-logger';

export class ManagedSignDataUseCase {
    constructor(
        private readonly cryptoProvider: CryptoProviderPort,
        private readonly managedDomain: ManagedKeyDomainService,
        private readonly keyVault: KeyVaultPort
    ) {}

    async execute(keyId: string, dataBase64: string, algorithm: SignAlg, passphrase?: string, clientIp = 'system') {
        const key = await this.managedDomain.getActiveOrThrow(keyId);
        this.managedDomain.assertSignAlgorithm(key, algorithm);
        const privateKey = this.keyVault.decrypt(key.encryptedPrivateKey);
        auditLog({ event: 'managed.sign', keyId, ip: clientIp });
        return this.cryptoProvider.signData(dataBase64, privateKey, passphrase, algorithm);
    }
}
