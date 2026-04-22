import { CryptoProviderPort } from '../../ports/crypto-provider.port';
import { ManagedKeyDomainService } from '../../services/managed-key-domain.service';
import { KeyVaultPort } from '../../ports/key-vault.port';
import { auditLog } from '../../../../infrastructure/audit/audit-logger';

export class ManagedHybridDecryptUseCase {
    constructor(
        private readonly cryptoProvider: CryptoProviderPort,
        private readonly managedDomain: ManagedKeyDomainService,
        private readonly keyVault: KeyVaultPort
    ) {}

    async execute(
        keyId: string,
        payload: { encryptedAesKey: string; iv: string; authTag: string; ciphertext: string },
        passphrase?: string,
        clientIp = 'system'
    ) {
        const key = await this.managedDomain.getActiveOrThrow(keyId);
        const privateKey = this.keyVault.decrypt(key.encryptedPrivateKey);
        auditLog({ event: 'managed.decrypt', keyId, ip: clientIp });
        return this.cryptoProvider.hybridDecrypt(
            payload.encryptedAesKey, payload.iv, payload.authTag, payload.ciphertext,
            privateKey, passphrase
        );
    }
}
