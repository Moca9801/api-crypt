import { CryptoProviderPort } from '../../ports/crypto-provider.port';
import { ManagedKeyDomainService } from '../../services/managed-key-domain.service';
import { auditLog } from '../../../../infrastructure/audit/audit-logger';

export class ManagedHybridEncryptUseCase {
    constructor(
        private readonly cryptoProvider: CryptoProviderPort,
        private readonly managedDomain: ManagedKeyDomainService
    ) {}

    async execute(keyId: string, plaintext: string, clientIp = 'system') {
        const key = await this.managedDomain.getActiveOrThrow(keyId);
        if (key.type !== 'rsa') {
            throw new Error('Hybrid encryption requires an RSA key');
        }
        auditLog({ event: 'managed.encrypt', keyId, ip: clientIp });
        return { keyId, ...this.cryptoProvider.hybridEncrypt(plaintext, key.publicKey) };
    }
}
