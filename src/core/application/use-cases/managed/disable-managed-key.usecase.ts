import { ManagedKeyRepositoryPort } from '../../ports/managed-key-repository.port';
import { ManagedKeyDomainService } from '../../services/managed-key-domain.service';
import { auditLog } from '../../../../infrastructure/audit/audit-logger';

export class DisableManagedKeyUseCase {
    constructor(
        private readonly managedKeyRepo: ManagedKeyRepositoryPort,
        private readonly managedDomain: ManagedKeyDomainService
    ) {}

    async execute(keyId: string, clientIp = 'system') {
        const key = await this.managedDomain.getOrThrow(keyId);
        const disabled = { ...key, status: 'disabled' as const };
        await this.managedKeyRepo.save(disabled);
        auditLog({ event: 'key.disabled', keyId, ip: clientIp });
        return this.managedDomain.toMetadata(disabled);
    }
}
