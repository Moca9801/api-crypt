import { ManagedKeyRepositoryPort } from '../../ports/managed-key-repository.port';
import { ManagedKey } from '../../../domain/managed-key';
import { ManagedKeyDomainService } from '../../services/managed-key-domain.service';

export class DisableManagedKeyUseCase {
    constructor(
        private readonly managedKeyRepo: ManagedKeyRepositoryPort,
        private readonly managedDomain: ManagedKeyDomainService
    ) {}

    execute(keyId: string) {
        const key = this.managedDomain.getOrThrow(keyId);
        const updated: ManagedKey = { ...key, status: 'disabled', rotatedAt: new Date().toISOString() };
        this.managedKeyRepo.save(updated);
        return this.managedDomain.toMetadata(updated);
    }
}
