import { ManagedKeyDomainService } from '../../services/managed-key-domain.service';
import { ManagedKeyRepositoryPort } from '../../ports/managed-key-repository.port';

export class ListManagedKeysUseCase {
    constructor(
        private readonly managedKeyRepo: ManagedKeyRepositoryPort,
        private readonly managedDomain: ManagedKeyDomainService
    ) {}

    async execute() {
        const keys = await this.managedKeyRepo.list();
        return keys.map((k) => this.managedDomain.toMetadata(k));
    }
}
