import { ManagedKeyDomainService } from '../../services/managed-key-domain.service';

export class GetManagedPublicKeyUseCase {
    constructor(private readonly managedDomain: ManagedKeyDomainService) {}

    async execute(keyId: string) {
        const key = await this.managedDomain.getOrThrow(keyId);
        return { keyId: key.keyId, publicKey: key.publicKey, metadata: this.managedDomain.toMetadata(key) };
    }
}
