import { ManagedKeyDomainService } from '../../services/managed-key-domain.service';

export class GetManagedPublicKeyUseCase {
    constructor(private readonly managedDomain: ManagedKeyDomainService) {}

    execute(keyId: string) {
        const key = this.managedDomain.getOrThrow(keyId);
        return { keyId, publicKey: key.publicKey, metadata: this.managedDomain.toMetadata(key) };
    }
}
