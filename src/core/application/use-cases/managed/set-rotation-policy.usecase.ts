import { CryptServiceError } from '../../../../libs/services/crypt.service';
import { ManagedKey, RotationPolicy } from '../../../domain/managed-key';
import { ManagedKeyRepositoryPort } from '../../ports/managed-key-repository.port';
import { ManagedKeyDomainService } from '../../services/managed-key-domain.service';

export class SetRotationPolicyUseCase {
    constructor(
        private readonly managedKeyRepo: ManagedKeyRepositoryPort,
        private readonly managedDomain: ManagedKeyDomainService
    ) {}

    execute(keyId: string, policy: RotationPolicy) {
        if (policy.ttlDays < 1 || policy.ttlDays > 3650) {
            throw new CryptServiceError(
                'ttlDays must be between 1 and 3650 (10 years)',
                'INVALID_ROTATION_POLICY'
            );
        }
        const key = this.managedDomain.getActiveOrThrow(keyId);
        const nextRotationAt = this.managedDomain.computeNextRotationAt(policy.ttlDays);
        const updated: ManagedKey = { ...key, rotationPolicy: policy, nextRotationAt };
        this.managedKeyRepo.save(updated);
        return this.managedDomain.toMetadata(updated);
    }
}
