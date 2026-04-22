import { CryptServiceError } from '../../../../libs/services/crypt.service';
import { ManagedKey, RotationPolicy } from '../../../domain/managed-key';
import { ManagedKeyRepositoryPort } from '../../ports/managed-key-repository.port';
import { ManagedKeyDomainService } from '../../services/managed-key-domain.service';
import { auditLog } from '../../../../infrastructure/audit/audit-logger';

export class SetRotationPolicyUseCase {
    constructor(
        private readonly managedKeyRepo: ManagedKeyRepositoryPort,
        private readonly managedDomain: ManagedKeyDomainService
    ) {}

    async execute(keyId: string, policy: RotationPolicy, clientIp = 'system') {
        if (policy.ttlDays < 1 || policy.ttlDays > 3650) {
            throw new CryptServiceError('ttlDays must be between 1 and 3650', 'INVALID_ROTATION_POLICY');
        }
        const key = await this.managedDomain.getActiveOrThrow(keyId);
        const nextRotationAt = this.managedDomain.computeNextRotationAt(policy.ttlDays);
        const updated: ManagedKey = { ...key, rotationPolicy: policy, nextRotationAt };
        await this.managedKeyRepo.save(updated);
        auditLog({ event: 'key.policy.set', keyId, ttlDays: policy.ttlDays, ip: clientIp });
        return this.managedDomain.toMetadata(updated);
    }
}
