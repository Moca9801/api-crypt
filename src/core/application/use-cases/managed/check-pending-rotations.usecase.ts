import { ManagedKey } from '../../../domain/managed-key';
import { ManagedKeyRepositoryPort } from '../../ports/managed-key-repository.port';
import { ManagedKeyDomainService } from '../../services/managed-key-domain.service';

export interface PendingRotationInfo {
    keyId: string;
    daysUntilRotation: number;
    nextRotationAt: string;
    algorithm: string;
    type: string;
}

export class CheckPendingRotationsUseCase {
    constructor(
        private readonly managedKeyRepo: ManagedKeyRepositoryPort,
        private readonly managedDomain: ManagedKeyDomainService
    ) {}

    async execute(warningDays = 7): Promise<PendingRotationInfo[]> {
        const now = Date.now();
        const keys = await this.managedKeyRepo.list();
        return keys
            .filter((k): k is ManagedKey & { nextRotationAt: string } =>
                k.status === 'active' && k.nextRotationAt !== undefined
            )
            .map((k) => {
                const msLeft = new Date(k.nextRotationAt).getTime() - now;
                const daysUntilRotation = Math.max(0, Math.ceil(msLeft / 86_400_000));
                return { keyId: k.keyId, daysUntilRotation, nextRotationAt: k.nextRotationAt, algorithm: k.algorithm, type: k.type };
            })
            .filter((i) => i.daysUntilRotation <= warningDays)
            .sort((a, b) => a.daysUntilRotation - b.daysUntilRotation);
    }
}
