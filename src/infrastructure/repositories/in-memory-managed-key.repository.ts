import { ManagedKeyRepositoryPort } from '../../core/application/ports/managed-key-repository.port';
import { ManagedKey } from '../../core/domain/managed-key';

/**
 * In-memory implementation of ManagedKeyRepositoryPort.
 * @dev-only — For tests only. Keys are lost on process restart.
 */
export class InMemoryManagedKeyRepository implements ManagedKeyRepositoryPort {
    private readonly keys = new Map<string, ManagedKey>();

    async save(key: ManagedKey): Promise<void> {
        this.keys.set(key.keyId, key);
    }

    async getById(keyId: string): Promise<ManagedKey | undefined> {
        return this.keys.get(keyId);
    }

    async list(): Promise<ManagedKey[]> {
        return Array.from(this.keys.values());
    }
}
