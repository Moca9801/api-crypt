import { ManagedKeyRepositoryPort } from '../../core/application/ports/managed-key-repository.port';
import { ManagedKey } from '../../core/domain/managed-key';

/**
 * In-memory implementation of ManagedKeyRepositoryPort.
 *
 * @dev-only — For use in tests and TEST_MODE=true only.
 * Keys are lost on process restart. Use FileSystemManagedKeyRepository for development
 * and any persistent deployment.
 */
export class InMemoryManagedKeyRepository implements ManagedKeyRepositoryPort {
    private readonly keys = new Map<string, ManagedKey>();

    save(key: ManagedKey): void {
        this.keys.set(key.keyId, key);
    }

    getById(keyId: string): ManagedKey | undefined {
        return this.keys.get(keyId);
    }

    list(): ManagedKey[] {
        return Array.from(this.keys.values());
    }
}
