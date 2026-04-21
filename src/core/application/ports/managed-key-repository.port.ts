import { ManagedKey } from '../../domain/managed-key';

export interface ManagedKeyRepositoryPort {
    save(key: ManagedKey): void;
    getById(keyId: string): ManagedKey | undefined;
    list(): ManagedKey[];
}
