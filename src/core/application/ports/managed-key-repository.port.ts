import { ManagedKey } from '../../domain/managed-key';

/**
 * Puerto del repositorio de claves gestionadas.
 *
 * Todos los métodos son async para permitir implementaciones con:
 * - fs.promises (default — JSON file, zero-deps)
 * - SQLite (better-sqlite3 / @databases/sqlite)
 * - PostgreSQL / Redis / KMS
 * sin cambiar los use cases ni la arquitectura hexagonal.
 */
export interface ManagedKeyRepositoryPort {
    save(key: ManagedKey): Promise<void>;
    getById(keyId: string): Promise<ManagedKey | undefined>;
    list(): Promise<ManagedKey[]>;
}
