import { promises as fs } from 'fs';
import { existsSync, readFileSync } from 'fs';
import { ManagedKey } from '../../core/domain/managed-key';
import { ManagedKeyRepositoryPort } from '../../core/application/ports/managed-key-repository.port';

/**
 * Persiste claves en un archivo JSON local usando fs.promises para escrituras async.
 *
 * Estrategia de concurrencia:
 * - Lecturas: siempre desde el cache en memoria (O(1), sin I/O)
 * - Escrituras: serializadas con una Promise queue (write mutex)
 *   para evitar race conditions si múltiples operaciones ocurren simultáneamente.
 *
 * Security note: All private keys in the file are AES-256-GCM encrypted
 * (EncryptedKeyBlob) — no plaintext key material is ever written to disk.
 *
 * Extension point: Para mayor throughput, reemplazar con SQLite (WAL mode)
 * o PostgreSQL implementando ManagedKeyRepositoryPort.
 */
export class FileSystemManagedKeyRepository implements ManagedKeyRepositoryPort {
    private readonly cache = new Map<string, ManagedKey>();
    private writeQueue: Promise<void> = Promise.resolve();

    constructor(private readonly dbPath: string) {
        // Carga inicial síncrona para que el servidor arranque rápido
        this.loadSync();
    }

    private loadSync(): void {
        if (!existsSync(this.dbPath)) return;
        try {
            const raw = readFileSync(this.dbPath, 'utf8');
            const arr = JSON.parse(raw) as ManagedKey[];
            if (!Array.isArray(arr)) throw new TypeError('keys database root must be a JSON array');
            for (const key of arr) this.cache.set(key.keyId, key);
        } catch (err) {
            throw new Error(
                `[api-crypt] Failed to load keys database from "${this.dbPath}": ${(err as Error).message}`
            );
        }
    }

    /** Serializa las escrituras para evitar race conditions. */
    private enqueueWrite(data: string): Promise<void> {
        this.writeQueue = this.writeQueue.then(() =>
            fs.writeFile(this.dbPath, data, 'utf8')
        );
        return this.writeQueue;
    }

    // ── ManagedKeyRepositoryPort ─────────────────────────────────────────────

    async save(key: ManagedKey): Promise<void> {
        this.cache.set(key.keyId, key);
        const arr = Array.from(this.cache.values());
        await this.enqueueWrite(JSON.stringify(arr, null, 2));
    }

    async getById(keyId: string): Promise<ManagedKey | undefined> {
        return this.cache.get(keyId);
    }

    async list(): Promise<ManagedKey[]> {
        return Array.from(this.cache.values());
    }
}
