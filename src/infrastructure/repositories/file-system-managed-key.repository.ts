import { existsSync, readFileSync, writeFileSync } from 'fs';
import { ManagedKey } from '../../core/domain/managed-key';
import { ManagedKeyRepositoryPort } from '../../core/application/ports/managed-key-repository.port';

/**
 * Persists managed keys to a local JSON file.
 *
 * Security note: All private keys stored in the file are AES-256-GCM encrypted
 * (EncryptedKeyBlob) — no plaintext key material is ever written to disk.
 *
 * The in-memory cache is populated at startup. Every write is flushed to disk
 * immediately via a synchronous writeFileSync, which is appropriate for a
 * self-hosted developer tool; replace with async + WAL for higher throughput.
 */
export class FileSystemManagedKeyRepository implements ManagedKeyRepositoryPort {
    private readonly cache = new Map<string, ManagedKey>();

    constructor(private readonly dbPath: string) {
        this.load();
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    private load(): void {
        if (!existsSync(this.dbPath)) {
            return; // fresh start — file will be created on first save()
        }
        try {
            const raw = readFileSync(this.dbPath, 'utf8');
            const arr = JSON.parse(raw) as ManagedKey[];
            if (!Array.isArray(arr)) {
                throw new TypeError('keys database root must be a JSON array');
            }
            for (const key of arr) {
                this.cache.set(key.keyId, key);
            }
        } catch (err) {
            throw new Error(
                `[api-crypt] Failed to load keys database from "${this.dbPath}": ` +
                `${(err as Error).message}`
            );
        }
    }

    private persist(): void {
        const arr = Array.from(this.cache.values());
        writeFileSync(this.dbPath, JSON.stringify(arr, null, 2), 'utf8');
    }

    // ── ManagedKeyRepositoryPort ──────────────────────────────────────────────

    save(key: ManagedKey): void {
        this.cache.set(key.keyId, key);
        this.persist();
    }

    getById(keyId: string): ManagedKey | undefined {
        return this.cache.get(keyId);
    }

    list(): ManagedKey[] {
        return Array.from(this.cache.values());
    }
}
