import { HttpClient } from '../http-client';
import {
    CreateKeyOptions, KeyCreateResult, ManagedKeyMetadata,
    PendingRotationInfo, RotateKeyOptions, RotationPolicy,
} from '../types';

interface KeyListResponse { ok: true; keys: ManagedKeyMetadata[] }
interface KeyPublicResponse { ok: true; keyId: string; publicKey: string; metadata: ManagedKeyMetadata }

/** Módulo de gestión de claves criptográficas. Acceder via `client.keys`. */
export class KeysModule {
    constructor(private readonly http: HttpClient) {}

    /** Crea un nuevo par de claves gestionado (RSA o EC). */
    async create(opts: CreateKeyOptions): Promise<KeyCreateResult> {
        return this.http.post<KeyCreateResult & { ok: true }>('/api/v1/crypto/keys/managed/create', opts);
    }

    /** Lista todas las claves gestionadas (solo metadatos, sin material de clave). */
    async list(): Promise<ManagedKeyMetadata[]> {
        const res = await this.http.get<KeyListResponse>('/api/v1/crypto/keys/managed');
        return res.keys;
    }

    /** Obtiene la clave pública PEM y metadatos de una clave gestionada. */
    async getPublicKey(keyId: string): Promise<KeyPublicResponse> {
        return this.http.get<KeyPublicResponse>(`/api/v1/crypto/keys/managed/${keyId}/public`);
    }

    /** Rota una clave gestionada generando un nuevo par. La clave anterior queda como 'disabled'. */
    async rotate(keyId: string, opts?: RotateKeyOptions): Promise<KeyCreateResult> {
        return this.http.post<KeyCreateResult & { ok: true }>(`/api/v1/crypto/keys/managed/${keyId}/rotate`, opts ?? {});
    }

    /** Deshabilita una clave (no puede usarse para operaciones, pero existe en el store). */
    async disable(keyId: string): Promise<ManagedKeyMetadata> {
        const res = await this.http.post<{ ok: true; metadata: ManagedKeyMetadata }>(`/api/v1/crypto/keys/managed/${keyId}/disable`, {});
        return res.metadata;
    }

    /** Establece o actualiza la política de rotación automática de una clave. */
    async setRotationPolicy(keyId: string, policy: RotationPolicy): Promise<ManagedKeyMetadata> {
        const res = await this.http.post<{ ok: true; metadata: ManagedKeyMetadata }>(`/api/v1/crypto/keys/managed/${keyId}/policy`, policy);
        return res.metadata;
    }

    /** Lista claves cuya rotación automática ocurre pronto (dentro de warningDays días). */
    async pendingRotations(warningDays = 7): Promise<PendingRotationInfo[]> {
        const res = await this.http.get<{ ok: true; count: number; keys: PendingRotationInfo[] }>(
            `/api/v1/crypto/keys/managed/rotation/pending?warningDays=${warningDays}`
        );
        return res.keys;
    }
}
