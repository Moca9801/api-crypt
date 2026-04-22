import { HttpClient } from '../http-client';

/** Módulo de generación de valores aleatorios criptográficamente seguros. Acceder via `client.random`. */
export class RandomModule {
    constructor(private readonly http: HttpClient) {}

    /**
     * Genera bytes aleatorios seguros.
     * @param length Número de bytes. Default: 32
     * @returns Bytes en base64
     */
    async bytes(length = 32): Promise<string> {
        const res = await this.http.get<{ ok: true; base64: string; length: number }>(
            `/api/v1/crypto/random/bytes?length=${length}`
        );
        return res.base64;
    }

    /**
     * Genera un UUID v4 criptográficamente seguro.
     */
    async uuid(): Promise<string> {
        const res = await this.http.get<{ ok: true; uuid: string }>('/api/v1/crypto/random/uuid');
        return res.uuid;
    }
}
