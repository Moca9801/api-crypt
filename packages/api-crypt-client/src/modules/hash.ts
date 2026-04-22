import { HttpClient } from '../http-client';
import { HashCombineMode, HashCombineResult } from '../types';

/** Módulo de funciones hash. Acceder via `client.hash`. */
export class HashModule {
    constructor(private readonly http: HttpClient) {}

    /**
     * Calcula el hash SHA-256 de un string.
     * @param data Datos a hashear
     * @param inputEncoding 'utf8' (default) o 'base64'
     * @returns Hash en formato hexadecimal (64 chars)
     */
    async sha256(data: string, inputEncoding: 'utf8' | 'base64' = 'utf8'): Promise<string> {
        const res = await this.http.post<{ ok: true; hex: string }>(
            '/api/v1/crypto/hash/sha256',
            { data, inputEncoding }
        );
        return res.hex;
    }

    /**
     * Combina dos hashes SHA-256 en uno nuevo.
     * @param mode 'concat-sha256' (concatena y hashea) o 'hmac-sha256' (requiere hmacSecret)
     */
    async combine(
        hashA: string,
        hashB: string,
        mode: HashCombineMode,
        hmacSecret?: string
    ): Promise<HashCombineResult> {
        const res = await this.http.post<HashCombineResult & { ok: true }>(
            '/api/v1/crypto/hash/combine',
            { hashA, hashB, mode, hmacSecret }
        );
        const { ok: _ok, ...result } = res;
        return result;
    }
}
