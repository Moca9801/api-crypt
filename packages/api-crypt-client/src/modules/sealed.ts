import { HttpClient } from '../http-client';
import { SealedBlob, TokenPayload } from '../types';

/**
 * Módulo de payloads sellados con TTL y protección contra replay.
 * Acceder via `client.sealed`.
 *
 * Un payload sellado es un objeto cifrado que expira automáticamente.
 * Ideal para links de un solo uso, magic links y tokens de corta vida.
 */
export class SealedModule {
    constructor(private readonly http: HttpClient) {}

    /**
     * Sella un objeto con un secreto y un TTL.
     * @param data Objeto a sellar
     * @param secret Secreto compartido
     * @param ttlSeconds Tiempo de vida en segundos (ej: 900 = 15 minutos)
     */
    async create(data: TokenPayload, secret: string, ttlSeconds: number): Promise<SealedBlob> {
        const res = await this.http.post<{ ok: true; sealed: SealedBlob }>(
            '/api/v1/crypto/sealed/create',
            { data, secret, ttlSeconds }
        );
        return res.sealed;
    }

    /**
     * Abre un payload sellado y retorna el objeto original.
     * Lanza ApiCryptError si el sello es inválido o ha expirado.
     */
    async open(sealed: SealedBlob, secret: string): Promise<TokenPayload> {
        const res = await this.http.post<{ ok: true; data: TokenPayload }>(
            '/api/v1/crypto/sealed/open',
            { sealed, secret }
        );
        return res.data;
    }
}
