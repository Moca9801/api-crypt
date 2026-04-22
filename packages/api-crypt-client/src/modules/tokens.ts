import { HttpClient } from '../http-client';
import { TokenPayload } from '../types';

/** Módulo de tokens firmados HMAC-SHA256. Acceder via `client.tokens`. */
export class TokensModule {
    constructor(private readonly http: HttpClient) {}

    /**
     * Crea un token firmado con payload y fecha de expiración.
     * @param payload Datos arbitrarios a incluir en el token
     * @param secret Secreto para firmar
     * @param expiresInSeconds TTL en segundos. Default: 3600 (1 hora)
     * @returns Token firmado (string opaco)
     */
    async create(payload: TokenPayload, secret: string, expiresInSeconds = 3600): Promise<string> {
        const res = await this.http.post<{ ok: true; token: string }>(
            '/api/v1/crypto/tokens/signed/create',
            { payload, secret, expiresInSeconds }
        );
        return res.token;
    }

    /**
     * Verifica un token firmado y retorna el payload si es válido.
     * Lanza ApiCryptError si el token es inválido o ha expirado.
     */
    async verify(token: string, secret: string): Promise<TokenPayload> {
        const res = await this.http.post<{ ok: true; payload: TokenPayload }>(
            '/api/v1/crypto/tokens/signed/verify',
            { token, secret }
        );
        return res.payload;
    }
}
