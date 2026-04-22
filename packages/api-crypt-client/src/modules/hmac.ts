import { HttpClient } from '../http-client';

/** Módulo HMAC-SHA256. Acceder via `client.hmac`. */
export class HmacModule {
    constructor(private readonly http: HttpClient) {}

    /**
     * Genera una firma HMAC-SHA256.
     * @param data Datos a firmar (string UTF-8)
     * @param secret Secreto en base64
     * @returns Firma en hexadecimal
     */
    async sign(data: string, secret: string): Promise<string> {
        const res = await this.http.post<{ ok: true; signatureHex: string }>(
            '/api/v1/crypto/hmac/sign',
            { data, secret }
        );
        return res.signatureHex;
    }

    /**
     * Verifica una firma HMAC-SHA256 usando comparación timing-safe.
     * @returns true si la firma es válida
     */
    async verify(data: string, secret: string, signatureHex: string): Promise<boolean> {
        const res = await this.http.post<{ ok: true; valid: boolean }>(
            '/api/v1/crypto/hmac/verify',
            { data, secret, signatureHex }
        );
        return res.valid;
    }
}
