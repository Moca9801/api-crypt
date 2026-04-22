import { HttpClient } from '../http-client';
import { SymmetricDecryptInput, SymmetricEncryptResult } from '../types';

/** Módulo de cifrado simétrico AES-256-GCM. Acceder via `client.symmetric`. */
export class SymmetricModule {
    constructor(private readonly http: HttpClient) {}

    /**
     * Cifra texto plano con AES-256-GCM.
     * Si no se provee una clave, el servidor genera una aleatoria.
     * @returns Payload con iv, authTag, ciphertext y la clave (base64). Guarda la clave con cuidado.
     */
    async encrypt(plaintext: string, key?: string): Promise<SymmetricEncryptResult> {
        const res = await this.http.post<SymmetricEncryptResult & { ok: true }>(
            '/api/v1/crypto/symmetric/encrypt',
            { plaintext, key }
        );
        const { ok: _ok, ...result } = res;
        return result;
    }

    /** Descifra un payload cifrado con `symmetric.encrypt()`. */
    async decrypt(payload: SymmetricDecryptInput): Promise<string> {
        const res = await this.http.post<{ ok: true; plaintext: string }>(
            '/api/v1/crypto/symmetric/decrypt',
            payload
        );
        return res.plaintext;
    }
}
