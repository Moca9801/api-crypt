import { HttpClient } from '../http-client';
import { HybridEncryptedPayload, SignAlgorithm } from '../types';

/** Módulo de operaciones criptográficas sobre claves gestionadas. Acceder via `client.managed`. */
export class ManagedModule {
    constructor(private readonly http: HttpClient) {}

    /**
     * Cifra texto plano usando el modelo híbrido RSA+AES con una clave gestionada.
     * Solo funciona con claves de tipo 'rsa'.
     */
    async encrypt(keyId: string, plaintext: string): Promise<HybridEncryptedPayload> {
        return this.http.post<HybridEncryptedPayload & { ok: true }>(
            '/api/v1/crypto/managed/hybrid/encrypt',
            { keyId, plaintext }
        );
    }

    /**
     * Descifra un payload cifrado con `managed.encrypt()`.
     * @param passphrase Solo necesario si la clave fue creada con passphrase.
     */
    async decrypt(
        keyId: string,
        payload: Omit<HybridEncryptedPayload, 'keyId'>,
        passphrase?: string
    ): Promise<string> {
        const res = await this.http.post<{ ok: true; plaintext: string }>(
            '/api/v1/crypto/managed/hybrid/decrypt',
            { keyId, ...payload, passphrase }
        );
        return res.plaintext;
    }

    /**
     * Firma datos (en base64) con la clave privada de una clave gestionada.
     * @param passphrase Solo necesario si la clave fue creada con passphrase.
     */
    async sign(
        keyId: string,
        dataBase64: string,
        algorithm: SignAlgorithm = 'RSA-SHA256',
        passphrase?: string
    ): Promise<string> {
        const res = await this.http.post<{ ok: true; signatureBase64: string }>(
            '/api/v1/crypto/managed/sign/data',
            { keyId, dataBase64, algorithm, passphrase }
        );
        return res.signatureBase64;
    }

    /** Verifica una firma creada con `managed.sign()`. */
    async verify(
        keyId: string,
        dataBase64: string,
        signatureBase64: string,
        algorithm: SignAlgorithm = 'RSA-SHA256'
    ): Promise<boolean> {
        const res = await this.http.post<{ ok: true; valid: boolean }>(
            '/api/v1/crypto/managed/sign/verify',
            { keyId, dataBase64, signatureBase64, algorithm }
        );
        return res.valid;
    }
}
