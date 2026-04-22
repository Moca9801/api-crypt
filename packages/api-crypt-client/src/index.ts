import { HttpClient } from './http-client';
import { KeysModule } from './modules/keys';
import { ManagedModule } from './modules/managed';
import { SymmetricModule } from './modules/symmetric';
import { HashModule } from './modules/hash';
import { HmacModule } from './modules/hmac';
import { TokensModule } from './modules/tokens';
import { SealedModule } from './modules/sealed';
import { RandomModule } from './modules/random';
import { ApiCryptClientConfig } from './types';

export { ApiCryptError } from './errors';
export * from './types';

/**
 * Cliente oficial para api-crypt.
 *
 * @example
 * ```typescript
 * import { ApiCryptClient } from 'api-crypt-client';
 *
 * const client = new ApiCryptClient({
 *   baseUrl: 'http://localhost:3000',
 *   apiKey: process.env.CRYPTO_API_KEY!,
 * });
 *
 * // Cifrar
 * const encrypted = await client.symmetric.encrypt('mi secreto');
 * // Descifrar
 * const plaintext = await client.symmetric.decrypt(encrypted);
 * ```
 */
export class ApiCryptClient {
    /** Gestión de claves criptográficas (crear, listar, rotar, deshabilitar, policy). */
    readonly keys: KeysModule;
    /** Operaciones criptográficas con claves gestionadas (cifrado híbrido, firma). */
    readonly managed: ManagedModule;
    /** Cifrado simétrico AES-256-GCM stateless. */
    readonly symmetric: SymmetricModule;
    /** Funciones hash SHA-256. */
    readonly hash: HashModule;
    /** HMAC-SHA256 sign/verify. */
    readonly hmac: HmacModule;
    /** Tokens firmados con TTL. */
    readonly tokens: TokensModule;
    /** Payloads sellados con TTL y protección anti-replay. */
    readonly sealed: SealedModule;
    /** Valores aleatorios criptográficamente seguros (bytes, UUID). */
    readonly random: RandomModule;

    constructor(config: ApiCryptClientConfig) {
        const http = new HttpClient(config);
        this.keys     = new KeysModule(http);
        this.managed  = new ManagedModule(http);
        this.symmetric = new SymmetricModule(http);
        this.hash     = new HashModule(http);
        this.hmac     = new HmacModule(http);
        this.tokens   = new TokensModule(http);
        this.sealed   = new SealedModule(http);
        this.random   = new RandomModule(http);
    }
}
