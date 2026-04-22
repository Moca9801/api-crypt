// ── Configuración ─────────────────────────────────────────────────────────────

export interface ApiCryptClientConfig {
    /** URL base del servidor api-crypt. Sin trailing slash. */
    baseUrl: string;
    /** API key configurada en el servidor (env: API_KEY). */
    apiKey: string;
    /** Timeout por request en milisegundos. Default: 10000 */
    timeoutMs?: number;
    /** Número de reintentos en errores 5xx / red. Default: 1 */
    retries?: number;
}

// ── Managed Keys ──────────────────────────────────────────────────────────────

export type ManagedKeyType = 'rsa' | 'ec';
export type ManagedKeyStatus = 'active' | 'disabled';

export interface RotationPolicy {
    ttlDays: number;
    onExpiry: 'disable' | 'keep';
}

export interface ManagedKeyMetadata {
    keyId: string;
    type: ManagedKeyType;
    algorithm: string;
    status: ManagedKeyStatus;
    passphraseProtected: boolean;
    createdAt: string;
    rotatedAt?: string;
    rotationPolicy?: RotationPolicy;
    nextRotationAt?: string;
    daysUntilRotation?: number;
    fingerprintSha256Hex: string;
}

export interface CreateKeyOptions {
    type: ManagedKeyType;
    keyId?: string;
    passphrase?: string;
    modulusLength?: 2048 | 3072 | 4096;
    namedCurve?: 'prime256v1' | 'secp384r1';
    rotationPolicy?: RotationPolicy;
}

export interface KeyCreateResult {
    keyId: string;
    publicKey: string;
    metadata: ManagedKeyMetadata;
}

export interface RotateKeyOptions {
    passphrase?: string;
    modulusLength?: 2048 | 3072 | 4096;
    namedCurve?: 'prime256v1' | 'secp384r1';
}

export interface PendingRotationInfo {
    keyId: string;
    daysUntilRotation: number;
    nextRotationAt: string;
    algorithm: string;
    type: string;
}

// ── Managed Crypto ────────────────────────────────────────────────────────────

export interface HybridEncryptedPayload {
    keyId: string;
    encryptedAesKey: string;
    iv: string;
    authTag: string;
    ciphertext: string;
}

export type SignAlgorithm = 'RSA-SHA256' | 'ECDSA-SHA256';

// ── Symmetric ─────────────────────────────────────────────────────────────────

export interface SymmetricEncryptResult {
    iv: string;
    authTag: string;
    ciphertext: string;
    key: string;
}

export interface SymmetricDecryptInput {
    iv: string;
    authTag: string;
    ciphertext: string;
    key: string;
}

// ── Hash ──────────────────────────────────────────────────────────────────────

export type HashCombineMode = 'concat-sha256' | 'hmac-sha256';

export interface HashCombineResult {
    combinedHash: string;
    mode: HashCombineMode;
}

// ── Tokens ────────────────────────────────────────────────────────────────────

export type TokenPayload = Record<string, unknown>;

// ── Sealed ────────────────────────────────────────────────────────────────────

export interface SealedBlob {
    iv: string;
    authTag: string;
    ciphertext: string;
    expiresAt: number;
    nonce: string;
}
