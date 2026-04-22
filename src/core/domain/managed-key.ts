export type ManagedKeyType = 'rsa' | 'ec';
export type ManagedKeyStatus = 'active' | 'disabled';

/**
 * Opaque blob representing an AES-256-GCM encrypted private key PEM.
 * The actual encryption/decryption is handled by the KeyVaultPort in the infrastructure layer.
 */
export interface EncryptedKeyBlob {
    iv: string;
    authTag: string;
    ciphertext: string;
}

/**
 * Política de rotación automática de una clave gestionada.
 */
export interface RotationPolicy {
    /** Días de vida de la clave antes de rotación automática. */
    ttlDays: number;
    /**
     * Qué hacer con la clave anterior al rotar:
     * - 'disable': marcar como disabled (permite descifrado retrocompatible)
     * - 'keep': mantener activa (para casos de múltiples versiones activas)
     */
    onExpiry: 'disable' | 'keep';
}

export interface ManagedKey {
    keyId: string;
    type: ManagedKeyType;
    algorithm: string;
    status: ManagedKeyStatus;
    publicKey: string;
    /** Private key encrypted at rest via KeyVaultPort. Never stored as plaintext. */
    encryptedPrivateKey: EncryptedKeyBlob;
    /** True if the key PEM was generated with a passphrase (not stored, must be provided at use time). */
    passphraseProtected: boolean;
    createdAt: string;
    rotatedAt?: string;
    /** Política de rotación automática. Undefined = sin rotación automática. */
    rotationPolicy?: RotationPolicy;
    /** Fecha ISO 8601 de la próxima rotación automática programada. */
    nextRotationAt?: string;
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
    /** Días restantes para la próxima rotación (undefined si no hay policy). */
    daysUntilRotation?: number;
    fingerprintSha256Hex: string;
}

export interface CreateManagedKeyInput {
    keyId?: string;
    type: ManagedKeyType;
    /** Used to protect the PEM at generation time. NOT persisted server-side. */
    passphrase?: string;
    modulusLength?: 2048 | 3072 | 4096;
    namedCurve?: 'prime256v1' | 'secp384r1';
    /** Política de rotación a establecer al crear la clave. */
    rotationPolicy?: RotationPolicy;
}
