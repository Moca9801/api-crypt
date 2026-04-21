export type ManagedKeyType = 'rsa' | 'ec';
export type ManagedKeyStatus = 'active' | 'disabled';

export interface ManagedKey {
    keyId: string;
    type: ManagedKeyType;
    algorithm: string;
    status: ManagedKeyStatus;
    publicKey: string;
    privateKey: string;
    passphrase?: string;
    createdAt: string;
    rotatedAt?: string;
}

export interface ManagedKeyMetadata {
    keyId: string;
    type: ManagedKeyType;
    algorithm: string;
    status: ManagedKeyStatus;
    passphraseProtected: boolean;
    createdAt: string;
    rotatedAt?: string;
    fingerprintSha256Hex: string;
}

export interface CreateManagedKeyInput {
    keyId?: string;
    type: ManagedKeyType;
    passphrase?: string;
    modulusLength?: 2048 | 3072 | 4096;
    namedCurve?: 'prime256v1' | 'secp384r1';
}
