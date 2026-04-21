import { randomUUID } from 'crypto';
import {
    CryptServiceError,
    KeyGenOptions,
    SignAlg,
    generateKeyPair,
    hybridDecrypt,
    hybridEncrypt,
    publicKeyFingerprint,
    signData,
    verifySignature,
} from './crypt.service';

export type ManagedKeyStatus = 'active' | 'disabled';

export interface ManagedKeyRecord {
    keyId: string;
    type: 'rsa' | 'ec';
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
    type: 'rsa' | 'ec';
    algorithm: string;
    status: ManagedKeyStatus;
    passphraseProtected: boolean;
    createdAt: string;
    rotatedAt?: string;
    fingerprintSha256Hex: string;
}

const store = new Map<string, ManagedKeyRecord>();

function toMetadata(record: ManagedKeyRecord): ManagedKeyMetadata {
    return {
        keyId: record.keyId,
        type: record.type,
        algorithm: record.algorithm,
        status: record.status,
        passphraseProtected: Boolean(record.passphrase),
        createdAt: record.createdAt,
        rotatedAt: record.rotatedAt,
        fingerprintSha256Hex: publicKeyFingerprint(record.publicKey),
    };
}

function getRecord(keyId: string): ManagedKeyRecord {
    const record = store.get(keyId);
    if (!record) {
        throw new CryptServiceError(`Unknown keyId: ${keyId}`, 'KEY_NOT_FOUND');
    }
    return record;
}

function requireActiveRecord(keyId: string): ManagedKeyRecord {
    const record = getRecord(keyId);
    if (record.status !== 'active') {
        throw new CryptServiceError(`Key ${keyId} is disabled`, 'KEY_DISABLED');
    }
    return record;
}

export function createManagedKey(opts: KeyGenOptions, keyId?: string) {
    const safeKeyId = keyId && keyId.trim() ? keyId.trim() : randomUUID();
    if (store.has(safeKeyId)) {
        throw new CryptServiceError(`keyId already exists: ${safeKeyId}`, 'KEY_ALREADY_EXISTS');
    }
    const generated = generateKeyPair(opts);
    const now = new Date().toISOString();
    const record: ManagedKeyRecord = {
        keyId: safeKeyId,
        type: opts.type,
        algorithm: generated.algorithm,
        status: 'active',
        publicKey: generated.publicKey,
        privateKey: generated.privateKey,
        passphrase: opts.passphrase,
        createdAt: now,
    };
    store.set(record.keyId, record);
    return { keyId: record.keyId, publicKey: record.publicKey, metadata: toMetadata(record) };
}

export function listManagedKeys(): ManagedKeyMetadata[] {
    return Array.from(store.values()).map(toMetadata);
}

export function getManagedPublicKey(keyId: string) {
    const record = getRecord(keyId);
    return {
        keyId: record.keyId,
        publicKey: record.publicKey,
        metadata: toMetadata(record),
    };
}

export function rotateManagedKey(
    keyId: string,
    opts?: { passphrase?: string; modulusLength?: 2048 | 3072 | 4096; namedCurve?: 'prime256v1' | 'secp384r1' }
) {
    const current = requireActiveRecord(keyId);
    const config: KeyGenOptions =
        current.type === 'rsa'
            ? {
                  type: 'rsa',
                  modulusLength: opts?.modulusLength ?? 2048,
                  passphrase: opts?.passphrase,
              }
            : {
                  type: 'ec',
                  namedCurve: opts?.namedCurve ?? 'prime256v1',
                  passphrase: opts?.passphrase,
              };
    const generated = generateKeyPair(config);
    const next: ManagedKeyRecord = {
        ...current,
        algorithm: generated.algorithm,
        publicKey: generated.publicKey,
        privateKey: generated.privateKey,
        passphrase: config.passphrase,
        rotatedAt: new Date().toISOString(),
    };
    store.set(keyId, next);
    return { keyId, publicKey: next.publicKey, metadata: toMetadata(next) };
}

export function disableManagedKey(keyId: string) {
    const current = getRecord(keyId);
    const next: ManagedKeyRecord = { ...current, status: 'disabled', rotatedAt: new Date().toISOString() };
    store.set(keyId, next);
    return toMetadata(next);
}

export function managedHybridEncrypt(keyId: string, plaintext: string) {
    const key = requireActiveRecord(keyId);
    if (key.type !== 'rsa') {
        throw new CryptServiceError('Hybrid encryption requires an RSA managed key', 'KEY_TYPE_UNSUPPORTED');
    }
    return {
        keyId,
        ...hybridEncrypt(plaintext, key.publicKey),
    };
}

export function managedHybridDecrypt(
    keyId: string,
    payload: { encryptedAesKey: string; iv: string; authTag: string; ciphertext: string }
) {
    const key = requireActiveRecord(keyId);
    if (key.type !== 'rsa') {
        throw new CryptServiceError('Hybrid decryption requires an RSA managed key', 'KEY_TYPE_UNSUPPORTED');
    }
    return hybridDecrypt(
        payload.encryptedAesKey,
        payload.iv,
        payload.authTag,
        payload.ciphertext,
        key.privateKey,
        key.passphrase
    );
}

export function managedSignData(keyId: string, dataBase64: string, algorithm: SignAlg) {
    const key = requireActiveRecord(keyId);
    const normalizedAlg = key.type === 'rsa' ? 'RSA-SHA256' : 'ECDSA-SHA256';
    const requested = algorithm ?? normalizedAlg;
    if (requested !== normalizedAlg) {
        throw new CryptServiceError(
            `Algorithm mismatch for key ${keyId}. Expected ${normalizedAlg}.`,
            'ALGORITHM_MISMATCH'
        );
    }
    return signData(dataBase64, key.privateKey, key.passphrase, requested);
}

export function managedVerifySignature(
    keyId: string,
    dataBase64: string,
    signatureBase64: string,
    algorithm: SignAlg
) {
    const key = requireActiveRecord(keyId);
    const normalizedAlg = key.type === 'rsa' ? 'RSA-SHA256' : 'ECDSA-SHA256';
    const requested = algorithm ?? normalizedAlg;
    if (requested !== normalizedAlg) {
        return false;
    }
    return verifySignature(dataBase64, signatureBase64, key.publicKey, requested);
}
