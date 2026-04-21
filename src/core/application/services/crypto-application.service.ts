import { randomUUID } from 'crypto';
import { CryptServiceError, KeyGenOptions, SealedBlob, SignAlg } from '../../../libs/services/crypt.service';
import { CreateManagedKeyInput, ManagedKey, ManagedKeyMetadata } from '../../domain/managed-key';
import { CryptoProviderPort } from '../ports/crypto-provider.port';
import { ManagedKeyRepositoryPort } from '../ports/managed-key-repository.port';

export class CryptoApplicationService {
    constructor(
        private readonly cryptoProvider: CryptoProviderPort,
        private readonly managedKeyRepo: ManagedKeyRepositoryPort
    ) {}

    private toMetadata(key: ManagedKey): ManagedKeyMetadata {
        return {
            keyId: key.keyId,
            type: key.type,
            algorithm: key.algorithm,
            status: key.status,
            passphraseProtected: Boolean(key.passphrase),
            createdAt: key.createdAt,
            rotatedAt: key.rotatedAt,
            fingerprintSha256Hex: this.cryptoProvider.publicKeyFingerprint(key.publicKey),
        };
    }

    private getOrThrow(keyId: string): ManagedKey {
        const key = this.managedKeyRepo.getById(keyId);
        if (!key) {
            throw new CryptServiceError(`Unknown keyId: ${keyId}`, 'KEY_NOT_FOUND');
        }
        return key;
    }

    private getActiveOrThrow(keyId: string): ManagedKey {
        const key = this.getOrThrow(keyId);
        if (key.status !== 'active') {
            throw new CryptServiceError(`Key ${keyId} is disabled`, 'KEY_DISABLED');
        }
        return key;
    }

    private buildKeyGenOptions(input: CreateManagedKeyInput): KeyGenOptions {
        if (input.type === 'rsa') {
            return {
                type: 'rsa',
                modulusLength: input.modulusLength ?? 2048,
                passphrase: input.passphrase,
            };
        }
        return {
            type: 'ec',
            namedCurve: input.namedCurve ?? 'prime256v1',
            passphrase: input.passphrase,
        };
    }

    createManagedKey(input: CreateManagedKeyInput) {
        const keyId = input.keyId && input.keyId.trim() ? input.keyId.trim() : randomUUID();
        if (this.managedKeyRepo.getById(keyId)) {
            throw new CryptServiceError(`keyId already exists: ${keyId}`, 'KEY_ALREADY_EXISTS');
        }
        const generated = this.cryptoProvider.generateKeyPair(this.buildKeyGenOptions(input));
        const key: ManagedKey = {
            keyId,
            type: input.type,
            algorithm: generated.algorithm,
            status: 'active',
            publicKey: generated.publicKey,
            privateKey: generated.privateKey,
            passphrase: input.passphrase,
            createdAt: new Date().toISOString(),
        };
        this.managedKeyRepo.save(key);
        return { keyId: key.keyId, publicKey: key.publicKey, metadata: this.toMetadata(key) };
    }

    listManagedKeys() {
        return this.managedKeyRepo.list().map((item) => this.toMetadata(item));
    }

    getManagedPublicKey(keyId: string) {
        const key = this.getOrThrow(keyId);
        return { keyId, publicKey: key.publicKey, metadata: this.toMetadata(key) };
    }

    rotateManagedKey(
        keyId: string,
        opts?: { passphrase?: string; modulusLength?: 2048 | 3072 | 4096; namedCurve?: 'prime256v1' | 'secp384r1' }
    ) {
        const current = this.getActiveOrThrow(keyId);
        const generated = this.cryptoProvider.generateKeyPair(
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
                  }
        );
        const updated: ManagedKey = {
            ...current,
            algorithm: generated.algorithm,
            publicKey: generated.publicKey,
            privateKey: generated.privateKey,
            passphrase: opts?.passphrase,
            rotatedAt: new Date().toISOString(),
        };
        this.managedKeyRepo.save(updated);
        return { keyId, publicKey: updated.publicKey, metadata: this.toMetadata(updated) };
    }

    disableManagedKey(keyId: string) {
        const key = this.getOrThrow(keyId);
        const updated: ManagedKey = { ...key, status: 'disabled', rotatedAt: new Date().toISOString() };
        this.managedKeyRepo.save(updated);
        return this.toMetadata(updated);
    }

    managedHybridEncrypt(keyId: string, plaintext: string) {
        const key = this.getActiveOrThrow(keyId);
        if (key.type !== 'rsa') {
            throw new CryptServiceError('Hybrid encryption requires an RSA managed key', 'KEY_TYPE_UNSUPPORTED');
        }
        return { keyId, ...this.cryptoProvider.hybridEncrypt(plaintext, key.publicKey) };
    }

    managedHybridDecrypt(
        keyId: string,
        payload: { encryptedAesKey: string; iv: string; authTag: string; ciphertext: string }
    ) {
        const key = this.getActiveOrThrow(keyId);
        if (key.type !== 'rsa') {
            throw new CryptServiceError('Hybrid decryption requires an RSA managed key', 'KEY_TYPE_UNSUPPORTED');
        }
        return this.cryptoProvider.hybridDecrypt(
            payload.encryptedAesKey,
            payload.iv,
            payload.authTag,
            payload.ciphertext,
            key.privateKey,
            key.passphrase
        );
    }

    managedSignData(keyId: string, dataBase64: string, algorithm: SignAlg) {
        const key = this.getActiveOrThrow(keyId);
        const expected: SignAlg = key.type === 'rsa' ? 'RSA-SHA256' : 'ECDSA-SHA256';
        if (algorithm !== expected) {
            throw new CryptServiceError(`Algorithm mismatch for key ${keyId}. Expected ${expected}.`, 'ALGORITHM_MISMATCH');
        }
        return this.cryptoProvider.signData(dataBase64, key.privateKey, key.passphrase, algorithm);
    }

    managedVerifySignature(keyId: string, dataBase64: string, signatureBase64: string, algorithm: SignAlg) {
        const key = this.getActiveOrThrow(keyId);
        const expected: SignAlg = key.type === 'rsa' ? 'RSA-SHA256' : 'ECDSA-SHA256';
        if (algorithm !== expected) {
            return false;
        }
        return this.cryptoProvider.verifySignature(dataBase64, signatureBase64, key.publicKey, algorithm);
    }

    generateLegacyKeyPair(opts: KeyGenOptions) {
        return this.cryptoProvider.generateKeyPair(opts);
    }
    fingerprintPublicKey(publicKeyPem: string) {
        return this.cryptoProvider.publicKeyFingerprint(publicKeyPem);
    }
    hybridEncrypt(plaintext: string, publicKeyPem: string) {
        return this.cryptoProvider.hybridEncrypt(plaintext, publicKeyPem);
    }
    hybridDecrypt(
        encryptedAesKey: string,
        iv: string,
        authTag: string,
        ciphertext: string,
        privateKeyPem: string,
        passphrase?: string
    ) {
        return this.cryptoProvider.hybridDecrypt(encryptedAesKey, iv, authTag, ciphertext, privateKeyPem, passphrase);
    }
    symmetricEncrypt(plaintext: string, keyB64?: string) {
        return this.cryptoProvider.symmetricEncrypt(plaintext, keyB64);
    }
    symmetricDecrypt(iv: string, authTag: string, ciphertext: string, key: string) {
        return this.cryptoProvider.symmetricDecrypt(iv, authTag, ciphertext, key);
    }
    pbkdf2Derive(password: string, salt?: string, iterations?: number) {
        return this.cryptoProvider.pbkdf2Derive(password, salt, iterations);
    }
    sha256Digest(data: string, input?: 'utf8' | 'base64') {
        return this.cryptoProvider.sha256Digest(data, input);
    }
    combineHashes(hashA: string, hashB: string, mode: 'concat-sha256' | 'hmac-sha256', hmacSecret?: string) {
        return this.cryptoProvider.combineHashes(hashA, hashB, mode, hmacSecret);
    }
    hmacSign(data: string, secret: string) {
        return this.cryptoProvider.hmacSign(data, secret);
    }
    hmacVerify(data: string, signatureHex: string, secret: string) {
        return this.cryptoProvider.hmacVerify(data, signatureHex, secret);
    }
    createSignedToken(payload: Record<string, unknown>, secret: string, expiresInSeconds?: number) {
        return this.cryptoProvider.createSignedToken(payload, secret, expiresInSeconds);
    }
    verifySignedToken(token: string, secret: string) {
        return this.cryptoProvider.verifySignedToken(token, secret);
    }
    sealPayload(data: Record<string, unknown>, secret: string, ttlSeconds: number): SealedBlob {
        return this.cryptoProvider.sealPayload(data, secret, ttlSeconds);
    }
    unsealPayload(blob: SealedBlob, secret: string) {
        return this.cryptoProvider.unsealPayload(blob, secret);
    }
    getRandomBytes(length: number) {
        return this.cryptoProvider.getRandomBytes(length);
    }
    getRandomUuid() {
        return this.cryptoProvider.getRandomUuid();
    }
    signData(dataB64: string, privateKeyPem: string, passphrase: string | undefined, alg: SignAlg) {
        return this.cryptoProvider.signData(dataB64, privateKeyPem, passphrase, alg);
    }
    verifySignature(dataB64: string, signatureB64: string, publicKeyPem: string, alg: SignAlg) {
        return this.cryptoProvider.verifySignature(dataB64, signatureB64, publicKeyPem, alg);
    }
    timingSafeCompareHex(aHex: string, bHex: string) {
        return this.cryptoProvider.timingSafeCompareHex(aHex, bHex);
    }
}
