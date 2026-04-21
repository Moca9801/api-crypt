import { KeyGenOptions, SealedBlob, SignAlg } from '../../../libs/services/crypt.service';

export interface CryptoProviderPort {
    generateKeyPair(opts: KeyGenOptions): { algorithm: string; publicKey: string; privateKey: string };
    hybridEncrypt(plaintext: string, publicKeyPem: string): {
        scheme: string;
        encryptedAesKey: string;
        iv: string;
        authTag: string;
        ciphertext: string;
    };
    hybridDecrypt(
        encryptedAesKey: string,
        iv: string,
        authTag: string,
        ciphertext: string,
        privateKeyPem: string,
        passphrase?: string
    ): string;
    symmetricEncrypt(plaintext: string, keyB64?: string): { iv: string; authTag: string; ciphertext: string; key: string };
    symmetricDecrypt(iv: string, authTag: string, ciphertext: string, key: string): string;
    pbkdf2Derive(password: string, salt?: string, iterations?: number): {
        algorithm: string;
        iterations: number;
        salt: string;
        derivedKey: string;
    };
    sha256Digest(data: string, input?: 'utf8' | 'base64'): string;
    combineHashes(hashA: string, hashB: string, mode: 'concat-sha256' | 'hmac-sha256', hmacSecret?: string): {
        mode: string;
        combined: string;
    };
    hmacSign(data: string, secret: string): string;
    hmacVerify(data: string, signatureHex: string, secret: string): boolean;
    createSignedToken(payload: Record<string, unknown>, secret: string, expiresInSeconds?: number): string;
    verifySignedToken(token: string, secret: string): Record<string, unknown>;
    sealPayload(data: Record<string, unknown>, secret: string, ttlSeconds: number): SealedBlob;
    unsealPayload(blob: SealedBlob, secret: string): Record<string, unknown>;
    getRandomBytes(length: number): Buffer;
    getRandomUuid(): string;
    signData(dataB64: string, privateKeyPem: string, passphrase: string | undefined, alg: SignAlg): string;
    verifySignature(dataB64: string, signatureB64: string, publicKeyPem: string, alg: SignAlg): boolean;
    publicKeyFingerprint(publicKeyPem: string): string;
    timingSafeCompareHex(aHex: string, bHex: string): boolean;
}
