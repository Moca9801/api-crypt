import {
    KeyGenOptions,
    SealedBlob,
    SignAlg,
    combineHashes,
    createSignedToken,
    generateKeyPair,
    getRandomBytes,
    getRandomUuid,
    hmacSign,
    hmacVerify,
    hybridDecrypt,
    hybridEncrypt,
    pbkdf2Derive,
    publicKeyFingerprint,
    sealPayload,
    sha256Digest,
    signData,
    symmetricDecrypt,
    symmetricEncrypt,
    timingSafeCompareHex,
    unsealPayload,
    verifySignature,
    verifySignedToken,
} from '../../libs/services/crypt.service';
import { CryptoProviderPort } from '../../core/application/ports/crypto-provider.port';

export class NodeCryptoAdapter implements CryptoProviderPort {
    generateKeyPair(opts: KeyGenOptions) {
        return generateKeyPair(opts);
    }
    hybridEncrypt(plaintext: string, publicKeyPem: string) {
        return hybridEncrypt(plaintext, publicKeyPem);
    }
    hybridDecrypt(
        encryptedAesKey: string,
        iv: string,
        authTag: string,
        ciphertext: string,
        privateKeyPem: string,
        passphrase?: string
    ) {
        return hybridDecrypt(encryptedAesKey, iv, authTag, ciphertext, privateKeyPem, passphrase);
    }
    symmetricEncrypt(plaintext: string, keyB64?: string) {
        return symmetricEncrypt(plaintext, keyB64);
    }
    symmetricDecrypt(iv: string, authTag: string, ciphertext: string, key: string) {
        return symmetricDecrypt(iv, authTag, ciphertext, key);
    }
    pbkdf2Derive(password: string, salt?: string, iterations?: number) {
        return pbkdf2Derive(password, salt, iterations);
    }
    sha256Digest(data: string, input?: 'utf8' | 'base64') {
        return sha256Digest(data, input);
    }
    combineHashes(hashA: string, hashB: string, mode: 'concat-sha256' | 'hmac-sha256', hmacSecret?: string) {
        return combineHashes(hashA, hashB, mode, hmacSecret);
    }
    hmacSign(data: string, secret: string) {
        return hmacSign(data, secret);
    }
    hmacVerify(data: string, signatureHex: string, secret: string) {
        return hmacVerify(data, signatureHex, secret);
    }
    createSignedToken(payload: Record<string, unknown>, secret: string, expiresInSeconds?: number) {
        return createSignedToken(payload, secret, expiresInSeconds);
    }
    verifySignedToken(token: string, secret: string) {
        return verifySignedToken(token, secret);
    }
    sealPayload(data: Record<string, unknown>, secret: string, ttlSeconds: number): SealedBlob {
        return sealPayload(data, secret, ttlSeconds);
    }
    unsealPayload(blob: SealedBlob, secret: string) {
        return unsealPayload(blob, secret);
    }
    getRandomBytes(length: number) {
        return getRandomBytes(length);
    }
    getRandomUuid() {
        return getRandomUuid();
    }
    signData(dataB64: string, privateKeyPem: string, passphrase: string | undefined, alg: SignAlg) {
        return signData(dataB64, privateKeyPem, passphrase, alg);
    }
    verifySignature(dataB64: string, signatureB64: string, publicKeyPem: string, alg: SignAlg) {
        return verifySignature(dataB64, signatureB64, publicKeyPem, alg);
    }
    publicKeyFingerprint(publicKeyPem: string) {
        return publicKeyFingerprint(publicKeyPem);
    }
    timingSafeCompareHex(aHex: string, bHex: string) {
        return timingSafeCompareHex(aHex, bHex);
    }
}
