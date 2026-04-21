import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';
import { EncryptedKeyBlob } from '../../core/domain/managed-key';
import { KeyVaultPort } from '../../core/application/ports/key-vault.port';
import { CryptServiceError } from '../../libs/services/crypt.service';

const AES_KEY_LEN = 32;
const GCM_IV_LEN = 12;

/**
 * Encrypts and decrypts private key PEMs using AES-256-GCM with a server-managed MASTER_KEY.
 * Each encrypt() call uses a fresh random IV — ciphertexts are never reused.
 */
export class KeyVaultService implements KeyVaultPort {
    constructor(private readonly masterKey: Buffer) {
        if (masterKey.length !== AES_KEY_LEN) {
            throw new Error(
                `KeyVaultService: masterKey must be exactly ${AES_KEY_LEN} bytes ` +
                `(${AES_KEY_LEN * 2} hex chars). Got ${masterKey.length} bytes.`
            );
        }
    }

    encrypt(pem: string): EncryptedKeyBlob {
        const iv = randomBytes(GCM_IV_LEN);
        const cipher = createCipheriv('aes-256-gcm', this.masterKey, iv);
        const enc = Buffer.concat([cipher.update(pem, 'utf8'), cipher.final()]);
        const authTag = cipher.getAuthTag();
        return {
            iv: iv.toString('base64'),
            authTag: authTag.toString('base64'),
            ciphertext: enc.toString('base64'),
        };
    }

    decrypt(blob: EncryptedKeyBlob): string {
        try {
            const iv = Buffer.from(blob.iv, 'base64');
            const authTag = Buffer.from(blob.authTag, 'base64');
            const ciphertext = Buffer.from(blob.ciphertext, 'base64');
            const decipher = createDecipheriv('aes-256-gcm', this.masterKey, iv);
            decipher.setAuthTag(authTag);
            return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
        } catch {
            throw new CryptServiceError(
                'Failed to decrypt private key. Is MASTER_KEY correct and unchanged?',
                'KEY_DECRYPTION_FAILED'
            );
        }
    }
}
