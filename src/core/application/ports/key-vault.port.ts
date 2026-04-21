import { EncryptedKeyBlob } from '../../domain/managed-key';

/**
 * Port for encrypting and decrypting private key PEMs at rest.
 * Implemented in the infrastructure layer using the server's MASTER_KEY.
 */
export interface KeyVaultPort {
    /** Encrypt a plaintext private key PEM and return an opaque blob. */
    encrypt(pem: string): EncryptedKeyBlob;
    /** Decrypt an encrypted blob back to the private key PEM. */
    decrypt(blob: EncryptedKeyBlob): string;
}
