import { CreateManagedKeyInput } from '../../../domain/managed-key';
import { HybridEncryptResult, SignAlg } from '../../../../libs/services/crypt.service';
import { ManagedKeyMetadata } from '../../../domain/managed-key';

type ManagedKeyCreateResult = {
    keyId: string;
    publicKey: string;
    metadata: ManagedKeyMetadata;
};

type ManagedKeyPublicResult = {
    keyId: string;
    publicKey: string;
    metadata: ManagedKeyMetadata;
};

type ManagedHybridEncryptResult = HybridEncryptResult & {
    keyId: string;
};

export interface ManagedUseCases {
    createManagedKey: { execute(input: CreateManagedKeyInput): ManagedKeyCreateResult };
    listManagedKeys: { execute(): ManagedKeyMetadata[] };
    getManagedPublicKey: { execute(keyId: string): ManagedKeyPublicResult };
    rotateManagedKey: {
        execute(
            keyId: string,
            opts?: { passphrase?: string; modulusLength?: 2048 | 3072 | 4096; namedCurve?: 'prime256v1' | 'secp384r1' }
        ): ManagedKeyCreateResult;
    };
    disableManagedKey: { execute(keyId: string): ManagedKeyMetadata };
    managedHybridEncrypt: { execute(keyId: string, plaintext: string): ManagedHybridEncryptResult };
    managedHybridDecrypt: {
        execute(keyId: string, payload: { encryptedAesKey: string; iv: string; authTag: string; ciphertext: string }): string;
    };
    managedSignData: { execute(keyId: string, dataBase64: string, algorithm: SignAlg): string };
    managedVerifySignature: { execute(keyId: string, dataBase64: string, signatureBase64: string, algorithm: SignAlg): boolean };
}
