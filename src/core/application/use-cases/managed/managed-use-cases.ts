import { CreateManagedKeyInput, ManagedKeyMetadata, RotationPolicy } from '../../../domain/managed-key';
import { HybridEncryptResult, SignAlg } from '../../../../libs/services/crypt.service';
import { PendingRotationInfo } from './check-pending-rotations.usecase';

type KeyCreateResult = { keyId: string; publicKey: string; metadata: ManagedKeyMetadata };
type ManagedHybridEncryptResult = HybridEncryptResult & { keyId: string };

export interface ManagedUseCases {
    createManagedKey: { execute(input: CreateManagedKeyInput, clientIp?: string): Promise<KeyCreateResult> };
    listManagedKeys: { execute(): Promise<ManagedKeyMetadata[]> };
    getManagedPublicKey: { execute(keyId: string): Promise<{ keyId: string; publicKey: string; metadata: ManagedKeyMetadata }> };
    rotateManagedKey: { execute(keyId: string, opts?: { passphrase?: string; modulusLength?: 2048 | 3072 | 4096; namedCurve?: 'prime256v1' | 'secp384r1' }, clientIp?: string): Promise<KeyCreateResult> };
    disableManagedKey: { execute(keyId: string, clientIp?: string): Promise<ManagedKeyMetadata> };
    managedHybridEncrypt: { execute(keyId: string, plaintext: string, clientIp?: string): Promise<ManagedHybridEncryptResult> };
    managedHybridDecrypt: { execute(keyId: string, payload: { encryptedAesKey: string; iv: string; authTag: string; ciphertext: string }, passphrase?: string, clientIp?: string): Promise<string> };
    managedSignData: { execute(keyId: string, dataBase64: string, algorithm: SignAlg, passphrase?: string, clientIp?: string): Promise<string> };
    managedVerifySignature: { execute(keyId: string, dataBase64: string, signatureBase64: string, algorithm: SignAlg): Promise<boolean> };
    setRotationPolicy: { execute(keyId: string, policy: RotationPolicy, clientIp?: string): Promise<ManagedKeyMetadata> };
    checkPendingRotations: { execute(warningDays?: number): Promise<PendingRotationInfo[]> };
}
