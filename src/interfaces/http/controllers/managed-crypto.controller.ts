import { Request, Response } from 'express';
import { ManagedUseCases } from '../../../core/application/use-cases/managed/managed-use-cases';
import { CryptServiceError, SignAlg } from '../../../libs/services/crypt.service';
import { HybridDecryptInput, HybridEncryptInput, SignDataInput, VerifySignatureInput } from '../schemas/managed-crypto.schemas';

export class ManagedCryptoController {
    constructor(private readonly managedUseCases: ManagedUseCases) {}

    private clientIp(req: Request): string {
        return req.ip ?? req.socket.remoteAddress ?? 'unknown';
    }

    private sendError(res: Response, err: unknown) {
        if (err instanceof CryptServiceError) {
            return res.status(400).json({ ok: false, error: err.message, code: err.code });
        }
        console.error(err);
        return res.status(500).json({ ok: false, error: 'Internal server error' });
    }

    managedHybridEncrypt = async (req: Request, res: Response) => {
        try {
            const { keyId, plaintext } = req.body as HybridEncryptInput;
            return res.json({ ok: true, ...await this.managedUseCases.managedHybridEncrypt.execute(keyId, plaintext, this.clientIp(req)) });
        } catch (err) { return this.sendError(res, err); }
    };

    managedHybridDecrypt = async (req: Request, res: Response) => {
        try {
            const { keyId, encryptedAesKey, iv, authTag, ciphertext, passphrase } = req.body as HybridDecryptInput;
            const plaintext = await this.managedUseCases.managedHybridDecrypt.execute(
                keyId, { encryptedAesKey, iv, authTag, ciphertext }, passphrase, this.clientIp(req)
            );
            return res.json({ ok: true, plaintext });
        } catch (err) { return this.sendError(res, err); }
    };

    managedSignData = async (req: Request, res: Response) => {
        try {
            const { keyId, dataBase64, algorithm, passphrase } = req.body as SignDataInput;
            const signatureBase64 = await this.managedUseCases.managedSignData.execute(
                keyId, dataBase64, algorithm as SignAlg, passphrase, this.clientIp(req)
            );
            return res.json({ ok: true, signatureBase64 });
        } catch (err) { return this.sendError(res, err); }
    };

    managedSignVerify = async (req: Request, res: Response) => {
        try {
            const { keyId, dataBase64, signatureBase64, algorithm } = req.body as VerifySignatureInput;
            const valid = await this.managedUseCases.managedVerifySignature.execute(
                keyId, dataBase64, signatureBase64, algorithm as SignAlg
            );
            return res.json({ ok: true, valid });
        } catch (err) { return this.sendError(res, err); }
    };
}
