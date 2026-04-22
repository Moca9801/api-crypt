import { Request, Response } from 'express';
import { ManagedUseCases } from '../../../core/application/use-cases/managed/managed-use-cases';
import { CryptServiceError } from '../../../libs/services/crypt.service';
import { CreateKeyInput, RotateKeyInput, SetRotationPolicyInput } from '../schemas/managed-keys.schemas';

export class ManagedKeysController {
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

    createManagedKey = async (req: Request, res: Response) => {
        try {
            const body = req.body as CreateKeyInput;
            const result = await this.managedUseCases.createManagedKey.execute(body, this.clientIp(req));
            return res.json({ ok: true, ...result });
        } catch (err) { return this.sendError(res, err); }
    };

    listManagedKeys = async (_req: Request, res: Response) => {
        try {
            return res.json({ ok: true, keys: await this.managedUseCases.listManagedKeys.execute() });
        } catch (err) { return this.sendError(res, err); }
    };

    getManagedPublicKey = async (req: Request, res: Response) => {
        try {
            return res.json({ ok: true, ...await this.managedUseCases.getManagedPublicKey.execute(req.params.keyId) });
        } catch (err) { return this.sendError(res, err); }
    };

    rotateManagedKey = async (req: Request, res: Response) => {
        try {
            const body = req.body as RotateKeyInput;
            return res.json({ ok: true, ...await this.managedUseCases.rotateManagedKey.execute(req.params.keyId, body, this.clientIp(req)) });
        } catch (err) { return this.sendError(res, err); }
    };

    disableManagedKey = async (req: Request, res: Response) => {
        try {
            return res.json({ ok: true, metadata: await this.managedUseCases.disableManagedKey.execute(req.params.keyId, this.clientIp(req)) });
        } catch (err) { return this.sendError(res, err); }
    };

    setRotationPolicy = async (req: Request, res: Response) => {
        try {
            const body = req.body as SetRotationPolicyInput;
            return res.json({ ok: true, metadata: await this.managedUseCases.setRotationPolicy.execute(req.params.keyId, body, this.clientIp(req)) });
        } catch (err) { return this.sendError(res, err); }
    };


    checkPendingRotations = async (req: Request, res: Response) => {
        try {
            const warningDays = req.query.warningDays ? parseInt(String(req.query.warningDays), 10) : 7;
            const pending = await this.managedUseCases.checkPendingRotations.execute(warningDays);
            return res.json({ ok: true, count: pending.length, keys: pending });
        } catch (err) { return this.sendError(res, err); }
    };
}
