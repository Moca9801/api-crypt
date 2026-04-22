import { ManagedKeyRepositoryPort } from '../../core/application/ports/managed-key-repository.port';
import { KeyVaultPort } from '../../core/application/ports/key-vault.port';
import { CryptoProviderPort } from '../../core/application/ports/crypto-provider.port';
import { ManagedKeyDomainService } from '../../core/application/services/managed-key-domain.service';
import { ManagedKey } from '../../core/domain/managed-key';
import { auditLog } from '../audit/audit-logger';

/**
 * Scheduler de rotación automática de claves.
 *
 * Se ejecuta como proceso interno del servidor Node.js usando setInterval.
 * No requiere infraestructura externa (Redis, Cron, etc.).
 *
 * Intervalo configurable via ROTATION_CHECK_INTERVAL_MS (default: 1h).
 */
export class RotationScheduler {
    private timer: ReturnType<typeof setInterval> | null = null;
    private readonly intervalMs: number;

    constructor(
        private readonly managedKeyRepo: ManagedKeyRepositoryPort,
        private readonly cryptoProvider: CryptoProviderPort,
        private readonly keyVault: KeyVaultPort,
        private readonly managedDomain: ManagedKeyDomainService
    ) {
        this.intervalMs = Number(process.env.ROTATION_CHECK_INTERVAL_MS ?? '3600000');
    }

    /** Inicia el scheduler. Llama también inmediatamente al arrancar. */
    start(): void {
        console.log(
            `[RotationScheduler] Started. Checking every ${this.intervalMs / 60000} minutes.`
        );
        // Ejecutar inmediatamente al iniciar para capturar rotaciones pendientes
        void this.checkAndRotate();
        this.timer = setInterval(() => void this.checkAndRotate(), this.intervalMs);
        // Evitar que el interval bloquee el proceso en shutdown
        if (this.timer.unref) this.timer.unref();
    }

    /** Detiene el scheduler (llamado en graceful shutdown). */
    stop(): void {
        if (this.timer) {
            clearInterval(this.timer);
            this.timer = null;
            console.log('[RotationScheduler] Stopped.');
        }
    }

    /** Comprueba todas las claves con política y rota las que han expirado. */
    private async checkAndRotate(): Promise<void> {
        const now = new Date();
        const allKeys = await this.managedKeyRepo.list();
        const keys = allKeys.filter(
            (k) =>
                k.status === 'active' &&
                k.rotationPolicy !== undefined &&
                k.nextRotationAt !== undefined &&
                new Date(k.nextRotationAt) <= now
        );

        if (keys.length === 0) return;
        console.log(`[RotationScheduler] Found ${keys.length} key(s) due for rotation.`);

        for (const key of keys) {
            try {
                await this.rotateKey(key);
                console.log(`[RotationScheduler] ✅ Rotated key: ${key.keyId}`);
            } catch (err) {
                console.error(`[RotationScheduler] ❌ Failed to rotate key ${key.keyId}:`, err);
            }
        }
    }

    private async rotateKey(key: ManagedKey): Promise<void> {
        const policy = key.rotationPolicy!;
        const originalParams = this.managedDomain.getOriginalAlgorithmParams(key);
        const generated = this.cryptoProvider.generateKeyPair(originalParams);
        const nextRotationAt = this.managedDomain.computeNextRotationAt(policy.ttlDays);
        const rotated: ManagedKey = {
            ...key,
            algorithm: generated.algorithm,
            publicKey: generated.publicKey,
            encryptedPrivateKey: this.keyVault.encrypt(generated.privateKey),
            passphraseProtected: false,
            rotatedAt: new Date().toISOString(),
            nextRotationAt,
        };
        await this.managedKeyRepo.save(rotated);
        auditLog({ event: 'key.rotated.auto', keyId: key.keyId });
    }
}
