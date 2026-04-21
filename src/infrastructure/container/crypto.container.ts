import { CryptoApplicationService } from '../../core/application/services/crypto-application.service';
import { InMemoryManagedKeyRepository } from '../repositories/in-memory-managed-key.repository';
import { NodeCryptoAdapter } from '../adapters/node-crypto.adapter';
import { CryptoController } from '../../interfaces/http/controllers/crypto.controller';

let controllerSingleton: CryptoController | undefined;

export function getCryptoController(): CryptoController {
    if (!controllerSingleton) {
        const cryptoProvider = new NodeCryptoAdapter();
        const keyRepo = new InMemoryManagedKeyRepository();
        const appService = new CryptoApplicationService(cryptoProvider, keyRepo);
        const legacyRoutesDisabled =
            (process.env.DISABLE_LEGACY_CRYPTO_ROUTES ?? (process.env.NODE_ENV === 'production' ? 'true' : 'false')) ===
            'true';
        controllerSingleton = new CryptoController(appService, legacyRoutesDisabled);
    }
    return controllerSingleton;
}
