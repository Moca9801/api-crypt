import { CryptoApplicationService } from '../../core/application/services/crypto-application.service';
import { InMemoryManagedKeyRepository } from '../repositories/in-memory-managed-key.repository';
import { NodeCryptoAdapter } from '../adapters/node-crypto.adapter';
import { CryptoController } from '../../interfaces/http/controllers/crypto.controller';
import { ManagedKeyDomainService } from '../../core/application/services/managed-key-domain.service';
import { CreateManagedKeyUseCase } from '../../core/application/use-cases/managed/create-managed-key.usecase';
import { ListManagedKeysUseCase } from '../../core/application/use-cases/managed/list-managed-keys.usecase';
import { GetManagedPublicKeyUseCase } from '../../core/application/use-cases/managed/get-managed-public-key.usecase';
import { RotateManagedKeyUseCase } from '../../core/application/use-cases/managed/rotate-managed-key.usecase';
import { DisableManagedKeyUseCase } from '../../core/application/use-cases/managed/disable-managed-key.usecase';
import { ManagedHybridEncryptUseCase } from '../../core/application/use-cases/managed/managed-hybrid-encrypt.usecase';
import { ManagedHybridDecryptUseCase } from '../../core/application/use-cases/managed/managed-hybrid-decrypt.usecase';
import { ManagedSignDataUseCase } from '../../core/application/use-cases/managed/managed-sign-data.usecase';
import { ManagedVerifySignatureUseCase } from '../../core/application/use-cases/managed/managed-verify-signature.usecase';
import { ManagedUseCases } from '../../core/application/use-cases/managed/managed-use-cases';

let controllerSingleton: CryptoController | undefined;

export function getCryptoController(): CryptoController {
    if (!controllerSingleton) {
        const cryptoProvider = new NodeCryptoAdapter();
        const keyRepo = new InMemoryManagedKeyRepository();
        const managedDomain = new ManagedKeyDomainService(cryptoProvider, keyRepo);
        const managedUseCases: ManagedUseCases = {
            createManagedKey: new CreateManagedKeyUseCase(cryptoProvider, keyRepo, managedDomain),
            listManagedKeys: new ListManagedKeysUseCase(keyRepo, managedDomain),
            getManagedPublicKey: new GetManagedPublicKeyUseCase(managedDomain),
            rotateManagedKey: new RotateManagedKeyUseCase(cryptoProvider, keyRepo, managedDomain),
            disableManagedKey: new DisableManagedKeyUseCase(keyRepo, managedDomain),
            managedHybridEncrypt: new ManagedHybridEncryptUseCase(cryptoProvider, managedDomain),
            managedHybridDecrypt: new ManagedHybridDecryptUseCase(cryptoProvider, managedDomain),
            managedSignData: new ManagedSignDataUseCase(cryptoProvider, managedDomain),
            managedVerifySignature: new ManagedVerifySignatureUseCase(cryptoProvider, managedDomain),
        };
        const appService = new CryptoApplicationService(cryptoProvider, keyRepo);
        const legacyRoutesDisabled =
            (process.env.DISABLE_LEGACY_CRYPTO_ROUTES ?? (process.env.NODE_ENV === 'production' ? 'true' : 'false')) ===
            'true';
        controllerSingleton = new CryptoController(appService, managedUseCases, legacyRoutesDisabled);
    }
    return controllerSingleton;
}
