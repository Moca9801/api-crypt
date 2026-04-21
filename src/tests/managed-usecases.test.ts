import test from 'node:test';
import assert from 'node:assert/strict';
import { NodeCryptoAdapter } from '../infrastructure/adapters/node-crypto.adapter';
import { InMemoryManagedKeyRepository } from '../infrastructure/repositories/in-memory-managed-key.repository';
import { ManagedKeyDomainService } from '../core/application/services/managed-key-domain.service';
import { CreateManagedKeyUseCase } from '../core/application/use-cases/managed/create-managed-key.usecase';
import { ManagedHybridEncryptUseCase } from '../core/application/use-cases/managed/managed-hybrid-encrypt.usecase';
import { ManagedSignDataUseCase } from '../core/application/use-cases/managed/managed-sign-data.usecase';
import { ManagedVerifySignatureUseCase } from '../core/application/use-cases/managed/managed-verify-signature.usecase';
import { CryptServiceError } from '../libs/services/crypt.service';

function buildDeps() {
    const crypto = new NodeCryptoAdapter();
    const repo = new InMemoryManagedKeyRepository();
    const managedDomain = new ManagedKeyDomainService(crypto, repo);
    return { crypto, repo, managedDomain };
}

test('CreateManagedKeyUseCase creates RSA key and metadata', () => {
    const { crypto, repo, managedDomain } = buildDeps();
    const createUseCase = new CreateManagedKeyUseCase(crypto, repo, managedDomain);
    const result = createUseCase.execute({ type: 'rsa', modulusLength: 2048 });

    assert.equal(typeof result.keyId, 'string');
    assert.equal(result.metadata.type, 'rsa');
    assert.equal(result.metadata.status, 'active');
    assert.equal(result.metadata.passphraseProtected, false);
    assert.match(result.publicKey, /BEGIN PUBLIC KEY/);
});

test('ManagedHybridEncryptUseCase rejects non-RSA key type', () => {
    const { crypto, repo, managedDomain } = buildDeps();
    const createUseCase = new CreateManagedKeyUseCase(crypto, repo, managedDomain);
    const encryptUseCase = new ManagedHybridEncryptUseCase(crypto, managedDomain);
    const created = createUseCase.execute({ type: 'ec', namedCurve: 'prime256v1' });

    assert.throws(
        () => encryptUseCase.execute(created.keyId, 'hello'),
        (err: unknown) =>
            err instanceof CryptServiceError &&
            err.code === 'KEY_TYPE_UNSUPPORTED' &&
            err.message.includes('RSA managed key')
    );
});

test('ManagedSignDataUseCase and ManagedVerifySignatureUseCase roundtrip', () => {
    const { crypto, repo, managedDomain } = buildDeps();
    const createUseCase = new CreateManagedKeyUseCase(crypto, repo, managedDomain);
    const signUseCase = new ManagedSignDataUseCase(crypto, managedDomain);
    const verifyUseCase = new ManagedVerifySignatureUseCase(crypto, managedDomain);
    const created = createUseCase.execute({ type: 'rsa', modulusLength: 2048 });
    const dataBase64 = Buffer.from('payload-data', 'utf8').toString('base64');

    const signature = signUseCase.execute(created.keyId, dataBase64, 'RSA-SHA256');
    const valid = verifyUseCase.execute(created.keyId, dataBase64, signature, 'RSA-SHA256');
    const invalidAlg = verifyUseCase.execute(created.keyId, dataBase64, signature, 'ECDSA-SHA256');

    assert.equal(valid, true);
    assert.equal(invalidAlg, false);
});
