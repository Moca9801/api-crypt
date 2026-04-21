import test from 'node:test';
import assert from 'node:assert/strict';
import { NodeCryptoAdapter } from '../infrastructure/adapters/node-crypto.adapter';
import { InMemoryManagedKeyRepository } from '../infrastructure/repositories/in-memory-managed-key.repository';
import { KeyVaultService } from '../infrastructure/crypto/key-vault';
import { ManagedKeyDomainService } from '../core/application/services/managed-key-domain.service';
import { CreateManagedKeyUseCase } from '../core/application/use-cases/managed/create-managed-key.usecase';
import { ManagedHybridEncryptUseCase } from '../core/application/use-cases/managed/managed-hybrid-encrypt.usecase';
import { ManagedHybridDecryptUseCase } from '../core/application/use-cases/managed/managed-hybrid-decrypt.usecase';
import { ManagedSignDataUseCase } from '../core/application/use-cases/managed/managed-sign-data.usecase';
import { ManagedVerifySignatureUseCase } from '../core/application/use-cases/managed/managed-verify-signature.usecase';
import { CryptServiceError } from '../libs/services/crypt.service';

/** Shared test master key — 32 zero bytes, never use outside tests. */
const TEST_MASTER_KEY = Buffer.alloc(32, 0);

function buildDeps() {
    const crypto = new NodeCryptoAdapter();
    const repo = new InMemoryManagedKeyRepository();
    const keyVault = new KeyVaultService(TEST_MASTER_KEY);
    const managedDomain = new ManagedKeyDomainService(crypto, repo);
    return { crypto, repo, keyVault, managedDomain };
}

test('CreateManagedKeyUseCase creates RSA key and metadata', () => {
    const { crypto, repo, keyVault, managedDomain } = buildDeps();
    const createUseCase = new CreateManagedKeyUseCase(crypto, repo, managedDomain, keyVault);
    const result = createUseCase.execute({ type: 'rsa', modulusLength: 2048 });

    assert.equal(typeof result.keyId, 'string');
    assert.equal(result.metadata.type, 'rsa');
    assert.equal(result.metadata.status, 'active');
    assert.equal(result.metadata.passphraseProtected, false);
    assert.match(result.publicKey, /BEGIN PUBLIC KEY/);

    // Verify private key is encrypted at rest — no plaintext PEM in stored entity
    const stored = repo.getById(result.keyId);
    assert.ok(stored, 'key must be persisted in repo');
    assert.ok(stored.encryptedPrivateKey, 'encryptedPrivateKey blob must exist');
    assert.ok(stored.encryptedPrivateKey.ciphertext, 'ciphertext must be present');
    assert.ok(!('privateKey' in stored), 'plaintext privateKey must NOT be stored');
});

test('ManagedHybridEncryptUseCase rejects non-RSA key type', () => {
    const { crypto, repo, keyVault, managedDomain } = buildDeps();
    const createUseCase = new CreateManagedKeyUseCase(crypto, repo, managedDomain, keyVault);
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
    const { crypto, repo, keyVault, managedDomain } = buildDeps();
    const createUseCase = new CreateManagedKeyUseCase(crypto, repo, managedDomain, keyVault);
    const signUseCase = new ManagedSignDataUseCase(crypto, managedDomain, keyVault);
    const verifyUseCase = new ManagedVerifySignatureUseCase(crypto, managedDomain);
    const created = createUseCase.execute({ type: 'rsa', modulusLength: 2048 });
    const dataBase64 = Buffer.from('payload-data', 'utf8').toString('base64');

    const signature = signUseCase.execute(created.keyId, dataBase64, 'RSA-SHA256');
    const valid = verifyUseCase.execute(created.keyId, dataBase64, signature, 'RSA-SHA256');
    const invalidAlg = verifyUseCase.execute(created.keyId, dataBase64, signature, 'ECDSA-SHA256');

    assert.equal(valid, true);
    assert.equal(invalidAlg, false);
});

test('ManagedHybridDecryptUseCase roundtrip: encrypt then decrypt', () => {
    const { crypto, repo, keyVault, managedDomain } = buildDeps();
    const createUseCase = new CreateManagedKeyUseCase(crypto, repo, managedDomain, keyVault);
    const encryptUseCase = new ManagedHybridEncryptUseCase(crypto, managedDomain);
    const decryptUseCase = new ManagedHybridDecryptUseCase(crypto, managedDomain, keyVault);

    const created = createUseCase.execute({ type: 'rsa', modulusLength: 2048 });
    const plaintext = 'secret message for the vault';

    const encrypted = encryptUseCase.execute(created.keyId, plaintext);
    const decrypted = decryptUseCase.execute(created.keyId, {
        encryptedAesKey: encrypted.encryptedAesKey,
        iv: encrypted.iv,
        authTag: encrypted.authTag,
        ciphertext: encrypted.ciphertext,
    });

    assert.equal(decrypted, plaintext);
});

test('KeyVaultService encrypts and decrypts private key PEM correctly', () => {
    const keyVault = new KeyVaultService(TEST_MASTER_KEY);
    const fakePem = '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BA==\n-----END PRIVATE KEY-----';

    const blob = keyVault.encrypt(fakePem);
    assert.ok(blob.iv, 'blob must have iv');
    assert.ok(blob.authTag, 'blob must have authTag');
    assert.ok(blob.ciphertext, 'blob must have ciphertext');
    assert.notEqual(blob.ciphertext, Buffer.from(fakePem).toString('base64'), 'ciphertext must not be plaintext');

    const recovered = keyVault.decrypt(blob);
    assert.equal(recovered, fakePem, 'decrypted PEM must match original');
});
