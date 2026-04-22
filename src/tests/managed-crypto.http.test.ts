import test from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import { App } from '../app';
import { getScheduler } from '../infrastructure/container/crypto.container';

const API_KEY = 'test-api-key';

test('ManagedCrypto API - Integration', async (t) => {
    // Setup test environment variables
    process.env.API_KEY = API_KEY;
    process.env.MASTER_KEY = Buffer.alloc(32, 0).toString('hex');
    process.env.NODE_ENV = 'test';
    
    const appInstance = new App();
    const expressApp = appInstance.app;
    
    // Stop the scheduler so the test process can exit cleanly
    getScheduler()?.stop();

    let createdKeyId: string;

    await t.test('Setup: Create an RSA key', async () => {
        const response = await request(expressApp)
            .post('/api/v1/crypto/keys/managed/create')
            .set('x-api-key', API_KEY)
            .send({ type: 'rsa', modulusLength: 2048 });

        assert.equal(response.status, 200, response.text);
        createdKeyId = response.body.keyId;
    });

    let encryptedPayload: any;

    await t.test('POST /api/v1/crypto/managed/hybrid/encrypt', async () => {
        const response = await request(expressApp)
            .post('/api/v1/crypto/managed/hybrid/encrypt')
            .set('x-api-key', API_KEY)
            .send({ keyId: createdKeyId, plaintext: 'Integration Test Secret' });

        assert.equal(response.status, 200, response.text);
        assert.equal(response.body.ok, true);
        assert.ok(response.body.encryptedAesKey);
        assert.ok(response.body.ciphertext);
        
        encryptedPayload = {
            keyId: createdKeyId,
            encryptedAesKey: response.body.encryptedAesKey,
            iv: response.body.iv,
            authTag: response.body.authTag,
            ciphertext: response.body.ciphertext,
        };
    });

    await t.test('POST /api/v1/crypto/managed/hybrid/decrypt', async () => {
        const response = await request(expressApp)
            .post('/api/v1/crypto/managed/hybrid/decrypt')
            .set('x-api-key', API_KEY)
            .send(encryptedPayload);

        assert.equal(response.status, 200, response.text);
        assert.equal(response.body.ok, true);
        assert.equal(response.body.plaintext, 'Integration Test Secret');
    });

    let signatureBase64: string;
    const dataBase64 = Buffer.from('Integration test data').toString('base64');

    await t.test('POST /api/v1/crypto/managed/sign/data', async () => {
        const response = await request(expressApp)
            .post('/api/v1/crypto/managed/sign/data')
            .set('x-api-key', API_KEY)
            .send({ keyId: createdKeyId, dataBase64, algorithm: 'RSA-SHA256' });

        assert.equal(response.status, 200, response.text);
        assert.equal(response.body.ok, true);
        assert.ok(response.body.signatureBase64);
        
        signatureBase64 = response.body.signatureBase64;
    });

    await t.test('POST /api/v1/crypto/managed/sign/verify', async () => {
        const response = await request(expressApp)
            .post('/api/v1/crypto/managed/sign/verify')
            .set('x-api-key', API_KEY)
            .send({ keyId: createdKeyId, dataBase64, signatureBase64, algorithm: 'RSA-SHA256' });

        assert.equal(response.status, 200, response.text);
        assert.equal(response.body.ok, true);
        assert.equal(response.body.valid, true);
    });
});
