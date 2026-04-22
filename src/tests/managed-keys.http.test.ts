import test from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import { App } from '../app';
import { getScheduler } from '../infrastructure/container/crypto.container';

const API_KEY = 'test-api-key';

test('ManagedKeys API - Integration', async (t) => {
    // Setup test environment variables
    process.env.API_KEY = API_KEY;
    process.env.MASTER_KEY = Buffer.alloc(32, 0).toString('hex');
    process.env.NODE_ENV = 'test';
    
    const appInstance = new App();
    const expressApp = appInstance.app;
    
    // Stop the scheduler so the test process can exit cleanly
    getScheduler()?.stop();

    let createdKeyId: string;

    await t.test('POST /api/v1/crypto/keys/managed/create (RSA)', async () => {
        const response = await request(expressApp)
            .post('/api/v1/crypto/keys/managed/create')
            .set('x-api-key', API_KEY)
            .send({ type: 'rsa', modulusLength: 2048 });

        assert.equal(response.status, 200, response.text);
        assert.equal(response.body.ok, true);
        assert.equal(typeof response.body.keyId, 'string');
        assert.equal(response.body.metadata.type, 'rsa');
        assert.equal(response.body.metadata.status, 'active');
        
        createdKeyId = response.body.keyId;
    });

    await t.test('GET /api/v1/crypto/keys/managed', async () => {
        const response = await request(expressApp)
            .get('/api/v1/crypto/keys/managed')
            .set('x-api-key', API_KEY);

        assert.equal(response.status, 200, response.text);
        assert.equal(response.body.ok, true);
        assert.ok(Array.isArray(response.body.keys));
        
        const found = response.body.keys.find((k: any) => k.keyId === createdKeyId);
        assert.ok(found, 'Created key should be in the list');
    });

    await t.test('GET /api/v1/crypto/keys/managed/:keyId/public', async () => {
        const response = await request(expressApp)
            .get(`/api/v1/crypto/keys/managed/${createdKeyId}/public`)
            .set('x-api-key', API_KEY);

        assert.equal(response.status, 200, response.text);
        assert.equal(response.body.ok, true);
        assert.ok(response.body.publicKey.includes('BEGIN PUBLIC KEY'));
    });

    await t.test('POST /api/v1/crypto/keys/managed/:keyId/disable', async () => {
        const response = await request(expressApp)
            .post(`/api/v1/crypto/keys/managed/${createdKeyId}/disable`)
            .set('x-api-key', API_KEY);

        assert.equal(response.status, 200, response.text);
        assert.equal(response.body.ok, true);
        assert.equal(response.body.metadata.status, 'disabled');
    });

    await t.test('POST /api/v1/crypto/keys/managed/create (Fail validation)', async () => {
        const response = await request(expressApp)
            .post('/api/v1/crypto/keys/managed/create')
            .set('x-api-key', API_KEY)
            .send({ type: 'invalid_type' }); // Zod will block this

        assert.equal(response.status, 400);
        assert.equal(response.body.ok, false);
        assert.ok(response.body.error.includes('Validation error'));
    });
});
