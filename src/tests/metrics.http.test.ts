import test from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import { App } from '../app';
import { getScheduler } from '../infrastructure/container/crypto.container';

const API_KEY = 'test-api-key';

test('Metrics endpoint IP allowlist', async (t) => {
    process.env.API_KEY = API_KEY;
    process.env.MASTER_KEY = Buffer.alloc(32, 0).toString('hex');
    process.env.NODE_ENV = 'test';
    process.env.TRUST_PROXY = '1';
    process.env.METRICS_ALLOWED_IPS = '127.0.0.1';

    const appInstance = new App();
    const expressApp = appInstance.app;

    // Stop scheduler initialized by crypto container in integration tests.
    getScheduler()?.stop();

    await t.test('GET /api/v1/metrics allows IPv4-mapped localhost', async () => {
        const response = await request(expressApp)
            .get('/api/v1/metrics')
            .set('x-forwarded-for', '::ffff:127.0.0.1');

        assert.equal(response.status, 200, response.text);
        assert.ok(String(response.headers['content-type']).startsWith('text/plain'));
        assert.ok(response.text.length > 0);
    });

    await t.test('GET /api/v1/metrics rejects non-allowlisted IP', async () => {
        const response = await request(expressApp)
            .get('/api/v1/metrics')
            .set('x-forwarded-for', '10.10.10.10');

        assert.equal(response.status, 403, response.text);
        assert.equal(response.body.ok, false);
    });
});
