export function getOpenApiDocument() {
    return {
        openapi: '3.0.3',
        info: {
            title: 'api-crypt',
            version: '1.0.0',
            description: 'Prototype cryptographic API with managed keys, auth, and rate limiting.',
        },
        servers: [{ url: 'http://localhost:3000' }],
        tags: [
            { name: 'Managed Keys' },
            { name: 'Hybrid' },
            { name: 'Signatures' },
            { name: 'Hash/HMAC' },
            { name: 'Utility' },
        ],
        components: {
            securitySchemes: {
                ApiKeyAuth: {
                    type: 'apiKey',
                    in: 'header',
                    name: 'x-api-key',
                },
            },
        },
        security: [{ ApiKeyAuth: [] }],
        paths: {
            '/api/v1': {
                get: {
                    tags: ['Utility'],
                    summary: 'List main API endpoints',
                    security: [],
                    responses: { '200': { description: 'Endpoint discovery response' } },
                },
            },
            '/api/v1/docs/openapi.json': {
                get: {
                    tags: ['Utility'],
                    summary: 'Return OpenAPI JSON document',
                    security: [],
                    responses: { '200': { description: 'OpenAPI schema' } },
                },
            },
            '/api/v1/health': {
                get: {
                    tags: ['Utility'],
                    summary: 'Service health check',
                    security: [],
                    responses: { '200': { description: 'Health check response' } },
                },
            },
            '/api/v1/metrics': {
                get: {
                    tags: ['Utility'],
                    summary: 'Prometheus metrics',
                    security: [],
                    responses: { '200': { description: 'Prometheus metrics text' } },
                },
            },
            '/api/v1/crypto/keys/managed/create': {
                post: {
                    tags: ['Managed Keys'],
                    summary: 'Create a server-managed key and return keyId + public key',
                    responses: { '200': { description: 'Managed key created' } },
                },
            },
            '/api/v1/crypto/keys/managed': {
                get: {
                    tags: ['Managed Keys'],
                    summary: 'List managed key metadata',
                    responses: { '200': { description: 'Managed key metadata list' } },
                },
            },
            '/api/v1/crypto/keys/managed/{keyId}/public': {
                get: {
                    tags: ['Managed Keys'],
                    summary: 'Get managed key public PEM',
                    parameters: [{ name: 'keyId', in: 'path', required: true, schema: { type: 'string' } }],
                    responses: { '200': { description: 'Public key material' } },
                },
            },
            '/api/v1/crypto/keys/managed/{keyId}/rotate': {
                post: {
                    tags: ['Managed Keys'],
                    summary: 'Rotate a managed key in place',
                    parameters: [{ name: 'keyId', in: 'path', required: true, schema: { type: 'string' } }],
                    responses: { '200': { description: 'Managed key rotated' } },
                },
            },
            '/api/v1/crypto/keys/managed/{keyId}/disable': {
                post: {
                    tags: ['Managed Keys'],
                    summary: 'Disable a managed key',
                    parameters: [{ name: 'keyId', in: 'path', required: true, schema: { type: 'string' } }],
                    responses: { '200': { description: 'Managed key disabled' } },
                },
            },
            '/api/v1/crypto/keys/managed/{keyId}/policy': {
                post: {
                    tags: ['Managed Keys'],
                    summary: 'Set rotation policy for a key',
                    parameters: [{ name: 'keyId', in: 'path', required: true, schema: { type: 'string' } }],
                    responses: { '200': { description: 'Rotation policy set' } },
                },
            },
            '/api/v1/crypto/keys/managed/rotation/pending': {
                get: {
                    tags: ['Managed Keys'],
                    summary: 'List keys due for rotation',
                    parameters: [{ name: 'warningDays', in: 'query', schema: { type: 'integer' } }],
                    responses: { '200': { description: 'Pending rotations list' } },
                },
            },
            '/api/v1/crypto/managed/hybrid/encrypt': {
                post: {
                    tags: ['Hybrid'],
                    summary: 'Encrypt plaintext using managed RSA keyId',
                    responses: { '200': { description: 'Hybrid encrypted payload' } },
                },
            },
            '/api/v1/crypto/managed/hybrid/decrypt': {
                post: {
                    tags: ['Hybrid'],
                    summary: 'Decrypt payload using managed RSA keyId',
                    responses: { '200': { description: 'Decrypted plaintext' } },
                },
            },
            '/api/v1/crypto/managed/sign/data': {
                post: {
                    tags: ['Signatures'],
                    summary: 'Sign data with managed keyId private key',
                    responses: { '200': { description: 'Signature response' } },
                },
            },
            '/api/v1/crypto/managed/sign/verify': {
                post: {
                    tags: ['Signatures'],
                    summary: 'Verify signature with managed keyId public key',
                    responses: { '200': { description: 'Verification response' } },
                },
            },
            '/api/v1/crypto/hash/sha256': {
                post: {
                    tags: ['Hash/HMAC'],
                    summary: 'SHA-256 digest endpoint',
                    responses: { '200': { description: 'Digest response' } },
                },
            },
            '/api/v1/crypto/hmac/sign': {
                post: {
                    tags: ['Hash/HMAC'],
                    summary: 'HMAC SHA-256 signature endpoint',
                    responses: { '200': { description: 'HMAC signature response' } },
                },
            },
            '/api/v1/crypto/random/uuid': {
                get: {
                    tags: ['Utility'],
                    summary: 'Generate random UUID',
                    responses: { '200': { description: 'UUID response' } },
                },
            },
        },
    };
}
