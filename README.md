# api-crypt

Open source cryptography API toolkit for developers.  
Built with Node.js + Express + TypeScript.

## Project status

- **Status:** production-ready for single-instance deployments (V1.1)
- **Use case:** lightweight cryptographic microservice
- **Important:** features fail-closed security, Zod validation, and AES-256-GCM encryption at rest

> [!IMPORTANT]
> **Production Requirement:** This service does **NOT** implement TLS or Client Authentication natively. It **MUST** be deployed behind an API Gateway, Reverse Proxy (e.g., Nginx, Traefik), or Load Balancer that enforces TLS (HTTPS) and isolates the internal network.

## Features

- Managed key lifecycle (`keyId`): create, list, rotate, disable
- Hybrid encryption: RSA-OAEP + AES-256-GCM
- AES-256-GCM symmetric encryption/decryption
- Signing/verification (RSA/ECDSA)
- Hash, HMAC, PBKDF2, sealed payloads, random utilities
- API key protection + in-memory rate limiting
- OpenAPI JSON endpoint
- Postman collection included

## Use Cases & Strategy

`api-crypt` acts as a "Secure Vault" microservice. Instead of polluting your main backend with complex cryptography logic and exposing private keys in memory or logs, your backend delegates these operations.

- **PII Protection:** Encrypt credit cards, SSNs, and medical records before saving them to your main database (PostgreSQL/MongoDB). If your main DB is compromised, attackers only get ciphertext.
- **Webhook Signatures:** Sign payloads securely without exposing the private key to the web backend.
- **Secure Tokens / Magic Links:** Create sealed payloads for one-time links that prevent replay attacks.
- **CPU Isolation:** Offload expensive RSA/AES operations to a dedicated container.

## How it works (Workflow)

1. **Start the service** with your `API_KEY` and `MASTER_KEY` environment variables.
2. **Create a Managed Key** from your main backend:
   ```bash
   curl -X POST http://localhost:3000/api/v1/crypto/keys/managed/create \
     -H "X-API-KEY: <your-api-key>" \
     -H "Content-Type: application/json" \
     -d '{"keyId": "prod-cards", "type": "rsa", "modulusLength": 4096}'
   ```
   *(The private key is generated, encrypted with your `MASTER_KEY`, and securely saved to `keys.db.json`. Your backend never sees it).*
3. **Encrypt sensitive data** before saving it to your DB:
   ```javascript
   const response = await fetch('http://api-crypt:3000/api/v1/crypto/managed/hybrid/encrypt', {
       method: 'POST',
       headers: { 'X-API-KEY': '<your-api-key>', 'Content-Type': 'application/json' },
       body: JSON.stringify({ keyId: 'prod-cards', plaintext: '4111222233334444' })
   });
   const encryptedData = await response.json(); 
   // Save encryptedData (ciphertext, iv, authTag) to your PostgreSQL DB
   ```
4. **Decrypt data** when needed by passing the `encryptedData` JSON back to `/managed/hybrid/decrypt` using the same `keyId`.

## Node.js / TypeScript SDK

If your main backend uses Node.js or TypeScript, you can use the official type-safe SDK included in this repository:

```typescript
import { ApiCryptClient } from 'api-crypt-client';

const crypt = new ApiCryptClient({
    baseUrl: 'http://localhost:3000/api/v1',
    apiKey: process.env.CRYPTO_API_KEY
});

// Create a Managed Key
await crypt.keys.create({ keyId: 'my-key', type: 'rsa', modulusLength: 4096 });

// Hybrid Encrypt
const payload = await crypt.managed.hybridEncrypt({ keyId: 'my-key', plaintext: 'secret' });

// Sealed Payloads (Magic Links)
const token = await crypt.sealed.create({ data: { user: 1 }, secret: 'app-secret', ttlSeconds: 300 });
```

## Architecture

This project now follows a Clean Architecture-inspired structure:

- `src/core/domain`: entities and domain models
- `src/core/application`: use-case orchestration and ports (interfaces)
- `src/infrastructure`: concrete adapters (Node crypto) and repositories
- `src/interfaces/http`: transport-layer controllers
- `src/libs/routes`: HTTP route mapping only (thin router)

Patterns currently applied:

- **Ports and Adapters (Hexagonal)** for crypto provider and key repository
- **Repository Pattern** for managed keys
- **Dependency Inversion** from application service to abstractions
- **Controller pattern** with thin route handlers

```bash
npm install
npm run dev
```

Default server: `http://localhost:3000`

## Docker Support

This microservice is containerized for easy deployment and development.

### Development (Hot-Reload)
Runs the service with `nodemon` and mounts your `src` folder for real-time updates.
```bash
npm run docker:dev
```
*Accessible at: `http://localhost:3000`*

### Production (Hardened)
Builds a production-ready image with security hardening (`read_only` filesystem, no-privileges, etc.).
```bash
docker compose up -d --build
```

---

## Security Setup: Generating Keys

Before running the service (locally or via Docker), you must generate secure 64-character hex strings for your `API_KEY` and `MASTER_KEY`.

Run this command in your terminal to generate a key:
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

1.  **API_KEY**: Used to authenticate your backend requests to this microservice.
2.  **MASTER_KEY**: **CRITICAL**. This key encrypts all managed private keys stored on disk. If lost, all stored keys are unrecoverable.

## Environment variables

Create `.env` from `.env.example`.

- `PORT`: HTTP port (default `3000`)
- `API_KEY`: required API key for `/api/v1/crypto/*` routes
- `RATE_LIMIT_WINDOW_MS`: rate-limit window in milliseconds (default `60000`)
- `RATE_LIMIT_MAX`: max requests per route/window (default `120`)
- `DISABLE_LEGACY_CRYPTO_ROUTES`: disables unsafe legacy key-material endpoints
  - default: `true` when `NODE_ENV=production`, else `false`
- `TRUST_PROXY`: set to `true` or a list of proxy IPs if running behind an API Gateway/Load Balancer

## API docs

- Endpoint index: `GET /api/v1`
- OpenAPI JSON: `GET /api/v1/docs/openapi.json`

## Postman

Import:

- `api-crypt.postman_collection.json`

Set collection variables:

- `baseUrl` (for example `http://localhost:3000`)
- `apiKey` (must match your `.env`)

## Recommended route family

Prefer managed routes:

- `/api/v1/crypto/keys/managed/*`
- `/api/v1/crypto/managed/*`

Legacy raw key routes remain for compatibility, but can be disabled via:

- `DISABLE_LEGACY_CRYPTO_ROUTES=true`

## Security model notes

- **Authorization:** API key auth is baseline protection. **Client Scopes and Multi-Tenancy must be enforced at your API Gateway.**
- **Persistence:** Managed keys are persisted securely to the file system (`keys.db.json`) using AES-256-GCM encryption at rest (requires `MASTER_KEY`).
- **Network:** Deploy behind TLS and a reverse proxy in all non-local environments. Set `TRUST_PROXY` accordingly.
- **Observability:** The `/api/v1/metrics` endpoint is protected by an IP allowlist (`METRICS_ALLOWED_IPS`). You must ensure this endpoint is only routable from your internal VPC/monitoring network and blocked at the public edge.
- See `SECURITY.md` for reporting and hardening guidance.

## Contributing

See `CONTRIBUTING.md`.

## License

ISC
