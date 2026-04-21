# api-crypt

Open source cryptography API toolkit for developers.  
Built with Node.js + Express + TypeScript.

## Project status

- **Status:** beta prototype
- **Use case:** developer tooling, local/self-hosted security utilities
- **Important:** not externally audited yet

## Features

- Managed key lifecycle (`keyId`): create, list, rotate, disable
- Hybrid encryption: RSA-OAEP + AES-256-GCM
- AES-256-GCM symmetric encryption/decryption
- Signing/verification (RSA/ECDSA)
- Hash, HMAC, PBKDF2, sealed payloads, random utilities
- API key protection + in-memory rate limiting
- OpenAPI JSON endpoint
- Postman collection included

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

## Quick start

```bash
npm install
npm run dev
```

Default server: `http://localhost:3000`

## Environment variables

Create `.env` from `.env.example`.

- `PORT`: HTTP port (default `3000`)
- `API_KEY`: required API key for `/api/v1/crypto/*` routes
- `RATE_LIMIT_WINDOW_MS`: rate-limit window in milliseconds (default `60000`)
- `RATE_LIMIT_MAX`: max requests per route/window (default `120`)
- `DISABLE_LEGACY_CRYPTO_ROUTES`: disables unsafe legacy key-material endpoints
  - default: `true` when `NODE_ENV=production`, else `false`

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

- API key auth is baseline protection, not enterprise IAM.
- Managed keys are currently in-memory for prototype usage.
- Deploy behind TLS and a reverse proxy in all non-local environments.
- See `SECURITY.md` for reporting and hardening guidance.

## Contributing

See `CONTRIBUTING.md`.

## License

ISC
