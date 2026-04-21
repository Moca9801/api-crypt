# Security Policy

## Supported versions

This project is currently in active development. Security fixes are applied to the latest `main` branch.

## Reporting a vulnerability

Please do not open public GitHub issues for vulnerabilities.

Report privately with:

- clear description of the issue
- reproduction steps or proof of concept
- impact assessment
- suggested mitigation if available

Use repository security advisories or contact the maintainer directly.

## Disclosure process

1. Acknowledge report receipt as soon as possible.
2. Validate and reproduce.
3. Prepare fix and tests.
4. Coordinate disclosure timeline with reporter.
5. Publish advisory/changelog notes.

## Hardening checklist for deployers

- enforce HTTPS only
- set a strong `API_KEY`
- run behind reverse proxy/API gateway
- configure stricter rate limits
- disable legacy routes in production (`DISABLE_LEGACY_CRYPTO_ROUTES=true`)
- avoid logging secrets or private key material
- rotate keys and credentials regularly
- monitor auth failures and rate-limit events

## Cryptography note

This tool wraps cryptographic primitives but does not replace formal security review.  
For high-risk or regulated workloads, perform independent security testing before production use.
