# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅ Active security fixes |
| < 1.0   | ❌ Not supported |

---

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

### How to Report

1. **Email:** Send a detailed report to the maintainers via the contact listed on the [GitHub repository](https://github.com/Moca9801/api-crypt)
2. **GitHub Private Advisory:** Use [GitHub Security Advisories](https://github.com/Moca9801/api-crypt/security/advisories/new) to report privately

### What to Include

Please include as much of the following as possible:

- Type of vulnerability (e.g., cryptographic weakness, key exposure, RCE)
- Affected component (e.g., `KeyVaultService`, `NodeCryptoAdapter`, specific endpoint)
- Step-by-step reproduction instructions
- Proof of concept code (if applicable)
- Potential impact assessment
- Your suggested fix (if any)

---

## Response Timeline

| Milestone | Target |
|-----------|--------|
| Acknowledgment of report | 48 hours |
| Initial severity assessment | 5 business days |
| Fix development + testing | 30–90 days depending on severity |
| Public disclosure | After fix is released (coordinated) |

---

## Responsible Disclosure Policy

We follow **coordinated vulnerability disclosure**:

1. Reporter submits vulnerability privately
2. We acknowledge and assess severity
3. We develop and test a fix
4. We release the fix
5. We publicly acknowledge the reporter (unless they prefer anonymity)
6. Full public disclosure after users have had time to update

**We ask that you:**
- Allow us reasonable time to fix before public disclosure
- Not exploit the vulnerability beyond what is necessary to demonstrate it
- Not access or modify other users' data

---

## Security Design Decisions

Key security design decisions are documented in:

- [`docs/threat-model.md`](docs/threat-model.md) — STRIDE threat model
- [`docs/cryptography.md`](docs/cryptography.md) — Cryptographic algorithm justifications  
- [`SECURITY-AUDIT.md`](SECURITY-AUDIT.md) — Internal security audit checklist

---

## Known Limitations

The following limitations are **by design** and documented as out-of-scope:

- **No TLS**: api-crypt does not implement TLS — use a reverse proxy (nginx, Traefik, Caddy)
- **Single-instance**: Multiple instances sharing the same `keys.db.json` is not supported
- **No HSM support**: Private keys are encrypted with a software master key, not a hardware security module
- **Passphrase not stored**: Keys created with a passphrase require it on each operation — the server never stores it

---

## Automated Security Scanning

This repository runs automated security checks on every push:

- **CodeQL**: Static analysis for JavaScript/TypeScript vulnerabilities
- **TruffleHog**: Secret detection in commit history
- **npm audit**: Dependency vulnerability scanning
- **SBOM**: Software Bill of Materials generated per release

See [`.github/workflows/security.yml`](.github/workflows/security.yml) for details.
