# Contributing

Thanks for contributing to `api-crypt`.

## Development setup

1. Fork and clone the repository.
2. Install dependencies:

```bash
npm install
```

3. Create `.env` from `.env.example`.
4. Start dev server:

```bash
npm run dev
```

## Code guidelines

- Prefer TypeScript strict-safe changes.
- Keep crypto defaults secure and explicit.
- Avoid introducing new endpoints that accept private keys unless clearly marked as legacy/unsafe.
- Keep route handlers small; move logic to services.

## Pull request checklist

- [ ] Build passes (`npm run build`)
- [ ] TypeScript compile passes (`npx tsc --noEmit`)
- [ ] New/changed endpoints documented in `README.md`
- [ ] Security-sensitive behavior documented in `SECURITY.md`
- [ ] No secrets committed

## Commit style

Use clear, intent-focused messages, for example:

- `add managed key rotation route`
- `harden legacy route guard for production`

## Reporting issues

- Feature/bug: GitHub Issues
- Security vulnerabilities: follow `SECURITY.md`
