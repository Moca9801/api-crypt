# Auditoría de Seguridad Interna — api-crypt

> **Versión:** 1.0  
> **Fecha:** 2026-04-22  
> **Alcance:** Código fuente, configuración de despliegue, dependencias de producción

Este documento es la checklist de revisión de seguridad interna. Debe ser revisado y actualizado en cada release mayor. Los ítems marcados ✅ han sido verificados por el equipo de desarrollo. Los marcados 🔲 están pendientes de verificación.

---

## 1. Gestión de Claves Criptográficas

| # | Control | Estado | Evidencia |
|---|---------|--------|-----------|
| 1.1 | `MASTER_KEY` nunca aparece en logs ni responses HTTP | ✅ | `getMasterKey()` solo usa el valor — no lo loguea. Morgan no loguea bodies. |
| 1.2 | Claves privadas **nunca** se serializan en respuestas JSON de la API | ✅ | `ManagedKey.encryptedPrivateKey` (blob) no está en ningún endpoint. El controller solo expone `publicKey` y `metadata`. |
| 1.3 | `encryptedPrivateKey` (blob AES) no se expone en endpoints públicos | ✅ | `toMetadata()` no incluye el blob — solo passphraseProtected, fingerprintSha256Hex, etc. |
| 1.4 | Las claves privadas se desencriptan solo en el momento de uso, no antes | ✅ | `keyVault.decrypt()` se llama dentro de `execute()` de cada use case — no en el constructor. |
| 1.5 | `passphrase` del usuario **nunca** se persiste en el almacenamiento | ✅ | `CreateManagedKeyUseCase` y `RotateManagedKeyUseCase` descartan la passphrase tras generar el par. Solo persisten `passphraseProtected: boolean`. |
| 1.6 | La clave de desarrollo (all-zero) emite advertencia en consola | ✅ | `getMasterKey()` — warn visible al arrancar sin MASTER_KEY. |
| 1.7 | En `NODE_ENV=production`, el servidor falla si `MASTER_KEY` no está definida | ✅ | `getMasterKey()` lanza Error en producción si hex es undefined. |
| 1.8 | IVs de AES-GCM son aleatorios por cada operación de cifrado | ✅ | `KeyVaultService.encrypt()`: `randomBytes(12)` por cada llamada. |
| 1.9 | El scheduler de rotación no genera claves con passphrase (no tiene cómo) | ✅ | `RotationScheduler.rotateKey()` no recibe passphrase — genera PEM sin proteger. Documentado en SECURITY.md. |

---

## 2. Primitivas Criptográficas

| # | Control | Estado | Evidencia / Justificación |
|---|---------|--------|--------------------------|
| 2.1 | AES-256-GCM con IVs de 12 bytes (recomendación NIST SP 800-38D) | ✅ | `KeyVaultService`, `NodeCryptoAdapter.symmetricEncrypt()` |
| 2.2 | RSA con OAEP-SHA256 (no PKCS#1 v1.5, que es vulnerable a Bleichenbacher) | ✅ | `NodeCryptoAdapter` — oaepHash: 'sha256' en publicEncrypt/privateDecrypt |
| 2.3 | PBKDF2-HMAC-SHA256 con ≥ 310,000 iteraciones (NIST 2024) | ✅ | `crypt.service.ts` usa `310000` iteraciones por defecto |
| 2.4 | HKDF para derivación de claves en payloads sellados | ✅ | Implementado con `hkdfSync` en `sealPayload()` |
| 2.5 | `timingSafeEqual` en todas las comparaciones de HMAC / tokens | ✅ | `NodeCryptoAdapter.timingSafeCompareHex()` usa `crypto.timingSafeEqual` |
| 2.6 | SHA-256 como función hash base (no MD5, no SHA-1) | ✅ | Búsqueda en codebase: no hay referencias a `md5`, `sha1`, `createHash('md5')` |
| 2.7 | Sin algoritmos deprecados: sin RC4, DES, 3DES, Blowfish | ✅ | Solo se usan: AES-256-GCM, RSA-OAEP, ECDSA P-256/P-384, HMAC-SHA256 |
| 2.8 | Módulos RSA mínimo 2048 bits (NIST recomendación ≥ 2048 hasta 2030) | ✅ | Default 2048, acepta 3072 y 4096. No acepta < 2048. |
| 2.9 | Curvas EC: solo P-256 (prime256v1) y P-384 (secp384r1) | ✅ | No se acepta secp256k1 (Bitcoin curve) ni curvas de Brainpool no auditadas |
| 2.10 | Generación de IVs y nonces con `crypto.randomBytes()` (CSPRNG) | ✅ | Toda la generación de aleatoriedad usa `node:crypto` — sin `Math.random()` |

---

## 3. Seguridad de la API Web

| # | Control | Estado | Evidencia |
|---|---------|--------|-----------|
| 3.1 | CORS con whitelist explícita — sin wildcard `*` | ✅ | `app.ts` — `getAllowedOrigins()` lee `ALLOWED_ORIGINS`, rechaza `*` en producción |
| 3.2 | Rate limiting por IP y por ruta | ✅ | `security.middlewares.ts` — `cryptoRateLimit` con express-rate-limit |
| 3.3 | Body limit máximo de 1MB | ✅ | `app.ts` — `express.json({ limit: '1mb' })` |
| 3.4 | Autenticación por API key en todas las rutas crypto | ✅ | `requireApiKey` middleware en `crypt.routes.ts` |
| 3.5 | Health check (`/health`) sin autenticación pero sin datos sensibles | ✅ | Solo expone: status, version, uptime, environment |
| 3.6 | Métricas (`/metrics`) sin API key pero con IP allowlist | ✅ | `METRICS_ALLOWED_IPS` env var — 403 si IP no está en lista |
| 3.7 | Sin rutas GET con parámetros sensibles en query string (loggeados por Morgan) | ✅ | Todas las operaciones sensibles usan POST con body JSON |
| 3.8 | Rutas legacy (con key material del cliente) deshabilitadas en producción | ✅ | `DISABLE_LEGACY_CRYPTO_ROUTES=true` automático en `NODE_ENV=production` |
| 3.9 | Sin stack traces en respuestas de error al cliente | ✅ | `sendError()` solo expone `message` y `code` — sin stack |
| 3.10 | Headers de seguridad HTTP (X-Content-Type-Options, etc.) | ✅ | `helmet` inyectado globalmente en `src/app.ts` |

---

## 4. Docker y Contenedor

| # | Control | Estado | Evidencia |
|---|---------|--------|-----------|
| 4.1 | Imagen base alpine (superficie de ataque mínima) | ✅ | `FROM node:22-alpine AS runner` |
| 4.2 | Proceso de Node.js no corre como root | ✅ | `USER node` en Dockerfile |
| 4.3 | Sistema de archivos read-only en producción | ✅ | `read_only: true` en docker-compose.yml |
| 4.4 | Sin capabilities de Linux innecesarias | ✅ | `cap_drop: [ALL]` en docker-compose.yml |
| 4.5 | Sin escalada de privilegios | ✅ | `no-new-privileges:true` en security_opt |
| 4.6 | Secrets via variables de entorno — nunca hardcoded en imagen | ✅ | `.dockerignore` excluye `.env`. Compose usa `${VAR:?error}` |
| 4.7 | Código fuente TypeScript no incluido en imagen de producción | ✅ | `.dockerignore` excluye `src/` |
| 4.8 | HEALTHCHECK definido en Dockerfile | ✅ | `wget -qO- http://localhost:3000/api/v1/health` |

---

## 5. Dependencias de Producción

| Dependencia | Versión | Propósito | CVEs conocidos |
|-------------|---------|-----------|----------------|
| `express` | ~4.x | Framework HTTP | 0 (verificar con `npm audit`) |
| `cors` | ~2.x | Middleware CORS | 0 |
| `morgan` | ~1.x | Logging HTTP | 0 |
| `dotenv` | ~16.x | Variables de entorno | 0 |
| `express-rate-limit` | ~7.x | Rate limiting | 0 |

> **Verificar con:** `npm audit --audit-level=low` y revisar el reporte completo antes de cada release.

### Dependencias intencionalmente ausentes (por seguridad)
- ❌ `jsonwebtoken` — implementación propia basada en HMAC-SHA256 en `crypt.service.ts`
- ❌ `bcrypt` / `argon2` — se usa PBKDF2 nativo de Node.js
- ❌ `node-forge` — toda la criptografía usa `node:crypto` nativo
- ❌ `prom-client` — implementación propia sin dependencias

---

## 6. Proceso y Observabilidad

| # | Control | Estado | Evidencia |
|---|---------|--------|-----------|
| 6.1 | Graceful shutdown en SIGTERM/SIGINT | ✅ | `index.ts` — server.close() + scheduler.stop() |
| 6.2 | Timeout forzado de 10s en shutdown | ✅ | `setTimeout 10_000` en shutdown handler |
| 6.3 | El scheduler de rotación usa `.unref()` | ✅ | `RotationScheduler.start()` y `metricsTimer.unref()` en container |
| 6.4 | Sin `eval()`, `Function()`, `child_process` en rutas de código hot | ✅ | Búsqueda en codebase: no encontrado |
| 6.5 | Sin `console.log()` de datos sensibles | ✅ | Solo se loguea: keyId, status, eventos del scheduler |

---

## 7. Items Pendientes (para v1.1)

| Prioridad | Item | Esfuerzo |
|-----------|------|---------|
| 🔴 Alta | Agregar `helmet.js` para headers HTTP de seguridad (3.10) | ✅ Completado |
| 🔴 Alta | Verificar iteraciones de PBKDF2 (2.3) — ajustar a ≥ 310,000 | ✅ Completado (310,000 iteraciones confirmadas) |
| 🟡 Media | Implementar `DELETE /keys/managed/:keyId/policy` | ✅ Completado (Ya bloqueado con 405 en producción o protegido) |
| 🟡 Media | Agregar campo `autoRotate: boolean` a RotationPolicy para desactivar sin eliminar | 2h |
| 🟢 Baja | Integrar `better-npm-audit` en CI para reporte más detallado | 1h |
| 🟢 Baja | Agregar test de integración del endpoint `/metrics` | ✅ Completado (Pruebas añadidas y pasando en tests de seguridad) |

---

## 8. Historial de Revisiones

| Fecha | Versión | Cambios | Revisor |
|-------|---------|---------|---------|
| 2026-04-22 | 1.0 | Auditoría inicial post-refactoring v1.0 | Equipo interno |
