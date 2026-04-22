# api-crypt-client

> SDK oficial para [api-crypt](https://github.com/Moca9801/api-crypt) — el toolkit criptográfico open source para desarrolladores.

[![npm version](https://img.shields.io/npm/v/api-crypt-client)](https://www.npmjs.com/package/api-crypt-client)
[![License: ISC](https://img.shields.io/badge/License-ISC-blue.svg)](https://opensource.org/licenses/ISC)
[![Node.js ≥18](https://img.shields.io/badge/node-%3E%3D18-brightgreen)](https://nodejs.org)

## Instalación

```bash
npm install api-crypt-client
```

**Requisitos:** Node.js ≥ 18 (usa `fetch` nativo). Zero dependencias de producción.

---

## Inicio rápido — 3 líneas

```typescript
import { ApiCryptClient } from 'api-crypt-client';

const client = new ApiCryptClient({ baseUrl: 'http://localhost:3000', apiKey: process.env.CRYPTO_API_KEY! });

const encrypted = await client.symmetric.encrypt('mi secreto'); // ✅ listo
```

---

## Configuración

```typescript
const client = new ApiCryptClient({
  baseUrl: 'http://localhost:3000',   // URL de tu servidor api-crypt
  apiKey: process.env.CRYPTO_API_KEY!, // API key (env: API_KEY en el servidor)
  timeoutMs: 10_000,                   // opcional, default: 10 segundos
  retries: 1,                          // opcional, reintentos en errores 5xx
});
```

---

## API Reference

### `client.symmetric` — Cifrado simétrico AES-256-GCM

```typescript
// Cifrar — el servidor genera una clave aleatoria si no se provee
const { iv, authTag, ciphertext, key } = await client.symmetric.encrypt('datos secretos');

// Descifrar
const plaintext = await client.symmetric.decrypt({ iv, authTag, ciphertext, key });
```

---

### `client.keys` — Gestión de claves criptográficas

```typescript
// Crear una clave RSA gestionada
const { keyId, publicKey, metadata } = await client.keys.create({ type: 'rsa', modulusLength: 2048 });

// Crear una clave EC
const ecKey = await client.keys.create({ type: 'ec', namedCurve: 'prime256v1' });

// Listar todas las claves (solo metadatos, sin material de clave)
const keys = await client.keys.list();

// Obtener clave pública
const { publicKey } = await client.keys.getPublicKey(keyId);

// Rotar una clave (genera nuevo par, desactiva el anterior)
await client.keys.rotate(keyId);

// Deshabilitar una clave
await client.keys.disable(keyId);

// Política de rotación automática — rotar cada 90 días
await client.keys.setRotationPolicy(keyId, { ttlDays: 90, onExpiry: 'disable' });

// Claves próximas a rotar (en los próximos 7 días)
const pending = await client.keys.pendingRotations();
```

---

### `client.managed` — Cifrado y firma con claves gestionadas

```typescript
// Cifrado híbrido RSA+AES (requiere clave de tipo 'rsa')
const payload = await client.managed.encrypt(keyId, 'mensaje confidencial');
// payload = { keyId, encryptedAesKey, iv, authTag, ciphertext }

// Descifrado
const plaintext = await client.managed.decrypt(keyId, payload);

// Firma digital RSA-SHA256
const dataB64 = Buffer.from('datos a firmar').toString('base64');
const signature = await client.managed.sign(keyId, dataB64);

// Verificación
const valid = await client.managed.verify(keyId, dataB64, signature);
```

---

### `client.hash` — Funciones hash

```typescript
// SHA-256
const hex = await client.hash.sha256('datos');

// Combinar dos hashes
const { combinedHash } = await client.hash.combine(hashA, hashB, 'concat-sha256');
```

---

### `client.hmac` — HMAC-SHA256

```typescript
const secret = Buffer.from('mi secreto').toString('base64');
const sig = await client.hmac.sign('datos', secret);
const valid = await client.hmac.verify('datos', secret, sig); // true
```

---

### `client.tokens` — Tokens firmados con TTL

```typescript
// Crear token con 1 hora de vida
const token = await client.tokens.create({ userId: '123', role: 'admin' }, secret, 3600);

// Verificar (lanza ApiCryptError si expiró o es inválido)
const payload = await client.tokens.verify(token, secret);
```

---

### `client.sealed` — Payloads sellados con TTL y anti-replay

```typescript
// Ideal para magic links, links de un solo uso, etc.
const sealed = await client.sealed.create({ email: 'user@example.com' }, secret, 900); // 15 min

// Abrir (lanza ApiCryptError si expiró)
const data = await client.sealed.open(sealed, secret);
```

---

### `client.random` — Valores aleatorios seguros

```typescript
const bytesB64 = await client.random.bytes(32); // 32 bytes en base64
const id = await client.random.uuid();           // UUID v4
```

---

## Manejo de errores

```typescript
import { ApiCryptClient, ApiCryptError } from 'api-crypt-client';

try {
  await client.managed.decrypt(keyId, payload);
} catch (err) {
  if (err instanceof ApiCryptError) {
    console.error(err.code);        // 'KEY_NOT_FOUND', 'PASSPHRASE_REQUIRED', etc.
    console.error(err.statusCode);  // 400, 404, 429, 0 (red/timeout)
    console.error(err.message);     // Descripción legible

    if (err.isPassphraseRequired) {
      // La clave fue creada con passphrase — pedirla al usuario
    }
    if (err.isRateLimited) {
      // Demasiadas requests — esperar antes de reintentar
    }
    if (err.isTimeout) {
      // El servidor no respondió a tiempo
    }
  }
}
```

---

## Levantar el servidor

```bash
# Opción 1: Docker (recomendado)
docker compose up -d

# Opción 2: Local
npm install && npm run dev
```

Ver el [README del servidor](../../README.md) para configuración completa.

---

## Licencia

ISC © api-crypt contributors
