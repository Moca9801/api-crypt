# Decisiones Criptográficas — api-crypt

> Justificación de los algoritmos y parámetros seleccionados. Referencias a estándares NIST y IETF.

---

## 1. Cifrado Simétrico — AES-256-GCM

**Algoritmo:** AES (Advanced Encryption Standard), modo GCM (Galois/Counter Mode)  
**Tamaño de clave:** 256 bits  
**IV:** 12 bytes (96 bits) aleatorio por operación  
**Auth tag:** 128 bits

**Justificación:**
- GCM provee **cifrado autenticado (AEAD)** — detecta manipulación del ciphertext sin capa adicional
- IV de 96 bits es el tamaño recomendado por NIST SP 800-38D para GCM
- 256 bits: seguridad post-cuántica candidata (resistente a Grover con 128 bits de seguridad efectiva)
- Implementado en hardware (AES-NI) en CPUs modernas — sin overhead de rendimiento

**Alternativas consideradas y rechazadas:**
- AES-128-GCM: menor margen de seguridad a largo plazo
- AES-256-CBC: sin autenticación integrada, requiere MAC separado (error-prone)
- ChaCha20-Poly1305: buena alternativa, pero AES-GCM con AES-NI es igualmente rápido

---

## 2. Cifrado Asimétrico — RSA-OAEP-SHA256

**Estándar:** PKCS#8 para claves, OAEP (Optimal Asymmetric Encryption Padding)  
**Hash en OAEP:** SHA-256  
**Tamaños de clave:** 2048, 3072, 4096 bits

**Justificación:**
- OAEP es semanticamente seguro (IND-CCA2) — PKCS#1 v1.5 es vulnerable a [ataques de Bleichenbacher (1998)](https://link.springer.com/chapter/10.1007/BFb0055716)
- SHA-256 en el hash de OAEP: resistente a colisiones, no SHA-1 (deprecado por NIST en 2023)
- 2048 bits: mínimo recomendado por NIST hasta 2030 (NIST SP 800-57 Part 1)
- 3072+ bits: recomendado para datos con requerimientos de confidencialidad > 2030

---

## 3. Firma Digital — ECDSA + RSA-SHA256

**EC:** ECDSA con curvas NIST P-256 (prime256v1) y P-384 (secp384r1)  
**RSA:** RSA-SHA256 con PKCS#1 v1.5 (solo para firmas — no vulnerable a Bleichenbacher en este contexto)

**Justificación:**
- P-256: 128 bits de seguridad, soporte universal, certificada por NIST FIPS 186-5
- P-384: 192 bits de seguridad para requerimientos gubernamentales/militares
- ECDSA claves 10x más cortas que RSA con seguridad equivalente → mejor performance
- Se excluyen: secp256k1 (curve de Bitcoin, no auditada para uso general), curvas de Brainpool

---

## 4. Derivación de Claves — PBKDF2-HMAC-SHA256

**Función:** PBKDF2 con HMAC-SHA256  
**Salt:** 16 bytes aleatorios  
**Iteraciones:** Configurables (verificar default ≥ 310,000 — OWASP 2024)

**Justificación:**
- PBKDF2 es el estándar de NIST (SP 800-132) para derivación de contraseñas
- HMAC-SHA256 como PRF: resistente a longitud-extension attacks
- 310,000 iteraciones: calibradas para ~100ms en CPU moderna (OWASP 2024 recommendation)

> ⚠️ **Acción pendiente**: Verificar que el default en `NodeCryptoAdapter.pbkdf2Derive()` sea ≥ 310,000 iteraciones.

---

## 5. HMAC — HMAC-SHA256

**Algoritmo:** HMAC (Hash-based Message Authentication Code) con SHA-256

**Justificación:**
- HMAC-SHA256 es el estándar de facto para autenticación de mensajes
- Comparación con `timingSafeEqual` de Node.js — previene timing attacks
- Usado en: tokens firmados, payload sellados, verificación de integridad

---

## 6. Cifrado de Claves en Reposo (Key Vault)

**Algoritmo:** AES-256-GCM (mismo que cifrado simétrico)  
**Clave:** MASTER_KEY de 256 bits derivada de variable de entorno  
**IV:** 12 bytes aleatorios **por cada operación de escritura**

**Justificación:**
- IV único por operación previene ataques de reutilización de IV (crítico en GCM)
- authTag de 128 bits detecta cualquier modificación del ciphertext en disco
- La MASTER_KEY nunca se almacena en disco — solo en memoria del proceso

---

## 7. Generación de Aleatoriedad

**Fuente:** `node:crypto.randomBytes()` — CSPRNG del sistema operativo  
- Linux: `/dev/urandom` (alimentado por `getrandom()` syscall)  
- Windows: `BCryptGenRandom`  
- macOS: `getentropy()`

**Nunca se usa:** `Math.random()` — no criptográficamente seguro

---

## 8. Referencias

- [NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final) — Recommendation for GCM
- [NIST SP 800-57 Part 1](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final) — Key Management Guidelines
- [NIST FIPS 186-5](https://csrc.nist.gov/publications/detail/fips/186/5/final) — Digital Signature Standard
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) — PBKDF2 iterations
- [RFC 4868](https://www.rfc-editor.org/rfc/rfc4868) — HMAC-SHA-256/384/512 Usage in IKEv2
