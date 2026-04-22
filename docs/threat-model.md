# Modelo de Amenazas — api-crypt

> **Metodología:** STRIDE | **Versión:** 1.0 | **Fecha:** 2026-04-22

---

## 1. Activos a Proteger

| Activo | Clasificación | Impacto si comprometido |
|--------|--------------|------------------------|
| Claves privadas PEM | 🔴 Crítico | Compromiso total de datos cifrados |
| MASTER_KEY | 🔴 Crítico | Permite descifrar todas las claves del store |
| API_KEY | 🟡 Alto | Acceso no autorizado a todas las operaciones |
| keys.db.json | 🟡 Alto | Sin MASTER_KEY es inútil. Con ella, todo comprometido |
| Datos cifrados en tránsito | 🟡 Alto | Interceptación de operaciones |

---

## 2. Diagrama de Flujo de Datos

```
┌─────────────────────────────────────────────────────┐
│                  LÍMITE DE CONFIANZA                │
│                                                     │
│  [Cliente] ──HTTP/HTTPS──▶ [api-crypt server]       │
│                                 │                   │
│  [Prometheus] ◀──/metrics───────│                   │
│                                 ▼                   │
│  [Admin] ──.env────────▶ [KeyVaultService]          │
│                                 │ AES-256-GCM       │
│                                 ▼                   │
│                          [keys.db.json]              │
└─────────────────────────────────────────────────────┘
```

---

## 3. Análisis STRIDE

### Spoofing (Suplantación)
| ID | Amenaza | Mitigación | Residual |
|----|---------|-----------|---------|
| S-1 | Acceso sin API key | `requireApiKey` → 401 | Bajo |
| S-2 | Fuerza bruta de API key | Rate limiting por IP | Bajo |

### Tampering (Manipulación)
| ID | Amenaza | Mitigación | Residual |
|----|---------|-----------|---------|
| T-1 | Modificación de keys.db.json | AES-GCM valida authTag | Bajo |
| T-2 | MitM entre cliente y servidor | **TLS obligatorio vía reverse proxy** | **Medio sin TLS** |

### Repudiation (Repudio)
| ID | Amenaza | Mitigación | Residual |
|----|---------|-----------|---------|
| R-1 | Sin trazabilidad de operaciones | Morgan loguea método, ruta, IP | Bajo |
| R-2 | Logs solo en stdout | **PENDIENTE**: exportar a sistema persistente | **Alto** |

### Information Disclosure (Revelación)
| ID | Amenaza | Mitigación | Residual |
|----|---------|-----------|---------|
| I-1 | Clave privada en response | Controller solo expone `publicKey`/`metadata` | Bajo |
| I-2 | MASTER_KEY en logs | `getMasterKey()` no loguea el valor | Bajo |
| I-3 | Stack trace en error | `sendError()` solo expone message+code | Bajo |
| I-4 | Passphrase en body sin TLS | **Requiere TLS en producción** | **Alto sin TLS** |
| I-5 | API key timing attack | comparación mitigada usando `crypto.timingSafeEqual` | **Mitigado** |

### Denial of Service
| ID | Amenaza | Mitigación | Residual |
|----|---------|-----------|---------|
| D-1 | Request flood | Rate limiting 120 req/min | Bajo |
| D-2 | Payload gigante | Body limit 1MB | Bajo |
| D-3 | Generación masiva RSA-4096 | Rate limiting + API key | Bajo |

### Elevation of Privilege
| ID | Amenaza | Mitigación | Residual |
|----|---------|-----------|---------|
| E-1 | Escape de contenedor | USER node, no-new-privileges, cap_drop ALL | Bajo |
| E-2 | Supply chain attack | npm audit en CI + SBOM | Medio |

---

## 4. Controles Pendientes (Prioridad)

| Prioridad | Control |
|-----------|---------|
| 🔴 Alta | TLS via reverse proxy obligatorio |
| 🔴 Alta | Timing-safe comparison para API_KEY (I-5) |
| 🟡 Media | Audit log persistente |
| 🟡 Media | `helmet.js` para security headers |

---

## 5. Suposiciones de Seguridad

1. MASTER_KEY se gestiona en secrets manager — nunca en texto plano
2. TLS es responsabilidad del reverse proxy (nginx/Traefik/Caddy)
3. El host es de confianza — el operador controla el filesystem
4. API_KEY se trata como secreto y se transmite solo sobre TLS
5. Una sola instancia por MASTER_KEY — múltiples instancias requieren storage compartido (no soportado)
