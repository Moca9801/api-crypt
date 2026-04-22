# ─────────────────────────────────────────────────────────────────────────────
# Stage 1: Builder — compila TypeScript a JavaScript
# ─────────────────────────────────────────────────────────────────────────────
FROM node:22-alpine AS builder

WORKDIR /app

# Instalar dependencias (incluyendo devDependencies para compilar TS)
COPY package*.json tsconfig.json ./
RUN npm ci

# Compilar TypeScript
COPY src/ ./src/
RUN npm run build


# ─────────────────────────────────────────────────────────────────────────────
# Stage 2: Runner — imagen final minimal sin fuentes ni devDependencies
# ─────────────────────────────────────────────────────────────────────────────
FROM node:22-alpine AS runner

# Metadata
LABEL org.opencontainers.image.title="api-crypt"
LABEL org.opencontainers.image.description="Open source cryptographic REST API for developers"
LABEL org.opencontainers.image.source="https://github.com/Moca9801/api-crypt"
LABEL org.opencontainers.image.licenses="ISC"

ENV NODE_ENV=production

WORKDIR /app

# Solo dependencias de producción
COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force

# Código compilado desde el builder
COPY --from=builder /app/dist ./dist

# Directorio de datos para el archivo de claves (se monta como volumen)
RUN mkdir -p /data && chown node:node /data

# Ejecutar como usuario no-root
USER node

EXPOSE 3000

# Health check nativo de Docker — usa wget incluido en alpine
HEALTHCHECK \
  --interval=30s \
  --timeout=5s \
  --start-period=15s \
  --retries=3 \
  CMD wget -qO- http://localhost:3000/api/v1/health || exit 1

CMD ["node", "dist/index.js"]
