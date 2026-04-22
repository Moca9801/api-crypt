// ── Load environment variables FIRST — before any other module reads process.env ──
import dotenv from 'dotenv';
dotenv.config();

import { App } from './app';
import { getScheduler } from './infrastructure/container/crypto.container';

async function main() {
    const app = new App();
    const server = await app.listen();

    // ── Graceful shutdown ─────────────────────────────────────────────────────
    const shutdown = (signal: string) => {
        console.log(`\n[api-crypt] Received ${signal}. Shutting down gracefully...`);

        // Detener el scheduler de rotación antes de cerrar el servidor
        getScheduler()?.stop();

        server.close((err) => {
            if (err) {
                console.error('[api-crypt] Error during shutdown:', err);
                process.exit(1);
            }
            console.log('[api-crypt] Server closed. Goodbye.');
            process.exit(0);
        });

        // Forzar salida si el cierre tarda más de 10 segundos
        setTimeout(() => {
            console.error('[api-crypt] Forced shutdown after timeout.');
            process.exit(1);
        }, 10_000).unref();
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
}

main().catch((err) => {
    console.error('[api-crypt] Fatal startup error:', err);
    process.exit(1);
});
