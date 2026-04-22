import { NextFunction, Request, Response } from 'express';
import { metricsRegistry } from '../../infrastructure/metrics/metrics-registry';

/**
 * Middleware Express que instrumenta cada request:
 *  - Cuenta operaciones por ruta y estado HTTP
 *  - Mide latencia en ms y la observa en un histograma
 *  - Registra hits de rate limit
 */
export function metricsMiddleware(req: Request, res: Response, next: NextFunction): void {
    const startMs = Date.now();

    res.on('finish', () => {
        const durationMs = Date.now() - startMs;
        const route = req.route?.path ?? 'unknown_route';
        const method = req.method;
        const status = String(res.statusCode);
        const statusClass = `${res.statusCode < 400 ? 'success' : 'error'}`;

        // Contador de requests totales
        metricsRegistry.increment(
            'api_crypt_http_requests_total',
            { method, route, status_class: statusClass },
            'Total HTTP requests by method, route and status class'
        );

        // Histograma de latencia
        metricsRegistry.observe(
            'api_crypt_http_request_duration_ms',
            durationMs,
            { method, route },
            'HTTP request duration in milliseconds'
        );

        // Rate limit hit
        if (res.statusCode === 429) {
            metricsRegistry.increment(
                'api_crypt_rate_limit_hits_total',
                { route },
                'Total rate limit rejections'
            );
        }
    });

    next();
}

/**
 * Actualiza las métricas de estado del key store (llamada periódicamente desde el container).
 */
export function updateKeyStoreMetrics(activeCount: number, disabledCount: number, pendingRotation: number): void {
    metricsRegistry.setGauge('api_crypt_managed_keys_total', activeCount, { status: 'active' }, 'Managed keys by status');
    metricsRegistry.setGauge('api_crypt_managed_keys_total', disabledCount, { status: 'disabled' }, 'Managed keys by status');
    metricsRegistry.setGauge('api_crypt_keys_rotation_pending_total', pendingRotation, {}, 'Keys due for rotation within 7 days');
    metricsRegistry.setGauge('api_crypt_process_uptime_seconds', Math.floor(process.uptime()), {}, 'Process uptime in seconds');
    metricsRegistry.setGauge('api_crypt_process_memory_heap_used_bytes', process.memoryUsage().heapUsed, {}, 'Heap memory used in bytes');
}
