import { ApiCryptClientConfig } from './types';
import { ApiCryptError } from './errors';

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

interface ApiResponse {
    ok: boolean;
    error?: string;
    code?: string;
    [key: string]: unknown;
}

/**
 * Cliente HTTP interno del SDK.
 * Gestiona autenticación, timeout, reintentos con backoff exponencial
 * y serialización de errores tipados.
 */
export class HttpClient {
    private readonly baseUrl: string;
    private readonly apiKey: string;
    private readonly timeoutMs: number;
    private readonly retries: number;

    constructor(config: ApiCryptClientConfig) {
        this.baseUrl = config.baseUrl.replace(/\/$/, ''); // quitar trailing slash
        this.apiKey = config.apiKey;
        this.timeoutMs = config.timeoutMs ?? 10_000;
        this.retries = config.retries ?? 1;
    }

    async get<T>(path: string): Promise<T> {
        return this.request<T>('GET', path, undefined);
    }

    async post<T>(path: string, body: unknown): Promise<T> {
        return this.request<T>('POST', path, body);
    }

    async delete_<T>(path: string): Promise<T> {
        return this.request<T>('DELETE', path, undefined);
    }

    private async request<T>(method: string, path: string, body: unknown): Promise<T> {
        let lastError: Error = new ApiCryptError('Request failed', 'NETWORK_ERROR', 0);

        for (let attempt = 0; attempt <= this.retries; attempt++) {
            if (attempt > 0) {
                // Backoff exponencial: 500ms, 1s, 2s, …, máximo 5s
                await sleep(Math.min(500 * 2 ** (attempt - 1), 5_000));
            }

            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);

            try {
                const response = await fetch(`${this.baseUrl}${path}`, {
                    method,
                    headers: {
                        'Content-Type': 'application/json',
                        'x-api-key': this.apiKey,
                    },
                    body: body !== undefined ? JSON.stringify(body) : undefined,
                    signal: controller.signal,
                });

                clearTimeout(timeoutId);
                const data: ApiResponse = await response.json();

                if (!response.ok || data.ok === false) {
                    const err = new ApiCryptError(
                        data.error ?? `HTTP ${response.status}`,
                        data.code ?? `HTTP_${response.status}`,
                        response.status
                    );
                    // No reintentar errores de cliente (4xx)
                    if (response.status < 500) throw err;
                    lastError = err;
                    continue;
                }

                return data as T;
            } catch (err) {
                clearTimeout(timeoutId);

                if (err instanceof ApiCryptError) throw err;

                if ((err as Error).name === 'AbortError') {
                    lastError = new ApiCryptError(
                        `Request timed out after ${this.timeoutMs}ms`,
                        'REQUEST_TIMEOUT',
                        0
                    );
                } else {
                    lastError = new ApiCryptError(
                        `Network error: ${(err as Error).message}`,
                        'NETWORK_ERROR',
                        0
                    );
                }
            }
        }

        throw lastError;
    }
}
