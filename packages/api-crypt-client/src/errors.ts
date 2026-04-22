/**
 * Error lanzado por el SDK cuando el servidor responde con un error
 * o cuando ocurre un problema de red/timeout.
 */
export class ApiCryptError extends Error {
    /** Código de error del servidor (ej: 'KEY_NOT_FOUND', 'PASSPHRASE_REQUIRED'). */
    readonly code: string;
    /** HTTP status code. 0 si es un error de red o timeout. */
    readonly statusCode: number;

    constructor(message: string, code = 'UNKNOWN_ERROR', statusCode = 0) {
        super(message);
        this.name = 'ApiCryptError';
        this.code = code;
        this.statusCode = statusCode;
        // Mantiene stack trace correcto en V8 (Node.js)
        const ErrorCtor = Error as typeof Error & { captureStackTrace?: (t: unknown, c: unknown) => void };
        if (ErrorCtor.captureStackTrace) {
            ErrorCtor.captureStackTrace(this, ApiCryptError);
        }
    }

    get isTimeout(): boolean {
        return this.code === 'REQUEST_TIMEOUT';
    }

    get isNotFound(): boolean {
        return this.code === 'KEY_NOT_FOUND';
    }

    get isPassphraseRequired(): boolean {
        return this.code === 'PASSPHRASE_REQUIRED';
    }

    get isRateLimited(): boolean {
        return this.statusCode === 429;
    }
}
