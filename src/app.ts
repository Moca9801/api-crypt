import { Request, Response } from 'express';
import express, { Application } from 'express';
import morgan from 'morgan';
import cors from 'cors';
import dotenv from 'dotenv';
import v1Router from './libs/routes/index.routes';

dotenv.config();

function getAllowedOrigins(): string[] {
    const raw = process.env.ALLOWED_ORIGINS?.trim();
    if (!raw) {
        if (process.env.NODE_ENV === 'production') {
            throw new Error(
                '[api-crypt] FATAL: ALLOWED_ORIGINS must be set in production.\n' +
                'Example: ALLOWED_ORIGINS=https://yourapp.com,https://admin.yourapp.com'
            );
        }
        // Development: allow common localhost ports only
        return [
            'http://localhost:3000',
            'http://localhost:5173',
            'http://localhost:4200',
            'http://127.0.0.1:3000',
        ];
    }
    return raw.split(',').map((o) => o.trim()).filter(Boolean);
}

export class App {
    app: Application;

    constructor(private port?: number | string) {
        this.app = express();
        this.settings();
        this.middlewares();
        this.routes();
    }

    private settings() {
        this.app.set('port', this.port || process.env.PORT || 3000);
    }

    private middlewares() {
        this.app.use(express.static('public'));
        this.app.use(morgan('dev'));
        // Body limit capped at 1 MB — no legitimate crypto payload needs more
        this.app.use(express.json({ limit: '1mb' }));
        this.app.use(express.urlencoded({ limit: '1mb', extended: false }));
        // CORS restricted to explicit allowlist (no wildcard *)
        this.app.use(
            cors({
                origin: getAllowedOrigins(),
                methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
                allowedHeaders: [
                    'Authorization',
                    'X-API-KEY',
                    'Origin',
                    'X-Requested-With',
                    'Content-Type',
                    'Accept',
                ],
            })
        );
    }

    private getNextPort() {
        const currentPort = this.app.get('port');
        const nextPort = typeof currentPort === 'string' ? parseInt(currentPort, 10) + 1 : currentPort + 1;
        return nextPort;
    }

    public async listen() {
        return new Promise<void>((resolve, reject) => {
            const server = this.app
                .listen(this.app.get('port'), () => {
                    console.log(
                        `** 🚀 api-crypt listening on localhost:${this.app.get('port')} **`
                    );
                    resolve();
                })
                .on('error', (err: NodeJS.ErrnoException) => {
                    if (err && err.code === 'EADDRINUSE') {
                        console.log(`Port ${this.app.get('port')} in use. Trying next port...`);
                        this.app.set('port', this.getNextPort());
                        server.close();
                        this.listen().then(resolve).catch(reject);
                    } else {
                        reject(err);
                    }
                });
        });
    }

    private routes() {
        this.app.get('/', (_req: Request, res: Response) => {
            res.send('api-crypt is running. See /api/v1 for endpoints.');
        });

        this.app.use('/api/v1', v1Router);

        this.app.use((req: Request, res: Response) => {
            res.status(404).send(`The request URL: ${req.url} was not found on this server.`);
        });
    }
}