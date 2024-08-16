import { Request, Response } from 'express';
import express, { Application } from 'express';
import morgan from 'morgan';
import cors from 'cors';
import dotenv from 'dotenv';
import v1Router from './libs/routes/index.routes';


dotenv.config();

export class App {
    app: Application;

    constructor(private port?: number | string){
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
        this.app.use(express.json({limit: '50mb'}));
        this.app.use(express.urlencoded({limit: '50mb', extended: false}));
        this.app.use(cors());
        this.app.use((req, res, next) => {
            res.header('Access-Control-Allow-Origin', '*');
            res.header('Access-Control-Allow-Headers', 'Authorization, X-API-KEY, Origin, X-Requested-With, Content-Type, Accept, Access-Control-Allow-Request-Method');
            res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE');
            res.header('Allow', 'GET, POST, OPTIONS, PUT, DELETE');
            next();
        });
    }

    private getNextPort() {
        const currentPort = this.app.get('port');
        const nextPort = (typeof currentPort === 'string') ? parseInt(currentPort, 10) + 1 : currentPort + 1;
        return nextPort;
    }

    public async listen(){
        return new Promise<void>((resolve, reject)=>{
            const server = this.app.listen(this.app.get('port'), () => { 
                console.log(`** 🚀 CJJ Live development Server listening on localhost:${ this.app.get('port') }, application succesfully started.  **`);
                this.connectDatabase();
                resolve();
            }).on('error', (err: any)=>{
                if(err && err.code === 'EADDRINUSE') {
                    console.log(`Port ${this.app.get('port')} is already in use. Trying another port...`);
                    this.app.set('port', this.getNextPort());
                    server.close();
                    this.listen().then(resolve).catch(reject);
                }else {
                    reject(err);
                }
            });
        });
    }

    private async connectDatabase(){
        /*try{
            // nullish coalescing operator undefined OR null
            const connection = await connect({
                username: process.env.USER_DB_USERNAME as string,
                password: process.env.USER_DB_PASSWORD as string,
            });
            console.log('       ✅ Database connection established successfully.');
            connection.release();
        }catch (error: any) {
            console.error('Error:', error);
            console.log("-> Try to reconect");
            await Utils.sleep(2000);
            this.connectDatabase();
        }
        */
    }
    
    private routes(){
        this.app.get('/', (req: Request, res: Response) => {
            res.send('¡La API está en funcionamiento!');
        });
    
        this.app.use('/api/v1', v1Router);
        this.app.use((req: Request, res: Response) => {
            res.status(404).send(`The request URL:${ req.url } was not found on this server. That´s all e know.`);
        });
    }
}