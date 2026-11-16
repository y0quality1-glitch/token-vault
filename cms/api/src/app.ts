import express, { type NextFunction, type Request, type Response } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { CATALOG_PATH, CORS_ORIGINS, PATH } from './config';
import { ServiceError, handleError } from './core/ApiError';
import { CatalogController } from './controllers/catalogController/catalogController.controller';
import type { BaseController } from './controllers/baseController';
import requestLogger from './middlewares/requestLogger.middleware';
import { setupSwagger } from './swagger';

/**
 * The Express application (template: src/app.ts). Middlewares, the admin controllers under
 * PATH, the public catalog, API docs, then 404 and a 4-argument error handler (template fix
 * B-14: malformed JSON and thrown errors get the envelope, never Express's HTML page).
 */
export class App {
  public readonly app = express();

  constructor(private readonly controllers: BaseController[]) {}

  /** Builds the app. Call once, after the database is ready (see index.ts). */
  async build(): Promise<express.Application> {
    this.app.disable('x-powered-by');
    this.app.set('trust proxy', 'loopback');
    this.initializeMiddlewares();
    await setupSwagger(this.app);
    this.initializeControllers();
    this.initializeErrorHandling();
    return this.app;
  }

  private initializeMiddlewares() {
    this.app.use(requestLogger);
    this.app.use(helmet());
    // Same origin by default (the CMS UI proxies /api); cross-origin only for CMS_CORS_ORIGINS (template fix B-26).
    this.app.use(cors({ origin: CORS_ORIGINS.length ? CORS_ORIGINS : false, credentials: true }));
    // Bodies are small JSON documents; there are no file uploads (template fix B-07: no global multer).
    this.app.use(express.json({ limit: '256kb' }));
    this.app.get('/healthz', (_req, res) => void res.json({ status: 'ok', service: 'token-vault-cms' }));
  }

  private initializeControllers() {
    const api = express.Router();
    api.use((_req, res, next) => {
      res.setHeader('Cache-Control', 'no-store');
      next();
    });
    for (const c of this.controllers) api.use(c.init().router);
    this.app.use(PATH, api);
    // Public, signed catalog for consumers (no session; its own wire format).
    this.app.use(CATALOG_PATH, new CatalogController().router);
  }

  /** Every route each controller registered, e.g. for start-up logs and tests. */
  get routes() {
    return this.controllers.flatMap((c) => c.routes.map((r) => `${r.method} ${PATH}${r.path}`));
  }

  private initializeErrorHandling() {
    this.app.use((_req, res) => handleError(new ServiceError('E10001', 'Route not found'), res));
    this.app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => handleError(err, res));
  }
}
