import express, { type NextFunction, type Request, type RequestHandler, type Response } from 'express';
import type { ClassConstructor } from 'class-transformer';
import { ResponseStatus } from '../config';
import { ServiceError, handleError } from '../core/ApiError';
import { APP_ROUTES, SUCCESSMSG } from '../core/AppRoutes';
import { GenericResponse } from '../core/GenericResponse';
import { Pagination, Y0Params } from '../core/Y0Params';
import type { Y0Model } from '../databases/repository/y0Model/y0Model.model';
import authMiddleware from '../middlewares/auth.middleware';
import sanitizeBody from '../middlewares/sanitizeBody.middleware';
import { validationMiddleware } from '../middlewares/validation.middleware';
import type { BaseServices } from '../services/baseService';

type Method = 'get' | 'post' | 'put' | 'delete';
type Handler = (req: Request, res: Response) => Promise<void> | void;

/**
 * Base controller (template: controllers/baseController.ts). Registers a module's routes under
 * its prefix and turns results and errors into the GenericResponse envelope.
 *
 * The default route set is /getall, /getbyid/:id and /save; a module overrides
 * `_initialiseRoutes()` to expose a different set and add its own actions. Every route is
 * registered through `route()`, which also answers other methods on that path with 405
 * (template fix B-14), and catches errors so a request never hangs.
 */
export abstract class BaseController {
  public readonly router = express.Router();
  /** Paths registered by this controller (for the 405 fallback and the route list). */
  public readonly routes: { method: string; path: string }[] = [];

  protected constructor(
    protected readonly path: APP_ROUTES,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- any module's service
    public readonly service: BaseServices<any, any> | null,
  ) {}

  /** Called by App once the controller is constructed (so subclass fields exist). */
  init(): this {
    this._initialiseRoutes();
    for (const path of new Set(this.routes.map((r) => r.path))) {
      this.router.all(path, (_req, res) => handleError(new ServiceError('E10011'), res));
    }
    return this;
  }

  /** The default route set. Override to expose a different set (and call `route()` for each). */
  protected _initialiseRoutes(): void {
    this.route('post', '/getall', [authMiddleware], (req, res) => this.getAll(req, res));
    this.route('get', '/getbyid/:id', [authMiddleware], (req, res) => this.getById(req, res));
    this.route('post', '/save', [authMiddleware, validationMiddleware(this.dto())], (req, res) => this.postData(req, res));
  }

  protected dto(): ClassConstructor<object> {
    return this.service!.getDTO();
  }

  /** Registers `METHOD <prefix><sub>` with its middlewares; the handler's errors become failure envelopes. */
  protected route(method: Method, sub: string, middlewares: RequestHandler[], handler: Handler): void {
    const full = `${this.path}${sub}`;
    this.routes.push({ method: method.toUpperCase(), path: full });
    this.router[method](full, ...middlewares, async (req: Request, res: Response, _next: NextFunction) => {
      try {
        await handler(req, res);
      } catch (e) {
        handleError(e, res);
      }
    });
  }

  // ── default handlers ───────────────────────────────────────────
  protected async getAll(req: Request, res: Response) {
    const params = Pagination.from(req.body);
    const data = await this.service!.getAll(params, req.user);
    this.sendResponse(res, this.successMessage('GET'), data.records, data.totalRecords);
  }

  protected async getById(req: Request, res: Response) {
    const params = new Y0Params();
    params.id = String(req.params.id ?? '').trim() || null;
    this.sendResponse(res, this.successMessage('GET'), await this.service!.getById(params, req.user));
  }

  protected async postData(req: Request, res: Response) {
    const model = this.processData(req, this.service!.getModel());
    this.sendResponse(res, this.successMessage(model.id ? 'UPDATE' : 'ADD'), await this.service!.createRecord(model, req.user!), 0, model.id ? ResponseStatus.SUCCESS : ResponseStatus.CREATED);
  }

  /** Keeps only the fields the module's model declares (template: sanitizeBody). */
  protected processData<M extends Y0Model>(req: Request, model: M): M {
    return sanitizeBody(model, req.body as Record<string, unknown>);
  }

  protected successMessage(kind: keyof typeof SUCCESSMSG): string {
    const name = this.service?.getModuleName() ?? '';
    return `${name} ${SUCCESSMSG[kind]}`.trim();
  }

  public sendResponse<T>(res: Response, msg: string, details: T, totalRecords = 0, status: number = ResponseStatus.SUCCESS): void {
    res.status(status).json(GenericResponse.success(msg, details, totalRecords));
  }
}
