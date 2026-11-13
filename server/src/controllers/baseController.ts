import express, { type Request, type RequestHandler, type Response } from 'express';
import { catalogError, handleError } from '../core/ApiError';
import { SUCCESSMSG } from '../core/AppRoutes';
import { GenericResponse } from '../core/GenericResponse';

type Method = 'get' | 'post' | 'put' | 'delete';

/** A handler result with a non-default HTTP status or message. */
export class Reply<T = unknown> {
  constructor(
    public readonly details: T,
    public readonly status = 200,
    public readonly msg?: string,
    /** Set for failures that still carry a payload (agent decisions): sent as a failure envelope. */
    public readonly failure?: { code: string; error: string },
  ) {}
}

export const created = <T>(details: T, msg?: string) => new Reply(details, 201, msg);

/**
 * The broker's `{ status, body }` as a reply: HTTP status unchanged, `details` = the body, and a
 * failure envelope (code = decision_code or error code, error = reason) when status >= 400.
 */
export function agentReply(r: { status: number; body: unknown }, msg = 'Request completed'): Reply {
  const b = (r.body ?? {}) as { decision_code?: string; reason?: string; error?: { code?: string; message?: string } };
  if (r.status < 400) return new Reply(r.body, r.status, msg);
  return new Reply(b.error ? (b as { error: { details?: unknown } }).error.details ?? null : r.body, r.status, '', {
    code: b.decision_code ?? b.error?.code ?? 'ERROR',
    error: b.reason ?? b.error?.message ?? 'Request failed',
  });
}

/**
 * Base controller (template: controllers/baseController.ts). A module lists its routes in
 * `_initialiseRoutes()` with `route()`; handlers return their payload (or a Reply) and the base
 * sends it in the GenericResponse envelope, or turns a thrown error into the failure envelope.
 *
 * `guards` (e.g. session and organization checks) run before every route of the controller.
 * Each registered path also answers other methods with 405 (template fix B-14).
 */
export abstract class BaseController {
  public readonly router = express.Router();
  public readonly routes: { method: string; path: string }[] = [];

  protected constructor(
    protected readonly path: string,
    protected readonly moduleName: string,
    protected readonly guards: RequestHandler[] = [],
  ) {}

  init(): this {
    this._initialiseRoutes();
    for (const path of new Set(this.routes.map((r) => r.path))) {
      this.router.all(path, (_req, res) => handleError(catalogError('E10011'), res));
    }
    return this;
  }

  protected abstract _initialiseRoutes(): void;

  /** Registers `METHOD <prefix><sub>`; the handler's result (or error) becomes the envelope. */
  protected route(method: Method, sub: string, middlewares: RequestHandler[], handler: (req: Request, res: Response) => unknown | Promise<unknown>): void {
    const full = `${this.path}${sub}`;
    this.routes.push({ method: method.toUpperCase(), path: full });
    const action = sub.split('/')[1] ?? '';
    this.router[method](full, ...this.guards, ...middlewares, async (req: Request, res: Response) => {
      try {
        const out = await handler(req, res);
        if (res.headersSent) return;
        const reply = out instanceof Reply ? out : new Reply(out);
        if (reply.failure) {
          res.status(reply.status).json(GenericResponse.failure(reply.failure.error, reply.failure.code, reply.details));
          return;
        }
        res.status(reply.status).json(GenericResponse.success(reply.msg ?? this.successMessage(action, req), reply.details));
      } catch (e) {
        handleError(e, res);
      }
    });
  }

  /** "Agent Fetched Successfully", "Grant Added Successfully", "Grant Revoke Completed Successfully". */
  protected successMessage(action: string, req: Request): string {
    if (['getall', 'getbyid', 'getdata', 'getdatabyid', 'me'].includes(action) || action.startsWith('get')) return `${this.moduleName} ${SUCCESSMSG.GET}`;
    if (action === 'save' || action === 'savemulti') return `${this.moduleName} ${(req.body as { id?: unknown })?.id ? SUCCESSMSG.UPDATE : SUCCESSMSG.ADD}`;
    if (action === 'delete') return `${this.moduleName} ${SUCCESSMSG.DELETE}`;
    const words = action.replace(/([A-Z])/g, ' $1').toLowerCase();
    return `${this.moduleName} ${words} ${SUCCESSMSG.DONE.toLowerCase()}`.replace(/^\w/, (c) => c.toUpperCase());
  }
}

/** `req.body.id` (actions and updates), or a 400 when missing (template fix B-15). */
export function bodyId(req: Request, name = 'id'): string {
  const id = (req.body as Record<string, unknown> | undefined)?.[name];
  if (typeof id !== 'string' || !id.trim()) throw catalogError('E10004', 'Request validation failed', { fields: { [name]: 'Required' } });
  return id.trim();
}
