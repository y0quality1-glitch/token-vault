import { PERMISSIONS } from '@token-vault/shared';
import { APP_ROUTES } from '../../core/AppRoutes';
import { orgCtx, requirePermission } from '../../middlewares/auth.middleware';
import SecretExportService from '../../services/secretExportService/secretExportService.service';
import { BaseController, Reply } from '../baseController';
import { adminGuards } from '../guards';

/**
 * /api/v1/secretExport: export of secret values (spec 4.9.14), off unless SECRET_EXPORT_ENABLED=true.
 *   POST /getall              requests (and whether export is enabled)                     secret:read_metadata
 *   POST /request             `{secretIds, reason}` (201)                                  secret:export
 *   POST /approve | /reject   `{id, note?}` not by the requester                           secret:manage_access
 *   POST /prepare             `{id, passphrase}` requester: encrypt, get a 10-minute link   secret:export
 *   GET  /download/:token     requester, once: the encrypted file (then 404)               secret:export
 */
export class SecretExportController extends BaseController {
  constructor(private readonly service = new SecretExportService()) {
    super(APP_ROUTES.SECRET_EXPORT, 'Secret export', adminGuards);
  }

  protected _initialiseRoutes(): void {
    const P = PERMISSIONS;
    this.route('post', '/getall', [requirePermission(P.SECRET_READ_METADATA)], (req) => this.service.list(orgCtx(req)));
    this.route('post', '/request', [requirePermission(P.SECRET_EXPORT)], async (req) => new Reply(await this.service.request(orgCtx(req), req.body ?? {}), 201));
    this.route('post', '/approve', [requirePermission(P.SECRET_MANAGE_ACCESS)], (req) => this.service.decide(orgCtx(req), req.body ?? {}, 'APPROVED'));
    this.route('post', '/reject', [requirePermission(P.SECRET_MANAGE_ACCESS)], (req) => this.service.decide(orgCtx(req), req.body ?? {}, 'REJECTED'));
    this.route('post', '/prepare', [requirePermission(P.SECRET_EXPORT)], (req) => this.service.prepare(orgCtx(req), req.body ?? {}));
    this.route('get', '/download/:token', [requirePermission(P.SECRET_EXPORT)], (req) => this.service.download(orgCtx(req), String(req.params.token)));
  }
}
