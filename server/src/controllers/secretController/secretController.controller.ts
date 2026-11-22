import type { NextFunction, Request, Response } from 'express';
import { PERMISSIONS } from '@token-vault/shared';
import { APP_ROUTES } from '../../core/AppRoutes';
import { RetrieveSecretDto, SaveSecretDto, SecretLifecycleDto, SecretVersionDto, UpdateSecretValueDto } from '../../databases/repository/secret/secret.dto';
import { orgCtx, requirePermission } from '../../middlewares/auth.middleware';
import { validationMiddleware } from '../../middlewares/validation.middleware';
import SecretService from '../../services/secretService/secretService.service';
import { BaseController, Reply } from '../baseController';
import { adminGuards } from '../guards';

/**
 * /api/v1/secret (Secret Management, spec 4.9). Lists and details never contain a value;
 * only /retrieve does, for secret:retrieve, and every retrieval is audited.
 *   POST   /getall           filters, search, sort (metadata only)            secret:read_metadata
 *   GET    /getbyid/:id      metadata, versions, allowed actions              secret:read_metadata
 *   POST   /save             create with a value (no id, 201) | metadata (id)  secret:create | secret:update_metadata
 *   POST   /updateValue      `{id, payload, reason?}` new active version       secret:update_value
 *   POST   /rotate           `{id, payload, reason?}` manual rotation          secret:rotate
 *   POST   /retrieve         `{id, version?, fields?, reason?}` the value      secret:retrieve (refusals audited)
 *   POST   /rollback         `{id, version, reason?}` new version from old     secret:manage_versions
 *   POST   /destroyVersion   `{id, version, reason?}` crypto-shred a version   secret:manage_versions
 *   POST   /activate         `{id, reason?}` PENDING → ACTIVE                  secret:update_metadata
 *   POST   /revoke           `{id, reason?}` → REVOKED                         secret:delete
 *   POST   /archive          `{id, reason?}` REVOKED/EXPIRED → ARCHIVED        secret:delete
 *   DELETE /delete/:id       destroy every version; DELETED tombstone          secret:delete
 */
export class SecretController extends BaseController {
  constructor(private readonly service = new SecretService()) {
    super(APP_ROUTES.SECRET, 'Secret', adminGuards);
  }

  protected _initialiseRoutes(): void {
    const P = PERMISSIONS;
    /** Create and update need different permissions; decided by the presence of `id`. */
    const savePermission = (req: Request, _res: Response, next: NextFunction) => {
      SecretService.require(orgCtx(req), (req.body as { id?: unknown })?.id ? P.SECRET_UPDATE_METADATA : P.SECRET_CREATE);
      next();
    };
    this.route('post', '/getall', [requirePermission(P.SECRET_READ_METADATA)], (req) => this.service.list(orgCtx(req).org.id, req.body ?? {}));
    this.route('get', '/getbyid/:id', [requirePermission(P.SECRET_READ_METADATA)], (req) => this.service.detail(orgCtx(req), String(req.params.id)));
    this.route('post', '/save', [savePermission, validationMiddleware(SaveSecretDto)], async (req) => {
      const dto = req.body as SaveSecretDto;
      return dto.id ? this.service.updateMetadata(orgCtx(req), dto) : new Reply(await this.service.create(orgCtx(req), dto), 201);
    });
    this.route('post', '/updateValue', [requirePermission(P.SECRET_UPDATE_VALUE), validationMiddleware(UpdateSecretValueDto)], (req) => this.service.updateValue(orgCtx(req), req.body as UpdateSecretValueDto));
    this.route('post', '/rotate', [requirePermission(P.SECRET_ROTATE), validationMiddleware(UpdateSecretValueDto)], (req) => this.service.rotate(orgCtx(req), req.body as UpdateSecretValueDto));
    // secret:retrieve is checked by the service, so refusals are audited as secret.access_denied.
    this.route('post', '/retrieve', [requirePermission(P.SECRET_READ_METADATA), validationMiddleware(RetrieveSecretDto)], (req) => this.service.retrieve(orgCtx(req), req.body as RetrieveSecretDto));
    this.route('post', '/rollback', [requirePermission(P.SECRET_MANAGE_VERSIONS), validationMiddleware(SecretVersionDto)], (req) => this.service.rollback(orgCtx(req), req.body as SecretVersionDto));
    this.route('post', '/destroyVersion', [requirePermission(P.SECRET_MANAGE_VERSIONS), validationMiddleware(SecretVersionDto)], (req) => this.service.destroyVersion(orgCtx(req), req.body as SecretVersionDto));
    this.route('post', '/activate', [requirePermission(P.SECRET_UPDATE_METADATA), validationMiddleware(SecretLifecycleDto)], (req) => this.service.activate(orgCtx(req), req.body as SecretLifecycleDto));
    this.route('post', '/revoke', [requirePermission(P.SECRET_DELETE), validationMiddleware(SecretLifecycleDto)], (req) => this.service.revoke(orgCtx(req), req.body as SecretLifecycleDto));
    this.route('post', '/archive', [requirePermission(P.SECRET_DELETE), validationMiddleware(SecretLifecycleDto)], (req) => this.service.archive(orgCtx(req), req.body as SecretLifecycleDto));
    this.route('delete', '/delete/:id', [requirePermission(P.SECRET_DELETE)], (req) => this.service.remove(orgCtx(req), String(req.params.id)));
  }
}
