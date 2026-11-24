import type { NextFunction, Request, Response } from 'express';
import { PERMISSIONS } from '@token-vault/shared';
import { APP_ROUTES } from '../../core/AppRoutes';
import { CancelCertificateDto, CertificateRequestDto, CompleteCertificateDto, KeyVersionDto, RetrieveSecretDto, SaveSecretDto, SecretLifecycleDto, SecretVersionDto, UpdateSecretValueDto } from '../../databases/repository/secret/secret.dto';
import { RotateSecretDto } from '../../databases/repository/secret/secretLifecycle.dto';
import { orgCtx, requirePermission } from '../../middlewares/auth.middleware';
import { validationMiddleware } from '../../middlewares/validation.middleware';
import SecretService from '../../services/secretService/secretService.service';
import SecretImportService, { type ImportRequest } from '../../services/secretImportService/secretImportService.service';
import { BaseController, Reply } from '../baseController';
import { badRequest } from '../../lib/errors';
import { adminGuards } from '../guards';

/**
 * /api/v1/secret (Secret Management, spec 4.9). Lists and details never contain a value;
 * only /retrieve does, for secret:retrieve, and every retrieval is audited.
 *   POST   /getall           filters, search, sort (metadata only)            secret:read_metadata
 *   GET    /getbyid/:id      metadata, versions, allowed actions              secret:read_metadata
 *   POST   /save             create with a value (no id, 201) | metadata (id)  secret:create | secret:update_metadata
 *   POST   /updateValue      `{id, payload, reason?}` new active version       secret:update_value
 *   POST   /rotate           `{id, payload?, reason?}` rotate now; without a   secret:rotate
 *                             payload the webhook generates the new value
 *   POST   /getRotations     `{secretId?, status?}` rotation history           secret:read_metadata
 *   POST   /checkProvider    `{id}` the stored credential works at its provider secret:read_metadata
 *   POST   /import           `{format: json|env, content, name?, project?, workspace?, environment?,
 *                             onConflict?: skip|new_version|fail, dryRun?}`     secret:create
 *   POST   /retrieve         `{id, version?, fields?, reason?}` the value      secret:retrieve (refusals audited)
 *   POST   /rollback         `{id, version, reason?}` new version from old     secret:manage_versions
 *   POST   /destroyVersion   `{id, version, reason?}` crypto-shred a version   secret:manage_versions
 *   POST   /activate         `{id, reason?}` PENDING → ACTIVE                  secret:update_metadata
 *   POST   /revoke           `{id, reason?}` → REVOKED                         secret:delete
 *   POST   /archive          `{id, reason?}` REVOKED/EXPIRED → ARCHIVED        secret:delete
 *   DELETE /delete/:id       destroy every version; DELETED tombstone          secret:delete
 *   POST   /keyVersion/disable · /enable  `{id, version, reason?}` a key version  secret:manage_versions
 *                             may (not) be used for key operations
 *   POST   /certificate/request  `{id, keyAlgorithm?}` renewal: new key + CSR   secret:update_value
 *   POST   /certificate/complete `{requestId, certificate?, chain?} | {requestId, secret:update_value
 *                             issuerSecretId, validityDays?}` the next version   (+ secret:retrieve to issue with a CA secret)
 *   POST   /certificate/cancel   `{requestId, reason?}` the waiting key is destroyed secret:update_value
 */
export class SecretController extends BaseController {
  private readonly importer = new SecretImportService();

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
    this.route('post', '/rotate', [requirePermission(P.SECRET_ROTATE), validationMiddleware(RotateSecretDto)], (req) => this.service.rotate(orgCtx(req), req.body as RotateSecretDto));
    this.route('post', '/checkProvider', [requirePermission(P.SECRET_READ_METADATA)], (req) => this.service.checkProvider(SecretService.writer(orgCtx(req)), String((req.body as { id?: unknown })?.id ?? '')));
    this.route('post', '/import', [requirePermission(P.SECRET_CREATE)], (req) => this.importer.import(orgCtx(req), importRequest(req.body)));
    this.route('post', '/getRotations', [requirePermission(P.SECRET_READ_METADATA)], (req) => this.service.rotations(orgCtx(req).org.id, req.body ?? {}));
    // secret:retrieve is checked by the service, so refusals are audited as secret.access_denied.
    this.route('post', '/retrieve', [requirePermission(P.SECRET_READ_METADATA), validationMiddleware(RetrieveSecretDto)], (req) => this.service.retrieve(orgCtx(req), req.body as RetrieveSecretDto));
    this.route('post', '/rollback', [requirePermission(P.SECRET_MANAGE_VERSIONS), validationMiddleware(SecretVersionDto)], (req) => this.service.rollback(orgCtx(req), req.body as SecretVersionDto));
    this.route('post', '/destroyVersion', [requirePermission(P.SECRET_MANAGE_VERSIONS), validationMiddleware(SecretVersionDto)], (req) => this.service.destroyVersion(orgCtx(req), req.body as SecretVersionDto));
    this.route('post', '/activate', [requirePermission(P.SECRET_UPDATE_METADATA), validationMiddleware(SecretLifecycleDto)], (req) => this.service.activate(orgCtx(req), req.body as SecretLifecycleDto));
    this.route('post', '/revoke', [requirePermission(P.SECRET_DELETE), validationMiddleware(SecretLifecycleDto)], (req) => this.service.revoke(orgCtx(req), req.body as SecretLifecycleDto));
    this.route('post', '/archive', [requirePermission(P.SECRET_DELETE), validationMiddleware(SecretLifecycleDto)], (req) => this.service.archive(orgCtx(req), req.body as SecretLifecycleDto));
    this.route('post', '/keyVersion/disable', [requirePermission(P.SECRET_MANAGE_VERSIONS), validationMiddleware(KeyVersionDto)], (req) => this.service.setKeyVersion(orgCtx(req), req.body as KeyVersionDto, false));
    this.route('post', '/keyVersion/enable', [requirePermission(P.SECRET_MANAGE_VERSIONS), validationMiddleware(KeyVersionDto)], (req) => this.service.setKeyVersion(orgCtx(req), req.body as KeyVersionDto, true));
    this.route('post', '/certificate/request', [requirePermission(P.SECRET_UPDATE_VALUE), validationMiddleware(CertificateRequestDto)], async (req) => new Reply(await this.service.requestCertificate(orgCtx(req), req.body as CertificateRequestDto), 201));
    this.route('post', '/certificate/complete', [requirePermission(P.SECRET_UPDATE_VALUE), validationMiddleware(CompleteCertificateDto)], (req) => this.service.completeCertificate(orgCtx(req), req.body as CompleteCertificateDto));
    this.route('post', '/certificate/cancel', [requirePermission(P.SECRET_UPDATE_VALUE), validationMiddleware(CancelCertificateDto)], (req) => this.service.cancelCertificate(orgCtx(req), req.body as CancelCertificateDto));
    this.route('delete', '/delete/:id', [requirePermission(P.SECRET_DELETE)], (req) => this.service.remove(orgCtx(req), String(req.params.id)));
  }
}

/** The import body, checked loosely here (the service validates each item against its type). */
function importRequest(raw: unknown): ImportRequest {
  const b = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>;
  const str = (v: unknown) => (typeof v === 'string' && v.trim() ? v.trim() : undefined);
  const content = typeof b.content === 'string' ? b.content : '';
  const fields: Record<string, string> = {};
  if (b.format !== 'json' && b.format !== 'env') fields.format = 'Choose json or env';
  if (!content.trim()) fields.content = 'Paste or upload the file';
  if (b.onConflict !== undefined && !['skip', 'new_version', 'fail'].includes(String(b.onConflict))) fields.onConflict = 'Choose skip, new_version or fail';
  if (Object.keys(fields).length) throw badRequest('Request validation failed', { fields });
  return { format: b.format as 'json' | 'env', content, name: str(b.name), project: str(b.project), workspace: str(b.workspace), environment: str(b.environment) as ImportRequest['environment'], onConflict: (b.onConflict as ImportRequest['onConflict']) ?? 'skip', dryRun: b.dryRun === true };
}
