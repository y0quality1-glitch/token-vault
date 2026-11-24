import { PERMISSIONS, ROLE_PERMISSIONS } from '@token-vault/shared';
import { APP_ROUTES } from '../../core/AppRoutes';
import { db } from '../../databases/client';
import { SecretEntity } from '../../entities';
import { forbidden, notFound } from '../../lib/errors';
import { orgCtx, requirePermission } from '../../middlewares/auth.middleware';
import { userActor } from '../../services/auditService/auditService.service';
import SecretLeaseService from '../../services/secretLeaseService/secretLeaseService.service';
import { BaseController, Reply } from '../baseController';
import { adminGuards } from '../guards';

/**
 * /api/v1/secretLease: leases of dynamic secrets (spec 4.9.3 J).
 *   POST /getall   `{secretId?, status?, holderId?}` leases (never a credential)                    secret:read_metadata
 *   POST /issue    `{secretId, ttlSeconds?, reason?}` a lease for the signed-in member (201; the
 *                  credentials are returned once)                                                    secret:retrieve
 *   POST /renew    `{id, ttlSeconds?}` lengthen a lease you hold                                     secret:retrieve
 *   POST /revoke   `{id, reason?}` end a lease now: your own, or anyone's with secret:manage_access   secret:read_metadata
 */
export class SecretLeaseController extends BaseController {
  constructor(private readonly service = new SecretLeaseService()) {
    super(APP_ROUTES.SECRET_LEASE, 'Secret lease', adminGuards);
  }

  protected _initialiseRoutes(): void {
    const P = PERMISSIONS;
    this.route('post', '/getall', [requirePermission(P.SECRET_READ_METADATA)], (req) => this.service.list(orgCtx(req).org.id, req.body ?? {}));
    this.route('post', '/issue', [requirePermission(P.SECRET_RETRIEVE)], async (req) => {
      const ctx = orgCtx(req);
      const b = (req.body ?? {}) as { secretId?: unknown; ttlSeconds?: unknown; reason?: unknown };
      const s = typeof b.secretId === 'string' ? await db.findOneBy(SecretEntity, { id: b.secretId, organizationId: ctx.org.id }) : null;
      if (!s || s.status === 'DELETED') throw notFound('Secret');
      const issued = await this.service.issue(s, { type: 'USER', id: ctx.user.id, name: ctx.user.fullName, actor: userActor(ctx) }, { ttlSeconds: Number.isInteger(b.ttlSeconds) ? (b.ttlSeconds as number) : undefined, reason: typeof b.reason === 'string' ? b.reason : '' });
      return new Reply(issued, 201);
    });
    this.route('post', '/renew', [requirePermission(P.SECRET_RETRIEVE)], async (req) => {
      const ctx = orgCtx(req);
      const b = (req.body ?? {}) as { id?: unknown; ttlSeconds?: unknown };
      const lease = await this.service.get(ctx.org.id, String(b.id ?? ''));
      if (lease.holderType !== 'USER' || lease.holderId !== ctx.user.id) throw forbidden('Only the holder can lengthen a lease');
      return this.service.renew(lease, userActor(ctx), Number.isInteger(b.ttlSeconds) ? (b.ttlSeconds as number) : undefined);
    });
    this.route('post', '/revoke', [requirePermission(P.SECRET_READ_METADATA)], async (req) => {
      const ctx = orgCtx(req);
      const b = (req.body ?? {}) as { id?: unknown; reason?: unknown };
      const lease = await this.service.get(ctx.org.id, String(b.id ?? ''));
      const own = lease.holderType === 'USER' && lease.holderId === ctx.user.id;
      if (!own && !ROLE_PERMISSIONS[ctx.role!]?.includes(P.SECRET_MANAGE_ACCESS)) throw forbidden(`Ending someone else's lease needs ${P.SECRET_MANAGE_ACCESS}`);
      return this.service.revoke(lease, userActor(ctx), typeof b.reason === 'string' ? b.reason.slice(0, 300) : 'Revoked by a member');
    });
  }
}
