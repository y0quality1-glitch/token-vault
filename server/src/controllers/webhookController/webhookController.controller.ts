import type { NextFunction, Request, Response } from 'express';
import { PERMISSIONS } from '@token-vault/shared';
import { APP_ROUTES } from '../../core/AppRoutes';
import { CreateWebhookDto, SimulateOutageDto, UpdateWebhookDto } from '../../databases/repository/webhook/webhook.dto';
import { orgCtx, requirePermission } from '../../middlewares/auth.middleware';
import { validationMiddleware } from '../../middlewares/validation.middleware';
import WebhookService from '../../services/webhookService/webhookService.service';
import { BaseController, Reply, bodyId } from '../baseController';
import { adminGuards } from '../guards';

const validateCreate = validationMiddleware(CreateWebhookDto);
const validateUpdate = validationMiddleware(UpdateWebhookDto);
/** /save: with `id` an update (UpdateWebhookDto), without a registration (CreateWebhookDto). */
const validateSave = (req: Request, res: Response, next: NextFunction) => {
  const id = (req.body as { id?: unknown } | undefined)?.id;
  return (id !== undefined && id !== null ? validateUpdate : validateCreate)(req, res, next);
};

/**
 * /api/v1/webhook
 *   GET  /getbyid/:id      a webhook with the integrations that use it                any role
 *   POST /getall           every webhook, the default URL and transport options      any role
 *   POST /save             register (no id, 201) or configure (id)                   webhook:manage
 *   POST /test             `{ id }` verify / health check                            webhook:manage
 *   POST /simulateOutage   `{ id, enabled }` demo outage switch                      webhook:manage
 */
export class WebhookController extends BaseController {
  constructor(private readonly service = new WebhookService()) {
    super(APP_ROUTES.WEBHOOK, 'Webhook', adminGuards);
  }

  protected _initialiseRoutes(): void {
    this.route('post', '/getall', [], (req) => this.service.list(orgCtx(req).org.id));
    this.route('get', '/getbyid/:id', [], (req) => this.service.getById(orgCtx(req).org.id, String(req.params.id)));
    this.route('post', '/save', [requirePermission(PERMISSIONS.WEBHOOK_MANAGE), validateSave], async (req) => {
      const body = req.body as CreateWebhookDto | UpdateWebhookDto;
      if (body instanceof UpdateWebhookDto) return this.service.update(orgCtx(req), body);
      return new Reply(await this.service.create(orgCtx(req), body), 201);
    });
    this.route('post', '/test', [requirePermission(PERMISSIONS.WEBHOOK_MANAGE)], (req) => this.service.test(orgCtx(req), bodyId(req)));
    this.route('post', '/simulateOutage', [requirePermission(PERMISSIONS.WEBHOOK_MANAGE), validationMiddleware(SimulateOutageDto)], (req) => {
      const { id, enabled } = req.body as SimulateOutageDto;
      return this.service.simulateOutage(orgCtx(req), id, enabled);
    });
  }
}
