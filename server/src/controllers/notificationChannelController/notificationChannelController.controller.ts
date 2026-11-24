import { PERMISSIONS } from '@token-vault/shared';
import { APP_ROUTES } from '../../core/AppRoutes';
import { NotificationChannelIdDto, SaveNotificationChannelDto } from '../../databases/repository/secret/secretLifecycle.dto';
import { orgCtx, requirePermission } from '../../middlewares/auth.middleware';
import { validationMiddleware } from '../../middlewares/validation.middleware';
import NotificationService from '../../services/notificationService/notificationService.service';
import { BaseController, Reply } from '../baseController';
import { adminGuards } from '../guards';

/**
 * /api/v1/notificationChannel: where secret lifecycle events are sent (spec 4.9.18). Every route
 * needs notification:manage.
 *   POST   /getall           channels, with their last delivery
 *   POST   /save             create (201; a webhook channel's signing secret is returned once) or update `{id, ...}`
 *   DELETE /delete/:id
 *   POST   /test             `{id}` send a test notification now; returns the delivery
 *   POST   /getDeliveries    `{channelId?, status?}` recent deliveries
 *   POST   /retryDelivery    `{id}` send a failed delivery again
 */
export class NotificationChannelController extends BaseController {
  constructor(private readonly service = new NotificationService()) {
    super(APP_ROUTES.NOTIFICATION_CHANNEL, 'Notification channel', adminGuards);
  }

  protected _initialiseRoutes(): void {
    const manage = requirePermission(PERMISSIONS.NOTIFICATION_MANAGE);
    this.route('post', '/getall', [manage], (req) => this.service.list(orgCtx(req).org.id));
    this.route('post', '/save', [manage, validationMiddleware(SaveNotificationChannelDto)], async (req) => {
      const body = req.body as SaveNotificationChannelDto;
      const r = await this.service.save(orgCtx(req), body);
      return body.id ? r : new Reply(r, 201);
    });
    this.route('delete', '/delete/:id', [manage], (req) => this.service.remove(orgCtx(req), String(req.params.id)));
    this.route('post', '/test', [manage, validationMiddleware(NotificationChannelIdDto)], (req) => this.service.test(orgCtx(req), (req.body as NotificationChannelIdDto).id));
    this.route('post', '/getDeliveries', [manage], (req) => this.service.deliveries(orgCtx(req).org.id, req.body ?? {}));
    this.route('post', '/retryDelivery', [manage, validationMiddleware(NotificationChannelIdDto)], (req) => this.service.retry(orgCtx(req), (req.body as NotificationChannelIdDto).id));
  }
}
