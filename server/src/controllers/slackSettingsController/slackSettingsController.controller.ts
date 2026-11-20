import { PERMISSIONS } from '@token-vault/shared';
import { APP_ROUTES } from '../../core/AppRoutes';
import { orgCtx, requirePermission } from '../../middlewares/auth.middleware';
import { deleteSettings, getSettingsView, saveSettings, sendTest } from '../../services/slackService/slackService.service';
import { BaseController } from '../baseController';
import { adminGuards } from '../guards';

/**
 * /api/v1/slackSettings (Settings → Notifications: the Slack workspace and channel approval requests go to)
 *   POST /getdata      the current settings (secrets never returned)    any role
 *   POST /save         connect or update (validated by the service)    policy:manage
 *   POST /disconnect   remove the settings (details: null)              policy:manage
 *   POST /test         post a test message to the channel               policy:manage
 */
export class SlackSettingsController extends BaseController {
  constructor() {
    super(APP_ROUTES.SLACK_SETTINGS, 'Slack settings', adminGuards);
  }

  protected _initialiseRoutes(): void {
    this.route('post', '/getdata', [], (req) => getSettingsView(orgCtx(req).org.id));
    this.route('post', '/save', [requirePermission(PERMISSIONS.POLICY_MANAGE)], (req) => saveSettings(orgCtx(req), req.body));
    // Previously 204 with no body; the envelope needs a body, so 200 with details: null.
    this.route('post', '/disconnect', [requirePermission(PERMISSIONS.POLICY_MANAGE)], async (req) => {
      await deleteSettings(orgCtx(req));
      return null;
    });
    this.route('post', '/test', [requirePermission(PERMISSIONS.POLICY_MANAGE)], (req) => sendTest(orgCtx(req)));
  }
}
