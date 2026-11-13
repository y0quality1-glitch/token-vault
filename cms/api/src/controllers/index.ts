import { APIHealthCheckController } from './apiHealthController/apiHealthController.controller';
import { ApplicationController } from './applicationController/applicationController.controller';
import { AuditController } from './auditController/auditController.controller';
import { AuthController } from './authController/authController.controller';
import type { BaseController } from './baseController';
import { VersionController } from './versionController/versionController.controller';

/** Every admin controller, mounted under PATH. Register new modules here (and in APP_ROUTES). */
export const controllers = (): BaseController[] => [new APIHealthCheckController(), new AuthController(), new ApplicationController(), new VersionController(), new AuditController()];
