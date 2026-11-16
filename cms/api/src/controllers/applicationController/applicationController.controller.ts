import { ResponseStatus } from '../../config';
import { APP_ROUTES } from '../../core/AppRoutes';
import { ArchiveDto, AvailabilityDto, NewVersionDto } from '../../databases/repository/application/application.dto';
import authMiddleware, { admins, editors } from '../../middlewares/auth.middleware';
import { validationMiddleware } from '../../middlewares/validation.middleware';
import ApplicationService from '../../services/applicationService/applicationService.service';
import { BaseController } from '../baseController';

/**
 * /api/v1/application
 *   POST /getall           list (pageNumber, pageSize, search)      any role
 *   GET  /getbyid/:key     detail with every version                any role
 *   POST /save             new application + starter draft v1       editor, admin
 *   POST /newversion       new draft from the latest (or `from`)    editor, admin
 *   POST /availability     one-click available / coming soon        admin
 *   POST /archive          remove from the catalog                  admin
 */
export class ApplicationController extends BaseController {
  declare service: ApplicationService;

  constructor(path: APP_ROUTES = APP_ROUTES.APPLICATION, service = new ApplicationService()) {
    super(path, service);
  }

  protected _initialiseRoutes(): void {
    this.route('post', '/getall', [authMiddleware], (req, res) => this.getAll(req, res));
    this.route('get', '/getbyid/:id', [authMiddleware], (req, res) => this.getById(req, res));
    this.route('post', '/save', [authMiddleware, editors, validationMiddleware(this.dto())], (req, res) => this.postData(req, res));
    this.route('post', '/newversion', [authMiddleware, editors, validationMiddleware(NewVersionDto)], async (req, res) =>
      this.sendResponse(res, 'Version Added Successfully', await this.service.newVersion(req.body, req.user!), 0, ResponseStatus.CREATED),
    );
    this.route('post', '/availability', [authMiddleware, admins, validationMiddleware(AvailabilityDto)], async (req, res) =>
      this.sendResponse(res, 'Availability Updated Successfully', await this.service.setAvailability(req.body, req.user!)),
    );
    this.route('post', '/archive', [authMiddleware, admins, validationMiddleware(ArchiveDto)], async (req, res) =>
      this.sendResponse(res, 'Application Archived Successfully', await this.service.archive(req.body, req.user!)),
    );
  }
}
