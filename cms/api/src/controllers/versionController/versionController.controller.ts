import type { Request, Response } from 'express';
import { APP_ROUTES } from '../../core/AppRoutes';
import { VersionModel } from '../../databases/repository/version/version.model';
import { PreviewDto, RejectDto, ReviewDto, SaveVersionDto, VersionRefDto } from '../../databases/repository/version/version.dto';
import authMiddleware, { admins, editors, reviewers } from '../../middlewares/auth.middleware';
import { validationMiddleware } from '../../middlewares/validation.middleware';
import VersionService from '../../services/versionService/versionService.service';
import { BaseController } from '../baseController';

/**
 * /api/v1/version (every body names `key` and `version`)
 *   POST /getdatabyid   one version: definition, diff, signatures, allowed actions   any role
 *   POST /save          replace a draft's definition                                 editor, admin
 *   POST /submit        DRAFT → IN_REVIEW                                            editor, admin
 *   POST /withdraw      IN_REVIEW → DRAFT                                            editor, admin
 *   POST /approve       IN_REVIEW → PUBLISHED (another publisher)                    publisher, admin
 *   POST /publish       DRAFT or IN_REVIEW → PUBLISHED directly                      admin
 *   POST /reject        IN_REVIEW → DRAFT with a note                                publisher, admin
 *   POST /preview       the request the webhook would send (no credential)           any role
 */
export class VersionController extends BaseController {
  declare service: VersionService;

  constructor(path: APP_ROUTES = APP_ROUTES.VERSION, service = new VersionService()) {
    super(path, service);
  }

  protected _initialiseRoutes(): void {
    const send = (msg: string, run: (req: Request) => Promise<unknown>) => async (req: Request, res: Response) => this.sendResponse(res, msg, await run(req));
    this.route('post', '/getdatabyid', [authMiddleware, validationMiddleware(VersionRefDto)], send('Version Fetched Successfully', (req) => this.service.getDataById(req.body, req.user)));
    this.route('post', '/save', [authMiddleware, editors, validationMiddleware(SaveVersionDto)], send('Version Updated Successfully', (req) => this.service.updateDraft(this.processData(req, new VersionModel()), req.user!)));
    this.route('post', '/submit', [authMiddleware, editors, validationMiddleware(VersionRefDto)], send('Version Submitted Successfully', (req) => this.service.submit(req.body, req.user!)));
    this.route('post', '/withdraw', [authMiddleware, editors, validationMiddleware(VersionRefDto)], send('Version Withdrawn Successfully', (req) => this.service.withdraw(req.body, req.user!)));
    this.route('post', '/approve', [authMiddleware, reviewers, validationMiddleware(ReviewDto)], send('Version Published Successfully', (req) => this.service.approve(req.body, req.user!)));
    this.route('post', '/publish', [authMiddleware, admins, validationMiddleware(ReviewDto)], send('Version Published Successfully', (req) => this.service.publish(req.body, req.user!)));
    this.route('post', '/reject', [authMiddleware, reviewers, validationMiddleware(RejectDto)], send('Version Rejected Successfully', (req) => this.service.reject(req.body, req.user!)));
    this.route('post', '/preview', [authMiddleware, validationMiddleware(PreviewDto)], send('Preview', (req) => this.service.preview(req.body)));
  }
}
