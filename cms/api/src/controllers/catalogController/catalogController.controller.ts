import express from 'express';
import { SIGNING } from '../../config';
import { handleError } from '../../core/ApiError';
import CatalogService from '../../services/catalogService/catalogService.service';

/**
 * The public, signed catalog at /catalog/v1 (no session). Its JSON is a contract with deployed
 * consumers (the control plane and customer webhooks verify every signature), so it is served
 * as-is rather than in the admin API's envelope. Errors use the envelope.
 *
 *   GET /public-key          active key and every key that signed published versions
 *   GET /definitions         every published, non-archived definition (ETag, If-None-Match)
 *   GET /definitions/:key    one of them
 */
export class CatalogController {
  public readonly router = express.Router();

  constructor(private readonly catalog = new CatalogService()) {
    const wrap = (fn: (req: express.Request, res: express.Response) => Promise<void>) => (req: express.Request, res: express.Response) => fn(req, res).catch((e) => handleError(e, res));
    this.router.get(
      '/public-key',
      wrap(async (_req, res) => void res.json(await this.catalog.publicKeys())),
    );
    this.router.get(
      '/definitions',
      wrap(async (req, res) => {
        const definitions = await this.catalog.publishedEnvelopes();
        const etag = this.catalog.etag(definitions);
        res.setHeader('ETag', etag);
        res.setHeader('Cache-Control', 'no-cache');
        if (req.headers['if-none-match'] === etag) return void res.status(304).end();
        res.json({ key_id: SIGNING.keyId, generated_at: new Date().toISOString(), definitions });
      }),
    );
    this.router.get(
      '/definitions/:key',
      wrap(async (req, res) => void res.json(await this.catalog.definition(String(req.params.key)))),
    );
  }
}
