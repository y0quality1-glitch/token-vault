import { SIGNING } from '../../config';
import AppDatabase from '../../databases/database';

/** Liveness and readiness (template: apiHealthService). */
export default class APIHealthCheckService {
  async apiHealthCheck(): Promise<{ service: string; database: 'ok'; signingKey: string }> {
    await AppDatabase.getInstance().executeExternalQuery('SELECT 1');
    return { service: 'token-vault-cms', database: 'ok', signingKey: SIGNING.keyId };
  }
}
