import { Y0Model } from '../y0Model/y0Model.model';

/** Fields POST /version/save accepts (everything else in the body is dropped). */
export class VersionModel extends Y0Model {
  key: string = '';
  version: number = 0;
  definition: Record<string, unknown> = {};
}
