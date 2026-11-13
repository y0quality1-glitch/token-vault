import { Y0Model } from '../y0Model/y0Model.model';

/** Fields POST /application/save accepts (everything else in the body is dropped). */
export class ApplicationModel extends Y0Model {
  key: string = '';
  name: string = '';
  description: string = '';
}
