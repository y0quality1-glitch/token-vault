import { Transform } from 'class-transformer';
import { Check, trim } from '../common/validators';
import { zString, zodType } from '../common/zodCompat';

/** z.array(z.string().min(1)).min(1, 'Select at least one grant').max(50): element errors win, as in the old route. */
function grantIdsProblem(v: unknown): string | null {
  if (!Array.isArray(v)) return v === undefined ? 'Required' : `Expected array, received ${zodType(v)}`;
  const element = v.map(zString({ min: 1 })).find(Boolean);
  if (element) return element;
  if (v.length < 1) return 'Select at least one grant';
  if (v.length > 50) return 'Array must contain at most 50 element(s)';
  return null;
}

/** POST /accessReview/certify: keep these grants (restarts their review interval). */
export class CertifyDto {
  @Check(grantIdsProblem)
  grantIds!: string[];

  @Transform(trim)
  @Check(zString({ max: 240 }))
  note: string = '';
}
