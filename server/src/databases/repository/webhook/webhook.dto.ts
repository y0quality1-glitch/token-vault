import { Transform } from 'class-transformer';
import { ValidateIf } from 'class-validator';
import { Check, trim } from '../common/validators';
import { zBoolean, zEnum, zString } from '../common/zodCompat';

/**
 * The old endpointUrl schema: trimmed, a URL, http(s), no query string or fragment. zod ran every
 * check and the last failure was reported, so the same order is kept here.
 */
function endpointUrlProblem(v: unknown): string | null {
  const type = zString()(v);
  if (type) return type;
  const u = v as string;
  const problems: string[] = [];
  try {
    new URL(u);
  } catch {
    problems.push('Enter a valid URL, e.g. https://vault.internal.example.com');
  }
  if (!/^https?:\/\//.test(u)) problems.push('URL must use http(s)');
  if (/[?#]/.test(u)) problems.push('Base URL must not contain a query string or fragment');
  return problems.at(-1) ?? null;
}

const ENVIRONMENTS = ['development', 'staging', 'production'] as const;
const optional = ValidateIf((_o, v) => v !== undefined);

/** POST /webhook/save without `id`: step 1, register an endpoint (PENDING). */
export class CreateWebhookDto {
  @Transform(trim)
  @Check(zString({ min: 3, minMessage: 'Name must be at least 3 characters', max: 60 }))
  name!: string;

  @Transform(trim)
  @Check(endpointUrlProblem)
  endpointUrl!: string;

  @Check(zEnum(ENVIRONMENTS))
  environment!: (typeof ENVIRONMENTS)[number];

  @Transform(trim)
  @Check(zString({ max: 240 }))
  description: string = '';
}

/** POST /webhook/save with `id`: step 2, authentication, name, description or a new URL. */
export class UpdateWebhookDto {
  @Transform(trim)
  @Check(zString({ min: 1, minMessage: 'Required' }))
  id!: string;

  @optional
  @Check(zEnum(['SHARED_SECRET_HMAC', 'MTLS']))
  authenticationType?: 'SHARED_SECRET_HMAC' | 'MTLS';

  @optional
  @Transform(trim)
  @Check(zString({ min: 3, max: 60 }))
  name?: string;

  @optional
  @Transform(trim)
  @Check(zString({ max: 240 }))
  description?: string;

  // Moving the webhook (e.g. to https://). Its pinned instance identity must still match.
  @optional
  @Transform(trim)
  @Check(endpointUrlProblem)
  endpointUrl?: string;
}

/** POST /webhook/simulateOutage `{ id, enabled }` (demo control for the webhook-unavailable scenario). */
export class SimulateOutageDto {
  @Transform(trim)
  @Check(zString({ min: 1, minMessage: 'Required' }))
  id!: string;

  @Check(zBoolean)
  enabled!: boolean;
}
