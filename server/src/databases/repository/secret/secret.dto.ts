import { Transform } from 'class-transformer';
import { ArrayMaxSize, IsArray, IsBoolean, IsIn, IsInt, IsObject, IsOptional, IsString, Matches, Max, MaxLength, Min } from 'class-validator';
import { SECRET_NAME, SECRET_SCOPE_SLUG, SECRET_TAG, type Environment } from '@token-vault/shared';
import { Check, trim } from '../common/validators';

/**
 * Secret Management admin API (spec 4.9.4–4.9.10). Payloads are plain objects here: their
 * structure is checked against the secret type, by the control plane and again by the
 * customer webhook, which is the only place they are stored.
 */
const ENVIRONMENTS: Environment[] = ['development', 'staging', 'production'];
const future = (v: unknown) => (v == null || (typeof v === 'string' && Date.parse(v) > Date.now()) ? null : 'must be a date in the future');
const iso = (v: unknown) => (v == null || (typeof v === 'string' && !Number.isNaN(Date.parse(v))) ? null : 'must be a date and time (ISO 8601)');

/** The secret a route acts on. */
export class SecretIdDto {
  @IsString({ message: 'id is required' })
  @Matches(/^sec_[A-Za-z0-9]{8,40}$/, { message: 'id is not a secret id' })
  id!: string;
}

/** Metadata shared by create and update (spec 4.9.7: what can change without a new version). */
class SecretMetadataFields {
  @Transform(trim)
  @IsString({ message: 'Name is required' })
  @Matches(SECRET_NAME, { message: 'Letters, digits, spaces and . _ / - (at most 120 characters, starting with a letter or digit)' })
  name!: string;

  @Transform(trim)
  @IsOptional()
  @IsString()
  @MaxLength(500, { message: 'At most 500 characters' })
  description?: string;

  @IsOptional()
  @IsArray()
  @ArrayMaxSize(20, { message: 'At most 20 tags' })
  @Check((tags: unknown) => (Array.isArray(tags) && tags.every((t) => typeof t === 'string' && SECRET_TAG.test(t)) ? null : 'Tags are lower-case letters, digits and : . _ - (at most 40 characters)'))
  tags?: string[];

  /** Descriptive metadata, checked against the type's metadata fields. On update it replaces the metadata; omit it to keep the current one. */
  @IsOptional()
  @IsObject({ message: 'metadata must be an object' })
  metadata?: Record<string, unknown>;

  @IsOptional()
  @Check(future)
  expiresAt?: string | null;

  @IsOptional()
  @IsBoolean()
  rotationEnabled?: boolean;

  @IsOptional()
  @IsInt({ message: 'Rotation interval must be a number of days' })
  @Min(1, { message: 'At least 1 day' })
  @Max(3650, { message: 'At most 3650 days' })
  rotationIntervalDays?: number | null;
}

/**
 * POST /secret/save. Without `id`: a new secret with its first version (type, scope, payload).
 * With `id`: a metadata update (name, description, tags, metadata, expiry, rotation); the type,
 * scope and value are not changed this way (use /updateValue for the value).
 */
export class SaveSecretDto extends SecretMetadataFields {
  @IsOptional()
  @IsString()
  id?: string;

  @IsOptional()
  @IsString({ message: 'Choose a secret type' })
  @MaxLength(40)
  typeKey?: string;

  @IsOptional()
  @IsString()
  @Matches(SECRET_SCOPE_SLUG, { message: 'Lower-case letters, digits and dashes (at most 63 characters)' })
  project?: string;

  @IsOptional()
  @IsString()
  @Matches(SECRET_SCOPE_SLUG, { message: 'Lower-case letters, digits and dashes (at most 63 characters)' })
  workspace?: string;

  @IsOptional()
  @IsIn(ENVIRONMENTS, { message: 'Choose development, staging or production' })
  environment?: Environment;

  /** The value (create only). Never stored by the control plane. */
  @IsOptional()
  @IsObject({ message: 'payload must be an object of the type’s fields' })
  payload?: Record<string, unknown>;

  @IsOptional()
  @IsString()
  webhookId?: string;

  @IsOptional()
  @IsString()
  integrationId?: string | null;

  /** false: created PENDING, retrievable only once activated. */
  @IsOptional()
  @IsBoolean()
  activate: boolean = true;
}

/** POST /secret/updateValue: a new version becomes active (spec 4.9.7). */
export class UpdateSecretValueDto extends SecretIdDto {
  @IsObject({ message: 'payload must be an object of the type’s fields' })
  payload!: Record<string, unknown>;

  @Transform(trim)
  @IsOptional()
  @IsString()
  @MaxLength(300)
  reason: string = '';
}

/** POST /secret/retrieve: reveal a value (spec 4.9.6), the active version unless `version` is given. */
export class RetrieveSecretDto extends SecretIdDto {
  @IsOptional()
  @IsInt()
  @Min(1)
  version?: number;

  @IsOptional()
  @IsArray()
  @ArrayMaxSize(40)
  @IsString({ each: true })
  fields?: string[];

  @Transform(trim)
  @IsOptional()
  @IsString()
  @MaxLength(300)
  reason: string = '';
}

/** POST /secret/rollback: a new active version with the value of `version` (spec 4.9.8). */
export class SecretVersionDto extends SecretIdDto {
  @IsInt({ message: 'version is required' })
  @Min(1)
  version!: number;

  @Transform(trim)
  @IsOptional()
  @IsString()
  @MaxLength(300)
  reason: string = '';
}

/** POST /secret/activate, /revoke, /archive. */
export class SecretLifecycleDto extends SecretIdDto {
  @Transform(trim)
  @IsOptional()
  @IsString()
  @MaxLength(300)
  reason: string = '';
}

/** Filters accepted by /secret/getall (inside `filters`). */
export const SECRET_LIST_FILTERS = ['typeKey', 'category', 'project', 'workspace', 'environment', 'status', 'tag', 'integrationId', 'createdFrom', 'createdTo', 'updatedFrom', 'updatedTo', 'expiresBefore', 'expiresAfter'] as const;
export const isoProblem = iso;
