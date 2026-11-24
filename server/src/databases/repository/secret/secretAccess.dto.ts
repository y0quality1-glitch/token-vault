import { Transform, Type } from 'class-transformer';
import { ArrayMaxSize, IsArray, IsBoolean, IsIn, IsOptional, IsString, Matches, MaxLength, ValidateNested } from 'class-validator';
import { SECRET_SCOPE_SLUG, SECRET_TAG, type Environment, KEY_OPERATIONS, type KeyOperation } from '@token-vault/shared';
import { isValidCidr } from '../../../lib/net';
import { Check, trim } from '../common/validators';

/** Secret access grants and held retrievals (spec 4.9.9, 4.9.15). */
const iso = (v: unknown) => (v == null || (typeof v === 'string' && !Number.isNaN(Date.parse(v))) ? null : 'must be a date and time (ISO 8601)');

export class SecretSelectorDto {
  @IsOptional()
  @Matches(SECRET_SCOPE_SLUG, { message: 'Lower-case letters, digits and dashes' })
  project?: string;

  @IsOptional()
  @Matches(SECRET_SCOPE_SLUG, { message: 'Lower-case letters, digits and dashes' })
  workspace?: string;

  @IsOptional()
  @IsIn(['development', 'staging', 'production'], { message: 'Choose development, staging or production' })
  environment?: Environment;

  @IsOptional()
  @IsString()
  @MaxLength(40)
  typeKey?: string;

  @IsOptional()
  @Matches(SECRET_TAG, { message: 'Not a valid tag' })
  tag?: string;
}

/** POST /secretAccess/save: grant an agent access to one secret, or to every secret matching a selector. */
export class CreateSecretGrantDto {
  @IsString({ message: 'Choose an agent' })
  agentId!: string;

  @IsOptional()
  @IsString()
  secretId?: string;

  @IsOptional()
  @ValidateNested()
  @Type(() => SecretSelectorDto)
  selector?: SecretSelectorDto;

  @Transform(trim)
  @IsOptional()
  @IsString()
  @MaxLength(300)
  description?: string;

  /** Fields the agent may read (empty or omitted: every field). */
  @IsOptional()
  @IsArray()
  @ArrayMaxSize(40)
  @IsString({ each: true })
  fields?: string[];

  @IsOptional()
  @IsIn(['ACTIVE', 'ANY'], { message: 'ACTIVE (the active version only) or ANY' })
  versions?: 'ACTIVE' | 'ANY';

  @IsOptional()
  @IsArray()
  @ArrayMaxSize(20)
  @Check((v: unknown) => (Array.isArray(v) && v.every((c) => typeof c === 'string' && isValidCidr(c)) ? null : 'Each entry must be a CIDR range, e.g. 10.0.0.0/8'))
  allowedCidrs?: string[];

  @IsOptional()
  @IsBoolean()
  requireApproval?: boolean;

  @IsOptional()
  @Check(iso)
  validFrom?: string;

  @IsOptional()
  @Check((v: unknown) => iso(v) ?? (v == null || Date.parse(v as string) > Date.now() ? null : 'must be in the future'))
  expiresAt?: string | null;

  /** false: the agent may use the key (keyOperations) but never read the value. Default true. */
  @IsOptional()
  @IsBoolean()
  allowRetrieve?: boolean;

  /** Key operations the agent may ask the webhook to perform with the key (spec 4.9.3 E). */
  @IsOptional()
  @IsArray()
  @ArrayMaxSize(5)
  @Check((v: unknown) => (Array.isArray(v) && v.every((o) => (KEY_OPERATIONS as readonly unknown[]).includes(o)) ? null : `Key operations are ${KEY_OPERATIONS.join(', ')}`))
  keyOperations?: KeyOperation[];
}

export class SecretGrantRevokeDto {
  @IsString({ message: 'id is required' })
  id!: string;

  @Transform(trim)
  @IsOptional()
  @IsString()
  @MaxLength(300)
  reason?: string;
}

export class SecretApprovalDecisionDto {
  @IsString({ message: 'id is required' })
  id!: string;

  @Transform(trim)
  @IsOptional()
  @IsString()
  @MaxLength(300)
  note?: string;
}
