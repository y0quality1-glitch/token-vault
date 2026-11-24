import { Transform, Type } from 'class-transformer';
import { ArrayMaxSize, ArrayMinSize, IsArray, IsBoolean, IsIn, IsObject, IsOptional, IsString, Matches, MaxLength, ValidateNested } from 'class-validator';
import { NOTIFICATION_CHANNEL_KINDS, SECRET_NOTIFICATION_EVENTS, SECRET_POLICY_SCOPES, SECRET_SCOPE_SLUG, type Environment, type NotificationChannelKind, type SecretNotificationEvent, type SecretPolicyScope } from '@token-vault/shared';
import { Check, trim } from '../common/validators';

/** Expiry and retention policies, rotation and notification channels (spec 4.9.8, 4.9.11, 4.9.12, 4.9.18). */

/** An integer in [min, max], or null (the setting is not set at this level). */
const intOrNull = (min: number, max: number) => (v: unknown) => (v == null || (Number.isInteger(v) && (v as number) >= min && (v as number) <= max) ? null : `must be a whole number from ${min} to ${max}, or empty`);

/** POST /secretPolicy/save: one policy per organization, project or workspace (replaced if it exists). */
export class SaveSecretPolicyDto {
  @IsIn(SECRET_POLICY_SCOPES, { message: 'Choose organization, project or workspace' })
  scope!: SecretPolicyScope;

  @IsOptional()
  @Matches(SECRET_SCOPE_SLUG, { message: 'Lower-case letters, digits and dashes' })
  project?: string;

  @IsOptional()
  @Matches(SECRET_SCOPE_SLUG, { message: 'Lower-case letters, digits and dashes' })
  workspace?: string;

  @Check(intOrNull(1, 365))
  expiryWarningDays: number | null = null;

  @Check(intOrNull(1, 3650))
  defaultExpiresInDays: number | null = null;

  @Check(intOrNull(0, 1000))
  keepVersions: number | null = null;

  @Check(intOrNull(0, 3650))
  keepDays: number | null = null;
}

export class NotificationScopeDto {
  @IsOptional()
  @Matches(SECRET_SCOPE_SLUG, { message: 'Lower-case letters, digits and dashes' })
  project?: string;

  @IsOptional()
  @IsIn(['development', 'staging', 'production'], { message: 'Choose development, staging or production' })
  environment?: Environment;
}

const EMAIL = /^[^\s@,;<>]{1,64}@[^\s@,;<>]{1,253}\.[^\s@,;<>]{2,}$/;

/** POST /notificationChannel/save: create (no id) or update a channel. */
export class SaveNotificationChannelDto {
  @IsOptional()
  @IsString()
  id?: string;

  @Transform(trim)
  @IsString({ message: 'Name is required' })
  @MaxLength(80, { message: 'At most 80 characters' })
  @Matches(/\S/, { message: 'Name is required' })
  name!: string;

  @IsOptional()
  @IsIn(NOTIFICATION_CHANNEL_KINDS, { message: 'Choose email, webhook or Slack' })
  kind?: NotificationChannelKind;

  @IsOptional()
  @IsBoolean()
  enabled: boolean = true;

  @IsArray()
  @ArrayMinSize(1, { message: 'Choose at least one event' })
  @ArrayMaxSize(SECRET_NOTIFICATION_EVENTS.length)
  @IsIn(SECRET_NOTIFICATION_EVENTS, { each: true, message: 'Unknown event' })
  events!: SecretNotificationEvent[];

  @IsOptional()
  @IsObject()
  @ValidateNested()
  @Type(() => NotificationScopeDto)
  scope?: NotificationScopeDto;

  /** EMAIL */
  @IsOptional()
  @IsArray()
  @ArrayMaxSize(20, { message: 'At most 20 recipients' })
  @Check((v: unknown) => (v == null || (Array.isArray(v) && v.every((e) => typeof e === 'string' && EMAIL.test(e.trim()))) ? null : 'Each recipient must be an email address'))
  recipients?: string[];

  /** WEBHOOK */
  @IsOptional()
  @IsString()
  @MaxLength(2000)
  url?: string;

  /** WEBHOOK: true creates a new signing secret (shown once). */
  @IsOptional()
  @IsBoolean()
  rotateSigningSecret?: boolean;

  /** SLACK: a channel ID; omitted: the Slack connection's own channel. */
  @IsOptional()
  @Check((v: unknown) => (v == null || v === '' || (typeof v === 'string' && /^[CG][A-Z0-9]{6,20}$/.test(v)) ? null : 'Use the channel ID (starts with C or G)'))
  slackChannelId?: string | null;
}

export class NotificationChannelIdDto {
  @IsString({ message: 'id is required' })
  id!: string;
}

/**
 * POST /secret/rotate: rotate now. With `payload`: the new value (any type). Without: the
 * customer webhook generates it (types with generated fields).
 */
export class RotateSecretDto {
  @IsString({ message: 'id is required' })
  @Matches(/^sec_[A-Za-z0-9]{8,40}$/, { message: 'id is not a secret id' })
  id!: string;

  @IsOptional()
  @IsObject({ message: 'payload must be an object of the type’s fields' })
  payload?: Record<string, unknown>;

  @Transform(trim)
  @IsOptional()
  @IsString()
  @MaxLength(300)
  reason: string = '';
}
