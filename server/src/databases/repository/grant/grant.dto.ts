import { Transform, Type } from 'class-transformer';
import { ArrayMaxSize, ArrayMinSize, IsArray, IsBoolean, IsIn, IsInt, IsOptional, IsString, Max, MaxLength, Min, MinLength, ValidateNested } from 'class-validator';
import { isValidCidr } from '../../../lib/net';
import { GENERIC_RESOURCE, getOperation } from '../../../services/providerService/registry';
import { Check, trim } from '../common/validators';

const trimEach = ({ value }: { value: unknown }) => (Array.isArray(value) ? value.map((x) => (typeof x === 'string' ? x.trim() : x)) : value);

/** ISO 8601 date-time with a time zone (Z or an offset), as zod's `datetime({ offset: true })`. */
const DATETIME = /^\d{4}-\d{2}-\d{2}T([01]\d|2[0-3]):[0-5]\d(:[0-5]\d(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})$/;
export const dateTimeProblem = (message: string) => (v: unknown) => (typeof v === 'string' && DATETIME.test(v) && !Number.isNaN(Date.parse(v)) ? null : message);

const scopesProblem = (s: unknown[]) => ((s ?? []).every((x) => typeof x === 'string' && !!getOperation(x)) ? null : 'Unknown operation');
const repositoriesProblem = (list: unknown[]) => ((list ?? []).every((x) => typeof x === 'string' && GENERIC_RESOURCE.test(x)) ? null : 'Enter one resource per line, without spaces');
const USER_GROUPS_MESSAGE = 'User groups apply only when the agent may act for users';

/** Validity, rate limit, budgets, network and acting-for-users settings: shared by every grant body. */
class GrantLimitsDto {
  @Check(dateTimeProblem('Enter a valid start date/time'))
  validFrom!: string;

  @Check(dateTimeProblem('Enter a valid expiry date/time'))
  expiresAt!: string;

  @IsInt()
  @Min(1, { message: 'Must be at least 1' })
  @Max(600, { message: 'Maximum 600 per minute' })
  rateLimitPerMinute!: number;

  // Budgets (optional): counted over rolling windows from the access log.
  @IsOptional()
  @IsInt()
  @Min(1, { message: 'Must be at least 1' })
  @Max(100_000, { message: 'At most 100000' })
  maxRequestsPerDay: number | null = null;

  @IsOptional()
  @IsInt()
  @Min(1, { message: 'Must be at least 1' })
  @Max(10_000, { message: 'At most 10000' })
  maxWritesPerHour: number | null = null;

  @IsArray()
  @ArrayMaxSize(20)
  @Transform(trimEach)
  @Check((list: unknown[]) => ((list ?? []).every((x) => typeof x === 'string' && isValidCidr(x)) ? null : 'Use IPv4 CIDR notation'))
  allowedCidrs: string[] = [];

  // Acting for users: whether a signed user token must, may or must not accompany requests.
  @IsIn(['ALLOWED', 'REQUIRED', 'NOT_ALLOWED'])
  onBehalfOf: 'ALLOWED' | 'REQUIRED' | 'NOT_ALLOWED' = 'ALLOWED';

  @IsArray()
  @ArrayMaxSize(20, { message: 'At most 20 groups' })
  @Transform(trimEach)
  @Check((list: unknown[], o: GrantLimitsDto) => {
    if (!(list ?? []).every((x) => typeof x === 'string' && x.length >= 1 && x.length <= 200)) return 'User groups are 1-200 characters';
    return o.onBehalfOf !== 'NOT_ALLOWED' || !list?.length ? null : USER_GROUPS_MESSAGE;
  })
  allowedUserGroups: string[] = [];
}

/** Operations and resources of one grant. */
class GrantScopeFields extends GrantLimitsDto {
  // Destructive operations are checked separately: they need an approval policy (grant service).
  @IsArray()
  @ArrayMinSize(1, { message: 'Select at least one permission' })
  @Check(scopesProblem)
  scopes!: string[];

  @IsArray()
  @ArrayMaxSize(20)
  @Transform(trimEach)
  @Check(repositoriesProblem)
  repositories: string[] = [];
}

/** POST /grant/newVersion: new restrictions for the grant `id` (the old version is superseded). */
export class GrantVersionDto extends GrantScopeFields {
  @IsString()
  id!: string;
}

/** POST /grant/save: creates a grant (grants are never edited in place: see newVersion). */
export class GrantDto extends GrantScopeFields {
  @Transform(trim)
  @IsString({ message: 'Grant name must be at least 3 characters' })
  @MinLength(3, { message: 'Grant name must be at least 3 characters' })
  @MaxLength(80)
  name!: string;

  @IsString({ message: 'Select an agent' })
  @MinLength(1, { message: 'Select an agent' })
  agentId!: string;

  @IsString({ message: 'Select an integration' })
  @MinLength(1, { message: 'Select an integration' })
  integrationId!: string;

  @IsIn(['development', 'staging', 'production'])
  environment!: 'development' | 'staging' | 'production';

  @IsBoolean()
  approvalRequired: boolean = false;
}

class GrantBatchItemDto {
  @IsString({ message: 'Select an integration' })
  @MinLength(1, { message: 'Select an integration' })
  integrationId!: string;

  @IsOptional()
  @Transform(trim)
  @IsString({ message: 'Grant name must be at least 3 characters' })
  @MinLength(3, { message: 'Grant name must be at least 3 characters' })
  @MaxLength(80)
  name?: string;

  @IsArray()
  @ArrayMinSize(1, { message: 'Select at least one permission' })
  @Check(scopesProblem)
  scopes!: string[];

  @IsArray()
  @ArrayMaxSize(20)
  @Transform(trimEach)
  @Check(repositoriesProblem)
  repositories: string[] = [];
}

/**
 * POST /grant/savemulti: one agent, several applications. One grant per item (integration,
 * operations, resources, name); the other settings are shared. All are created or none.
 */
export class GrantBatchDto extends GrantLimitsDto {
  @IsString({ message: 'Select an agent' })
  @MinLength(1, { message: 'Select an agent' })
  agentId!: string;

  @IsBoolean()
  approvalRequired: boolean = false;

  @IsArray()
  @ArrayMinSize(1, { message: 'Select at least one integration' })
  @ArrayMaxSize(10, { message: 'At most 10 integrations at once' })
  @ValidateNested({ each: true })
  @Type(() => GrantBatchItemDto)
  @Check((items: GrantBatchItemDto[]) => (new Set((items ?? []).map((i) => i?.integrationId)).size === (items ?? []).length ? null : 'Each integration can appear only once'))
  items!: GrantBatchItemDto[];
}

/** POST /grant/revoke */
export class RevokeGrantDto {
  @IsString()
  id!: string;

  @Transform(trim)
  @IsString()
  @MaxLength(240)
  reason: string = '';
}

/** POST /grant/extend */
export class ExtendGrantDto {
  @IsString()
  id!: string;

  @Check(dateTimeProblem('Enter a valid date/time'))
  expiresAt!: string;
}
