import { Transform, Type } from 'class-transformer';
import { ArrayMaxSize, ArrayMinSize, IsArray, IsBoolean, IsDefined, IsIn, IsInt, IsOptional, IsString, Length, Max, MaxLength, Min, ValidateIf, ValidateNested } from 'class-validator';
import { ARGUMENT_OPERATORS, DATA_DETECTORS, FILTER_LIMITS, argumentProblem, operationSelectorProblem, responseFilterProblem, type ArgumentOperator, type DataDetector } from '@token-vault/shared';
import { isValidCidr } from '../../../lib/net';
import { operations } from '../../../services/providerService/registry';
import { Check, trim } from '../common/validators';

class AgentSelectorDto {
  @IsIn(['any', 'agent', 'agentType'])
  type!: 'any' | 'agent' | 'agentType';

  @IsOptional()
  @IsString()
  value?: string;
}

class IntegrationSelectorDto {
  @IsIn(['any', 'integration', 'provider'])
  type!: 'any' | 'integration' | 'provider';

  @IsOptional()
  @IsString()
  value?: string;
}

class TimeWindowDto {
  @IsInt()
  @Min(0)
  @Max(23)
  startHour!: number;

  @IsInt()
  @Min(0)
  @Max(24)
  endHour!: number;
}

class ArgumentRuleDto {
  @Transform(trim)
  @IsString()
  @MaxLength(60)
  field!: string;

  @IsIn(ARGUMENT_OPERATORS.map((o) => o.op))
  op!: ArgumentOperator;

  @Check((v) => (typeof v === 'number' || (typeof v === 'string' && v.length <= 500) || (Array.isArray(v) && v.every((x) => typeof x === 'string' && x.trim().length >= 1 && x.trim().length <= 200)) ? null : 'must be text, a number or a list of values'))
  value!: string | number | string[];
}

/** The live catalog's operation ids and applications, for operation selectors. */
const known = () => ({ operationIds: operations().map((o) => o.id), providers: [...new Set(operations().map((o) => o.provider))] });

class ConditionsDto {
  @IsDefined()
  @ValidateNested()
  @Type(() => AgentSelectorDto)
  agentSelector!: AgentSelectorDto;

  @IsDefined()
  @ValidateNested()
  @Type(() => IntegrationSelectorDto)
  integrationSelector!: IntegrationSelectorDto;

  // Exact ids, or selectors matched against the live catalog: "*", "github.*", "risk:write", "github:destructive".
  @IsArray()
  @ArrayMinSize(1, { message: 'Select at least one operation (or Any)' })
  @ArrayMaxSize(100)
  @Check((ops: unknown[]) => (ops ?? []).map((o) => (typeof o === 'string' ? operationSelectorProblem(o, known()) : 'must be text')).find(Boolean) ?? null)
  operations!: string[];

  @IsIn(['any', 'development', 'staging', 'production'])
  environment!: 'any' | 'development' | 'staging' | 'production';

  @IsOptional()
  @ValidateIf((_o, v) => v !== null)
  @ValidateNested()
  @Type(() => TimeWindowDto)
  timeWindow?: TimeWindowDto | null;

  @IsOptional()
  @IsArray()
  @ArrayMaxSize(20)
  @Transform(({ value }) => (Array.isArray(value) ? value.map((x) => (typeof x === 'string' ? x.trim() : x)) : value))
  @Check((list: unknown[]) => ((list ?? []).every((x) => typeof x === 'string' && isValidCidr(x)) ? null : 'Use IPv4 CIDR notation'))
  sourceCidrs?: string[];

  @IsOptional()
  @IsArray()
  @ArrayMaxSize(10, { message: 'At most 10 argument rules' })
  @ValidateNested({ each: true })
  @Type(() => ArgumentRuleDto)
  @Check((rules: ArgumentRuleDto[]) => (rules ?? []).map((r) => argumentProblem(r)).find(Boolean) ?? null)
  arguments?: ArgumentRuleDto[];
}

class CustomPatternDto {
  @Transform(trim)
  @IsString()
  @MaxLength(40)
  name!: string;

  @IsString()
  @MaxLength(FILTER_LIMITS.MAX_PATTERN_LENGTH)
  pattern!: string;
}

class ResponseFilterDto {
  @IsArray()
  @ArrayMaxSize(DATA_DETECTORS.length)
  @IsIn(DATA_DETECTORS.map((d) => d.id), { each: true })
  mask: DataDetector[] = [];

  @IsArray()
  @ArrayMaxSize(FILTER_LIMITS.MAX_PATTERNS)
  @ValidateNested({ each: true })
  @Type(() => CustomPatternDto)
  customPatterns: CustomPatternDto[] = [];

  @IsArray()
  @ArrayMaxSize(FILTER_LIMITS.MAX_FIELDS)
  @Transform(({ value }) => (Array.isArray(value) ? value.map((x) => (typeof x === 'string' ? x.trim() : x)) : value))
  @Check((list: unknown[]) => ((list ?? []).every((x) => typeof x === 'string' && x.length >= 1 && x.length <= 200) ? null : 'Field names are 1-200 characters'))
  removeFields: string[] = [];

  @IsIn(['off', 'flag', 'block'])
  promptInjection: 'off' | 'flag' | 'block' = 'off';
}

/** POST /policy/save: creates a policy, or updates the one named by `id`. */
export class PolicyDto {
  @IsOptional()
  @IsString()
  id?: string;

  @Transform(trim)
  @IsString({ message: 'Name must be at least 3 characters' })
  @Length(3, 80, { message: 'Name must be at least 3 characters' })
  name!: string;

  @Transform(trim)
  @IsString()
  @MaxLength(300)
  description: string = '';

  @IsIn(['ALLOW', 'DENY', 'REQUIRE_APPROVAL', 'FILTER'])
  effect!: 'ALLOW' | 'DENY' | 'REQUIRE_APPROVAL' | 'FILTER';

  @IsInt({ message: 'Priority must be between 1 and 1000' })
  @Min(1, { message: 'Priority must be between 1 and 1000' })
  @Max(1000, { message: 'Priority must be between 1 and 1000' })
  priority!: number;

  @IsBoolean()
  enabled!: boolean;

  @IsDefined()
  @ValidateNested()
  @Type(() => ConditionsDto)
  conditions!: ConditionsDto;

  // FILTER policies: what to mask, remove or check in results before the agent gets them.
  @IsOptional()
  @ValidateIf((_o, v) => v !== null)
  @ValidateNested()
  @Type(() => ResponseFilterDto)
  @Check((f: ResponseFilterDto | null) => (f ? responseFilterProblem(f) : null))
  responseFilter?: ResponseFilterDto | null;
}
