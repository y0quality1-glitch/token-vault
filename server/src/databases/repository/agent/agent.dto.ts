import { Transform } from 'class-transformer';
import { ArrayMaxSize, IsArray, IsIn, IsInt, IsOptional, IsString, Max, MaxLength, Min, MinLength, ValidateIf } from 'class-validator';
import { isValidCidr } from '../../../lib/net';
import { Check, trim } from '../common/validators';

const trimEach = ({ value }: { value: unknown }) => (Array.isArray(value) ? value.map((x) => (typeof x === 'string' ? x.trim() : x)) : value);

const isUrl = (v: string) => {
  try {
    new URL(v);
    return true;
  } catch {
    return false;
  }
};

/** POST /agent/save: registers an agent (no `id`), or updates the one named by `id` (its type cannot change). */
export class AgentDto {
  @IsOptional()
  @IsString()
  id?: string;

  @Transform(trim)
  @IsString({ message: 'Name must be at least 3 characters' })
  @MinLength(3, { message: 'Name must be at least 3 characters' })
  @MaxLength(60)
  name!: string;

  @Transform(trim)
  @IsString()
  @MaxLength(240)
  description: string = '';

  @IsIn(['development', 'staging', 'production'])
  environment!: 'development' | 'staging' | 'production';

  @Transform(trim)
  @IsString({ message: 'Owner / team is required' })
  @MinLength(1, { message: 'Owner / team is required' })
  @MaxLength(60)
  ownerTeam!: string;

  // Required when registering; ignored on update.
  @ValidateIf((o: AgentDto) => !o.id)
  @IsIn(['AI_AGENT', 'APPLICATION', 'SERVICE'])
  agentType?: 'AI_AGENT' | 'APPLICATION' | 'SERVICE';

  @Transform(trim)
  @IsString({ message: 'Enter a valid URL' })
  @Check((v) => (v === '' || (typeof v === 'string' && isUrl(v)) ? null : 'Enter a valid URL'))
  callbackUrl: string = '';

  @IsArray()
  @ArrayMaxSize(20)
  @Transform(trimEach)
  @Check((list: unknown[]) => ((list ?? []).every((x) => typeof x === 'string' && isValidCidr(x)) ? null : 'Use IPv4 CIDR notation, e.g. 10.0.0.0/16'))
  allowedCidrs: string[] = [];
}

/** POST /agent/rotateCredential: graceMinutes = how long the replaced key keeps working (0 = stops at once; at most 24 h). */
export class RotateCredentialDto {
  @IsString()
  id!: string;

  @IsInt()
  @Min(0)
  @Max(1440)
  graceMinutes: number = 0;
}
