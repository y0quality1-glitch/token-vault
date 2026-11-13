import { Transform } from 'class-transformer';
import { IsBoolean, IsInt, IsOptional, IsString, Length, Matches, Max, MaxLength, Min, MinLength } from 'class-validator';
import { USER_TOKEN_LIMITS } from '../../../lib/user-token';
import { trim } from '../common/validators';

/** POST /userIssuer/save: registers a user identity issuer, or updates the one named by `id`. */
export class UserIssuerDto {
  @IsOptional()
  @IsString()
  id?: string;

  @Transform(trim)
  @IsString({ message: 'Name must be at least 3 characters' })
  @Length(3, 80, { message: 'Name must be at least 3 characters' })
  name!: string;

  @Transform(trim)
  @IsString({ message: 'Enter the issuer (the tokens\' "iss" claim)' })
  @MinLength(1, { message: 'Enter the issuer (the tokens\' "iss" claim)' })
  @MaxLength(300)
  issuer!: string;

  @Transform(trim)
  @IsString({ message: 'Enter the audience (the tokens\' "aud" claim)' })
  @MinLength(1, { message: 'Enter the audience (the tokens\' "aud" claim)' })
  @MaxLength(300)
  audience!: string;

  @Transform(trim)
  @IsString({ message: 'Paste the public key' })
  @MinLength(1, { message: 'Paste the public key' })
  @MaxLength(10_000)
  publicKey!: string;

  @Transform(trim)
  @IsString({ message: 'Use a claim name such as groups or roles' })
  @Matches(/^[a-zA-Z_][a-zA-Z0-9_:./-]{0,99}$/, { message: 'Use a claim name such as groups or roles' })
  groupsClaim: string = 'groups';

  @IsInt()
  @Min(USER_TOKEN_LIMITS.MIN_LIFETIME_S, { message: 'At least 60 seconds' })
  @Max(USER_TOKEN_LIMITS.MAX_LIFETIME_S, { message: 'At most 24 hours (86400 seconds)' })
  maxTokenLifetimeSeconds: number = 3600;

  @IsBoolean()
  enabled: boolean = true;
}

/** POST /userIssuer/verifyToken: checks a user token against the organization's issuers. */
export class VerifyUserTokenDto {
  @Transform(trim)
  @IsString({ message: 'Paste a user token' })
  @MinLength(1, { message: 'Paste a user token' })
  @MaxLength(USER_TOKEN_LIMITS.MAX_TOKEN_LENGTH)
  token!: string;
}
