import { IsIn, IsInt, IsString, Length, Max, Min, ValidateIf } from 'class-validator';
import { ACCESS_MODES, ROTATION_INTERVAL_MAX_DAYS, ROTATION_INTERVAL_MIN_DAYS, type AccessMode } from '@token-vault/shared';

/*
 * POST /integration/save, /oauthStart and /rotate are validated by the integration service
 * against the provider definition (the fields depend on the auth method).
 */

/** POST /integration/oauthComplete: the provider's code and state, relayed to the webhook. */
export class OAuthCompleteDto {
  @IsString()
  @Length(1, 2000)
  code!: string;

  @IsString()
  @Length(1, 200)
  state!: string;
}

/** POST /integration/oauthCancel: the state of the connection to drop. */
export class OAuthCancelDto {
  @IsString()
  @Length(1, 200)
  state!: string;
}

/** POST /integration/setAccessMode */
export class IntegrationAccessModeDto {
  @IsString()
  id!: string;

  @IsIn(ACCESS_MODES, { message: 'Choose Brokered, Decision only or Short-lived credential' })
  accessMode!: AccessMode;
}

/** POST /integration/setRotationPolicy: `intervalDays: null` clears the reminder. */
export class IntegrationRotationPolicyDto {
  @IsString()
  id!: string;

  @ValidateIf((_o, v) => v !== null)
  @IsInt()
  @Min(ROTATION_INTERVAL_MIN_DAYS, { message: `At least ${ROTATION_INTERVAL_MIN_DAYS} days` })
  @Max(ROTATION_INTERVAL_MAX_DAYS, { message: `At most ${ROTATION_INTERVAL_MAX_DAYS} days` })
  intervalDays!: number | null;
}
