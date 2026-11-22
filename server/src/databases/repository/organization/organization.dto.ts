import { Transform } from 'class-transformer';
import { Check, trim } from '../common/validators';
import { zEnum, zString } from '../common/zodCompat';

/** POST /organization/save: the current organization's name and environment. */
export class OrganizationDto {
  @Transform(trim)
  @Check(zString({ min: 2, minMessage: 'Name must be at least 2 characters', max: 80 }))
  name!: string;

  @Check(zEnum(['development', 'staging', 'production']))
  environment!: 'development' | 'staging' | 'production';
}

/** POST /organization/emergencyStop. */
export class EmergencyStopDto {
  @Transform(trim)
  @Check(zString({ min: 3, minMessage: 'Say why (at least 3 characters)', max: 240 }))
  reason!: string;
}

/** POST /organization/liftEmergencyStop. */
export class LiftEmergencyStopDto {
  @Transform(trim)
  @Check(zString({ max: 240 }))
  note: string = '';
}
