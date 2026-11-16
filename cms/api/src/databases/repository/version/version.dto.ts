import { Transform } from 'class-transformer';
import { IsBoolean, IsInt, IsObject, IsString, Length, MaxLength, Min, ValidateBy, type ValidationOptions } from 'class-validator';
import { ApplicationKeyDto } from '../application/application.dto';

const trim = ({ value }: { value: unknown }) => (typeof value === 'string' ? value.trim() : value);

/** An object whose values are all strings of at most `max` characters (resource fields). */
function IsStringRecord(max: number, options?: ValidationOptions) {
  return ValidateBy(
    {
      name: 'isStringRecord',
      validator: {
        validate: (v: unknown) => !!v && typeof v === 'object' && !Array.isArray(v) && Object.values(v).every((x) => typeof x === 'string' && x.length <= max),
        defaultMessage: () => `must be an object of strings (at most ${max} characters each)`,
      },
    },
    options,
  );
}

/** Identifies one version of one application. */
export class VersionRefDto extends ApplicationKeyDto {
  @IsInt({ message: 'version must be a version number' })
  @Min(1, { message: 'version must be a version number' })
  version!: number;
}

/** POST /version/save: replaces a draft's definition. */
export class SaveVersionDto extends VersionRefDto {
  @IsObject({ message: 'definition must be an object' })
  definition!: Record<string, unknown>;
}

/** POST /version/approve and /version/publish. */
export class ReviewDto extends VersionRefDto {
  @Transform(trim)
  @IsString()
  @MaxLength(1000, { message: 'At most 1000 characters' })
  note: string = '';

  @IsBoolean({ message: 'acknowledgeHostChange must be true or false' })
  acknowledgeHostChange: boolean = false;
}

export class RejectDto extends VersionRefDto {
  @Transform(trim)
  @IsString({ message: 'Explain what needs to change' })
  @Length(3, 1000, { message: 'Explain what needs to change' })
  note!: string;
}

/** POST /version/preview: the request the webhook would send, without any credential. */
export class PreviewDto extends VersionRefDto {
  @IsString()
  @Length(1, 100, { message: 'Choose an operation' })
  operation!: string;

  @IsStringRecord(500, { message: 'resource must be an object of strings' })
  resource: Record<string, string> = {};

  @IsObject({ message: 'input must be an object' })
  input: Record<string, unknown> = {};
}
