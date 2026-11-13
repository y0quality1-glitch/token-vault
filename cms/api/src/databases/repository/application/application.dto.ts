import { Transform } from 'class-transformer';
import { IsIn, IsInt, IsOptional, IsString, Length, Matches, MaxLength, Min } from 'class-validator';

const trim = ({ value }: { value: unknown }) => (typeof value === 'string' ? value.trim() : value);
export const APPLICATION_KEY = /^[a-z][a-z0-9-]{1,30}$/;

/** Identifies an application (every application route except save). */
export class ApplicationKeyDto {
  @IsString({ message: 'key is required' })
  @Matches(APPLICATION_KEY, { message: 'key is not a valid application key' })
  key!: string;
}

/** POST /application/save: a new application, with a starter draft as version 1. */
export class CreateApplicationDto {
  @IsString({ message: 'Lower-case letters, digits and dashes; starts with a letter (2-31 characters)' })
  @Matches(APPLICATION_KEY, { message: 'Lower-case letters, digits and dashes; starts with a letter (2-31 characters)' })
  key!: string;

  @Transform(trim)
  @IsString({ message: 'Name is required' })
  @Length(1, 60, { message: 'Name is required (at most 60 characters)' })
  name!: string;

  @Transform(trim)
  @IsString()
  @MaxLength(500, { message: 'At most 500 characters' })
  description: string = '';
}

/** POST /application/newversion: a new draft from the latest version, or from `from`. */
export class NewVersionDto extends ApplicationKeyDto {
  @IsOptional()
  @IsInt({ message: 'from must be a version number' })
  @Min(1, { message: 'from must be a version number' })
  from?: number;
}

export class AvailabilityDto extends ApplicationKeyDto {
  @IsIn(['available', 'coming_soon'], { message: 'Choose available or coming_soon' })
  availability!: 'available' | 'coming_soon';

  @Transform(trim)
  @IsString()
  @MaxLength(500, { message: 'At most 500 characters' })
  note: string = '';
}

export class ArchiveDto extends ApplicationKeyDto {
  @Transform(trim)
  @IsString({ message: 'Give a reason' })
  @Length(3, 500, { message: 'Give a reason' })
  reason!: string;
}
