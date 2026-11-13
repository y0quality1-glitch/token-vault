import { Transform } from 'class-transformer';
import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator';

const email = ({ value }: { value: unknown }) => (typeof value === 'string' ? value.trim() : value);

export class LoginDto {
  @Transform(email)
  @IsEmail({}, { message: 'Enter a valid email address' })
  email!: string;

  @IsString({ message: 'Password is required' })
  @IsNotEmpty({ message: 'Password is required' })
  password!: string;
}

export class ForgotPasswordDto {
  @Transform(email)
  @IsEmail({}, { message: 'Enter a valid email address' })
  email!: string;
}

export class SelectOrganizationDto {
  @IsString()
  @MinLength(1)
  organizationId!: string;
}
