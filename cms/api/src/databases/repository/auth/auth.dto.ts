import { Transform } from 'class-transformer';
import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class LoginDto {
  @Transform(({ value }) => (typeof value === 'string' ? value.trim().toLowerCase() : value))
  @IsEmail({}, { message: 'Enter a valid email address' })
  email!: string;

  @IsString({ message: 'Password is required' })
  @IsNotEmpty({ message: 'Password is required' })
  password!: string;
}
