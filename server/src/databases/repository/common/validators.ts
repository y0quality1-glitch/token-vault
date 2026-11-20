import { ValidateBy, type ValidationOptions } from 'class-validator';

/** Trims strings (class-transformer @Transform). */
export const trim = ({ value }: { value: unknown }) => (typeof value === 'string' ? value.trim() : value);

/**
 * Runs a domain check (`problem(value)` returns a message or null) as a class-validator rule,
 * so DTOs reuse the shared validation functions instead of duplicating them.
 */
export function Check(problem: (value: any, object: any) => string | null, options?: ValidationOptions) {
  return ValidateBy(
    {
      name: 'domainCheck',
      validator: {
        validate: (value, args) => problem(value, args?.object) === null,
        defaultMessage: (args) => problem(args?.value, args?.object) ?? 'is invalid',
      },
    },
    options,
  );
}
