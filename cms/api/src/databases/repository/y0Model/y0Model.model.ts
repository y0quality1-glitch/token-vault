/**
 * Base model (template: databases/repository/y0Model). A model lists the body fields a save
 * route accepts; every field has an initializer, which sanitizeBody relies on.
 */
export class Y0Model {
  id: string | null = null;
}
