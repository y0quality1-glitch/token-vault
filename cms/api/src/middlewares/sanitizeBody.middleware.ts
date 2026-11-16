import type { Y0Model } from '../databases/repository/y0Model/y0Model.model';

/** Copies only the fields the model declares (template: sanitizeBody), into a fresh model. */
export default function sanitizeBody<T extends Y0Model>(model: T, body: Record<string, unknown>): T {
  for (const key of Object.keys(model)) if (Object.hasOwn(body, key)) (model as Record<string, unknown>)[key] = body[key];
  return model;
}
