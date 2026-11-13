import { requireOrg, requireSession } from '../middlewares/auth.middleware';

/** Every admin route except sign-in: a valid session with an organization selected. */
export const adminGuards = [requireSession, requireOrg];

/** Signed-in, organization not required (session info, organization choice). */
export const sessionGuards = [requireSession];
