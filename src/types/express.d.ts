import type { AppRole } from './database.js';

/**
 * OSP-61: identity attached by `requireAuth` after the token, account and device checks pass.
 * Every field comes from the verified JWT claims or from the database, never from client headers.
 */
export interface AuthContext {
  user_id: string;
  role: AppRole;
  device_id: string;
  session_id: string;
}

declare global {
  namespace Express {
    interface Request {
      auth?: AuthContext;
    }
  }
}

export {};
