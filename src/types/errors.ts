/**
 * Unified HTTP Error Contract (Project Context Section 4.3)
 * Every error response from `connect-backend` follows `{ error_code, message }`.
 */
export type ErrorCode =
  | 'UNAUTHENTICATED'
  | 'ROLE_FORBIDDEN'
  | 'SESSION_NOT_BOUND'
  | 'DEVICE_REVOKED'
  | 'ACCOUNT_DISABLED'
  | 'RATE_LIMITED'
  | 'HTTPS_REQUIRED'
  | 'VALIDATION_ERROR'
  | 'NOT_FOUND'
  | 'CONFLICT'
  | 'INTERNAL_ERROR';

export interface ErrorResponsePayload {
  error_code: ErrorCode;
  message: string;
}

export class AppError extends Error {
  public readonly statusCode: number;
  public readonly errorCode: ErrorCode;

  constructor(statusCode: number, errorCode: ErrorCode, message: string) {
    super(message);
    this.name = 'AppError';
    this.statusCode = statusCode;
    this.errorCode = errorCode;
  }
}
