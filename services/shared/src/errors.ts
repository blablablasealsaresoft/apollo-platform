import { AppError } from './types';

// Centralized error codes for consistency across all services
export const ERROR_CODES = {
  // 400 - Bad Request
  BAD_REQUEST: 'BAD_REQUEST',
  VALIDATION_ERROR: 'VALIDATION_ERROR',
  INVALID_INPUT: 'INVALID_INPUT',
  MISSING_FIELD: 'MISSING_FIELD',
  INVALID_FORMAT: 'INVALID_FORMAT',

  // 401 - Unauthorized
  UNAUTHORIZED: 'UNAUTHORIZED',
  INVALID_TOKEN: 'INVALID_TOKEN',
  TOKEN_EXPIRED: 'TOKEN_EXPIRED',
  INVALID_CREDENTIALS: 'INVALID_CREDENTIALS',

  // 403 - Forbidden
  FORBIDDEN: 'FORBIDDEN',
  INSUFFICIENT_PERMISSIONS: 'INSUFFICIENT_PERMISSIONS',
  ACCESS_DENIED: 'ACCESS_DENIED',
  CLEARANCE_REQUIRED: 'CLEARANCE_REQUIRED',

  // 404 - Not Found
  NOT_FOUND: 'NOT_FOUND',
  RESOURCE_NOT_FOUND: 'RESOURCE_NOT_FOUND',
  USER_NOT_FOUND: 'USER_NOT_FOUND',
  OPERATION_NOT_FOUND: 'OPERATION_NOT_FOUND',

  // 409 - Conflict
  CONFLICT: 'CONFLICT',
  DUPLICATE_ENTRY: 'DUPLICATE_ENTRY',
  RESOURCE_EXISTS: 'RESOURCE_EXISTS',

  // 422 - Unprocessable Entity
  UNPROCESSABLE_ENTITY: 'UNPROCESSABLE_ENTITY',

  // 429 - Too Many Requests
  RATE_LIMITED: 'RATE_LIMITED',
  TOO_MANY_REQUESTS: 'TOO_MANY_REQUESTS',

  // 500 - Internal Server Error
  INTERNAL_ERROR: 'INTERNAL_ERROR',
  DATABASE_ERROR: 'DATABASE_ERROR',
  UNEXPECTED_ERROR: 'UNEXPECTED_ERROR',

  // 502 - Bad Gateway
  BAD_GATEWAY: 'BAD_GATEWAY',
  UPSTREAM_ERROR: 'UPSTREAM_ERROR',

  // 503 - Service Unavailable
  SERVICE_UNAVAILABLE: 'SERVICE_UNAVAILABLE',
  DATABASE_UNAVAILABLE: 'DATABASE_UNAVAILABLE',
  CACHE_UNAVAILABLE: 'CACHE_UNAVAILABLE',

  // 504 - Gateway Timeout
  GATEWAY_TIMEOUT: 'GATEWAY_TIMEOUT',
  REQUEST_TIMEOUT: 'REQUEST_TIMEOUT',
} as const;

export class BadRequestError extends AppError {
  constructor(message: string, code = ERROR_CODES.BAD_REQUEST) {
    super(message, 400, code);
  }
}

export class UnauthorizedError extends AppError {
  constructor(message = 'Unauthorized', code = ERROR_CODES.UNAUTHORIZED) {
    super(message, 401, code);
  }
}

export class ForbiddenError extends AppError {
  constructor(message = 'Forbidden', code = ERROR_CODES.FORBIDDEN) {
    super(message, 403, code);
  }
}

export class NotFoundError extends AppError {
  constructor(message: string, code = ERROR_CODES.NOT_FOUND) {
    super(message, 404, code);
  }
}

export class ConflictError extends AppError {
  constructor(message: string, code = ERROR_CODES.CONFLICT) {
    super(message, 409, code);
  }
}

export class ValidationError extends AppError {
  public readonly details?: Record<string, string[]>;

  constructor(message: string, code = ERROR_CODES.VALIDATION_ERROR, details?: Record<string, string[]>) {
    super(message, 422, code);
    this.details = details;
  }
}

export class RateLimitError extends AppError {
  public readonly retryAfter?: number;

  constructor(message = 'Too many requests', retryAfter?: number) {
    super(message, 429, ERROR_CODES.RATE_LIMITED);
    this.retryAfter = retryAfter;
  }
}

export class InternalServerError extends AppError {
  constructor(message = 'Internal Server Error', code = ERROR_CODES.INTERNAL_ERROR) {
    super(message, 500, code);
  }
}

export class BadGatewayError extends AppError {
  constructor(message = 'Bad Gateway', code = ERROR_CODES.BAD_GATEWAY) {
    super(message, 502, code);
  }
}

export class ServiceUnavailableError extends AppError {
  constructor(message = 'Service Unavailable', code = ERROR_CODES.SERVICE_UNAVAILABLE) {
    super(message, 503, code);
  }
}

export class GatewayTimeoutError extends AppError {
  constructor(message = 'Gateway Timeout', code = ERROR_CODES.GATEWAY_TIMEOUT) {
    super(message, 504, code);
  }
}

// Helper function to determine if an error is operational (expected) vs programming error
export function isOperationalError(error: Error): boolean {
  if (error instanceof AppError) {
    return error.isOperational;
  }
  return false;
}

// Helper to wrap unknown errors
export function wrapError(error: unknown, fallbackMessage = 'An unexpected error occurred'): AppError {
  if (error instanceof AppError) {
    return error;
  }
  if (error instanceof Error) {
    return new InternalServerError(error.message || fallbackMessage);
  }
  return new InternalServerError(fallbackMessage);
}
