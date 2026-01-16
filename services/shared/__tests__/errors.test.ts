/**
 * Shared Errors Unit Tests
 * Tests for custom error classes, error codes, and helper functions
 */

import {
  ERROR_CODES,
  BadRequestError,
  UnauthorizedError,
  ForbiddenError,
  NotFoundError,
  ConflictError,
  ValidationError,
  RateLimitError,
  InternalServerError,
  BadGatewayError,
  ServiceUnavailableError,
  GatewayTimeoutError,
  isOperationalError,
  wrapError,
} from '../src/errors';
import { AppError } from '../src/types';

describe('ERROR_CODES', () => {
  describe('400 - Bad Request codes', () => {
    it('should have BAD_REQUEST code', () => {
      expect(ERROR_CODES.BAD_REQUEST).toBe('BAD_REQUEST');
    });

    it('should have VALIDATION_ERROR code', () => {
      expect(ERROR_CODES.VALIDATION_ERROR).toBe('VALIDATION_ERROR');
    });

    it('should have INVALID_INPUT code', () => {
      expect(ERROR_CODES.INVALID_INPUT).toBe('INVALID_INPUT');
    });

    it('should have MISSING_FIELD code', () => {
      expect(ERROR_CODES.MISSING_FIELD).toBe('MISSING_FIELD');
    });

    it('should have INVALID_FORMAT code', () => {
      expect(ERROR_CODES.INVALID_FORMAT).toBe('INVALID_FORMAT');
    });
  });

  describe('401 - Unauthorized codes', () => {
    it('should have UNAUTHORIZED code', () => {
      expect(ERROR_CODES.UNAUTHORIZED).toBe('UNAUTHORIZED');
    });

    it('should have INVALID_TOKEN code', () => {
      expect(ERROR_CODES.INVALID_TOKEN).toBe('INVALID_TOKEN');
    });

    it('should have TOKEN_EXPIRED code', () => {
      expect(ERROR_CODES.TOKEN_EXPIRED).toBe('TOKEN_EXPIRED');
    });

    it('should have INVALID_CREDENTIALS code', () => {
      expect(ERROR_CODES.INVALID_CREDENTIALS).toBe('INVALID_CREDENTIALS');
    });
  });

  describe('403 - Forbidden codes', () => {
    it('should have FORBIDDEN code', () => {
      expect(ERROR_CODES.FORBIDDEN).toBe('FORBIDDEN');
    });

    it('should have INSUFFICIENT_PERMISSIONS code', () => {
      expect(ERROR_CODES.INSUFFICIENT_PERMISSIONS).toBe('INSUFFICIENT_PERMISSIONS');
    });

    it('should have ACCESS_DENIED code', () => {
      expect(ERROR_CODES.ACCESS_DENIED).toBe('ACCESS_DENIED');
    });

    it('should have CLEARANCE_REQUIRED code', () => {
      expect(ERROR_CODES.CLEARANCE_REQUIRED).toBe('CLEARANCE_REQUIRED');
    });
  });

  describe('404 - Not Found codes', () => {
    it('should have NOT_FOUND code', () => {
      expect(ERROR_CODES.NOT_FOUND).toBe('NOT_FOUND');
    });

    it('should have RESOURCE_NOT_FOUND code', () => {
      expect(ERROR_CODES.RESOURCE_NOT_FOUND).toBe('RESOURCE_NOT_FOUND');
    });

    it('should have USER_NOT_FOUND code', () => {
      expect(ERROR_CODES.USER_NOT_FOUND).toBe('USER_NOT_FOUND');
    });

    it('should have OPERATION_NOT_FOUND code', () => {
      expect(ERROR_CODES.OPERATION_NOT_FOUND).toBe('OPERATION_NOT_FOUND');
    });
  });

  describe('409 - Conflict codes', () => {
    it('should have CONFLICT code', () => {
      expect(ERROR_CODES.CONFLICT).toBe('CONFLICT');
    });

    it('should have DUPLICATE_ENTRY code', () => {
      expect(ERROR_CODES.DUPLICATE_ENTRY).toBe('DUPLICATE_ENTRY');
    });

    it('should have RESOURCE_EXISTS code', () => {
      expect(ERROR_CODES.RESOURCE_EXISTS).toBe('RESOURCE_EXISTS');
    });
  });

  describe('5xx - Server Error codes', () => {
    it('should have INTERNAL_ERROR code', () => {
      expect(ERROR_CODES.INTERNAL_ERROR).toBe('INTERNAL_ERROR');
    });

    it('should have DATABASE_ERROR code', () => {
      expect(ERROR_CODES.DATABASE_ERROR).toBe('DATABASE_ERROR');
    });

    it('should have SERVICE_UNAVAILABLE code', () => {
      expect(ERROR_CODES.SERVICE_UNAVAILABLE).toBe('SERVICE_UNAVAILABLE');
    });

    it('should have GATEWAY_TIMEOUT code', () => {
      expect(ERROR_CODES.GATEWAY_TIMEOUT).toBe('GATEWAY_TIMEOUT');
    });
  });
});

describe('BadRequestError', () => {
  it('should create error with message and default code', () => {
    const error = new BadRequestError('Invalid input');

    expect(error.message).toBe('Invalid input');
    expect(error.statusCode).toBe(400);
    expect(error.code).toBe(ERROR_CODES.BAD_REQUEST);
    expect(error.isOperational).toBe(true);
    expect(error instanceof AppError).toBe(true);
  });

  it('should create error with custom code', () => {
    const error = new BadRequestError('Missing field', ERROR_CODES.MISSING_FIELD);

    expect(error.code).toBe(ERROR_CODES.MISSING_FIELD);
  });

  it('should have proper error stack', () => {
    const error = new BadRequestError('Test');

    expect(error.stack).toBeDefined();
    expect(error.stack).toContain('BadRequestError');
  });
});

describe('UnauthorizedError', () => {
  it('should create error with default message and code', () => {
    const error = new UnauthorizedError();

    expect(error.message).toBe('Unauthorized');
    expect(error.statusCode).toBe(401);
    expect(error.code).toBe(ERROR_CODES.UNAUTHORIZED);
    expect(error.isOperational).toBe(true);
  });

  it('should create error with custom message', () => {
    const error = new UnauthorizedError('Token expired');

    expect(error.message).toBe('Token expired');
  });

  it('should create error with custom code', () => {
    const error = new UnauthorizedError('Invalid token', ERROR_CODES.INVALID_TOKEN);

    expect(error.code).toBe(ERROR_CODES.INVALID_TOKEN);
  });
});

describe('ForbiddenError', () => {
  it('should create error with default message and code', () => {
    const error = new ForbiddenError();

    expect(error.message).toBe('Forbidden');
    expect(error.statusCode).toBe(403);
    expect(error.code).toBe(ERROR_CODES.FORBIDDEN);
  });

  it('should create error with custom message and code', () => {
    const error = new ForbiddenError('Access denied', ERROR_CODES.ACCESS_DENIED);

    expect(error.message).toBe('Access denied');
    expect(error.code).toBe(ERROR_CODES.ACCESS_DENIED);
  });
});

describe('NotFoundError', () => {
  it('should create error with message and default code', () => {
    const error = new NotFoundError('User not found');

    expect(error.message).toBe('User not found');
    expect(error.statusCode).toBe(404);
    expect(error.code).toBe(ERROR_CODES.NOT_FOUND);
  });

  it('should create error with custom code', () => {
    const error = new NotFoundError('Operation not found', ERROR_CODES.OPERATION_NOT_FOUND);

    expect(error.code).toBe(ERROR_CODES.OPERATION_NOT_FOUND);
  });
});

describe('ConflictError', () => {
  it('should create error with message and default code', () => {
    const error = new ConflictError('Resource already exists');

    expect(error.message).toBe('Resource already exists');
    expect(error.statusCode).toBe(409);
    expect(error.code).toBe(ERROR_CODES.CONFLICT);
  });

  it('should create error with custom code', () => {
    const error = new ConflictError('Duplicate entry', ERROR_CODES.DUPLICATE_ENTRY);

    expect(error.code).toBe(ERROR_CODES.DUPLICATE_ENTRY);
  });
});

describe('ValidationError', () => {
  it('should create error with message and default code', () => {
    const error = new ValidationError('Validation failed');

    expect(error.message).toBe('Validation failed');
    expect(error.statusCode).toBe(422);
    expect(error.code).toBe(ERROR_CODES.VALIDATION_ERROR);
  });

  it('should create error with validation details', () => {
    const details = {
      email: ['Invalid email format', 'Email already exists'],
      password: ['Password too short'],
    };

    const error = new ValidationError('Validation failed', ERROR_CODES.VALIDATION_ERROR, details);

    expect(error.details).toEqual(details);
    expect(error.details?.email).toHaveLength(2);
  });

  it('should have undefined details when not provided', () => {
    const error = new ValidationError('Validation failed');

    expect(error.details).toBeUndefined();
  });
});

describe('RateLimitError', () => {
  it('should create error with default message', () => {
    const error = new RateLimitError();

    expect(error.message).toBe('Too many requests');
    expect(error.statusCode).toBe(429);
    expect(error.code).toBe(ERROR_CODES.RATE_LIMITED);
  });

  it('should create error with custom message', () => {
    const error = new RateLimitError('API rate limit exceeded');

    expect(error.message).toBe('API rate limit exceeded');
  });

  it('should include retryAfter when provided', () => {
    const error = new RateLimitError('Rate limited', 60);

    expect(error.retryAfter).toBe(60);
  });

  it('should have undefined retryAfter when not provided', () => {
    const error = new RateLimitError();

    expect(error.retryAfter).toBeUndefined();
  });
});

describe('InternalServerError', () => {
  it('should create error with default message and code', () => {
    const error = new InternalServerError();

    expect(error.message).toBe('Internal Server Error');
    expect(error.statusCode).toBe(500);
    expect(error.code).toBe(ERROR_CODES.INTERNAL_ERROR);
  });

  it('should create error with custom message and code', () => {
    const error = new InternalServerError('Database error', ERROR_CODES.DATABASE_ERROR);

    expect(error.message).toBe('Database error');
    expect(error.code).toBe(ERROR_CODES.DATABASE_ERROR);
  });
});

describe('BadGatewayError', () => {
  it('should create error with default message and code', () => {
    const error = new BadGatewayError();

    expect(error.message).toBe('Bad Gateway');
    expect(error.statusCode).toBe(502);
    expect(error.code).toBe(ERROR_CODES.BAD_GATEWAY);
  });

  it('should create error with custom message and code', () => {
    const error = new BadGatewayError('Upstream service error', ERROR_CODES.UPSTREAM_ERROR);

    expect(error.message).toBe('Upstream service error');
    expect(error.code).toBe(ERROR_CODES.UPSTREAM_ERROR);
  });
});

describe('ServiceUnavailableError', () => {
  it('should create error with default message and code', () => {
    const error = new ServiceUnavailableError();

    expect(error.message).toBe('Service Unavailable');
    expect(error.statusCode).toBe(503);
    expect(error.code).toBe(ERROR_CODES.SERVICE_UNAVAILABLE);
  });

  it('should create error with custom message and code', () => {
    const error = new ServiceUnavailableError('Database unavailable', ERROR_CODES.DATABASE_UNAVAILABLE);

    expect(error.message).toBe('Database unavailable');
    expect(error.code).toBe(ERROR_CODES.DATABASE_UNAVAILABLE);
  });
});

describe('GatewayTimeoutError', () => {
  it('should create error with default message and code', () => {
    const error = new GatewayTimeoutError();

    expect(error.message).toBe('Gateway Timeout');
    expect(error.statusCode).toBe(504);
    expect(error.code).toBe(ERROR_CODES.GATEWAY_TIMEOUT);
  });

  it('should create error with custom message and code', () => {
    const error = new GatewayTimeoutError('Request timed out', ERROR_CODES.REQUEST_TIMEOUT);

    expect(error.message).toBe('Request timed out');
    expect(error.code).toBe(ERROR_CODES.REQUEST_TIMEOUT);
  });
});

describe('isOperationalError', () => {
  it('should return true for AppError instances', () => {
    const error = new BadRequestError('Test');

    expect(isOperationalError(error)).toBe(true);
  });

  it('should return true for all custom error types', () => {
    expect(isOperationalError(new UnauthorizedError())).toBe(true);
    expect(isOperationalError(new ForbiddenError())).toBe(true);
    expect(isOperationalError(new NotFoundError('Not found'))).toBe(true);
    expect(isOperationalError(new ConflictError('Conflict'))).toBe(true);
    expect(isOperationalError(new ValidationError('Invalid'))).toBe(true);
    expect(isOperationalError(new RateLimitError())).toBe(true);
    expect(isOperationalError(new InternalServerError())).toBe(true);
    expect(isOperationalError(new BadGatewayError())).toBe(true);
    expect(isOperationalError(new ServiceUnavailableError())).toBe(true);
    expect(isOperationalError(new GatewayTimeoutError())).toBe(true);
  });

  it('should return false for regular Error instances', () => {
    const error = new Error('Regular error');

    expect(isOperationalError(error)).toBe(false);
  });

  it('should return false for TypeError', () => {
    const error = new TypeError('Type error');

    expect(isOperationalError(error)).toBe(false);
  });

  it('should return false for SyntaxError', () => {
    const error = new SyntaxError('Syntax error');

    expect(isOperationalError(error)).toBe(false);
  });
});

describe('wrapError', () => {
  it('should return AppError unchanged', () => {
    const originalError = new BadRequestError('Original error');
    const wrapped = wrapError(originalError);

    expect(wrapped).toBe(originalError);
    expect(wrapped.message).toBe('Original error');
  });

  it('should wrap regular Error in InternalServerError', () => {
    const originalError = new Error('Something went wrong');
    const wrapped = wrapError(originalError);

    expect(wrapped instanceof InternalServerError).toBe(true);
    expect(wrapped.message).toBe('Something went wrong');
    expect(wrapped.statusCode).toBe(500);
  });

  it('should wrap Error with empty message using fallback', () => {
    const originalError = new Error('');
    const wrapped = wrapError(originalError, 'Custom fallback');

    expect(wrapped.message).toBe('Custom fallback');
  });

  it('should wrap unknown types in InternalServerError with fallback', () => {
    const wrapped = wrapError('string error', 'An unexpected error occurred');

    expect(wrapped instanceof InternalServerError).toBe(true);
    expect(wrapped.message).toBe('An unexpected error occurred');
  });

  it('should wrap null in InternalServerError with fallback', () => {
    const wrapped = wrapError(null);

    expect(wrapped instanceof InternalServerError).toBe(true);
    expect(wrapped.message).toBe('An unexpected error occurred');
  });

  it('should wrap undefined in InternalServerError with fallback', () => {
    const wrapped = wrapError(undefined);

    expect(wrapped instanceof InternalServerError).toBe(true);
    expect(wrapped.message).toBe('An unexpected error occurred');
  });

  it('should wrap number in InternalServerError with fallback', () => {
    const wrapped = wrapError(123);

    expect(wrapped instanceof InternalServerError).toBe(true);
  });

  it('should wrap object in InternalServerError with fallback', () => {
    const wrapped = wrapError({ error: 'test' }, 'Object error');

    expect(wrapped instanceof InternalServerError).toBe(true);
    expect(wrapped.message).toBe('Object error');
  });

  it('should use default fallback message', () => {
    const wrapped = wrapError(null);

    expect(wrapped.message).toBe('An unexpected error occurred');
  });

  it('should preserve all AppError subclasses', () => {
    const errors = [
      new UnauthorizedError(),
      new ForbiddenError(),
      new NotFoundError('Test'),
      new ConflictError('Test'),
      new ValidationError('Test'),
      new RateLimitError(),
      new InternalServerError(),
      new BadGatewayError(),
      new ServiceUnavailableError(),
      new GatewayTimeoutError(),
    ];

    errors.forEach(error => {
      const wrapped = wrapError(error);
      expect(wrapped).toBe(error);
    });
  });
});

describe('AppError inheritance', () => {
  it('all error classes should extend AppError', () => {
    expect(new BadRequestError('test') instanceof AppError).toBe(true);
    expect(new UnauthorizedError() instanceof AppError).toBe(true);
    expect(new ForbiddenError() instanceof AppError).toBe(true);
    expect(new NotFoundError('test') instanceof AppError).toBe(true);
    expect(new ConflictError('test') instanceof AppError).toBe(true);
    expect(new ValidationError('test') instanceof AppError).toBe(true);
    expect(new RateLimitError() instanceof AppError).toBe(true);
    expect(new InternalServerError() instanceof AppError).toBe(true);
    expect(new BadGatewayError() instanceof AppError).toBe(true);
    expect(new ServiceUnavailableError() instanceof AppError).toBe(true);
    expect(new GatewayTimeoutError() instanceof AppError).toBe(true);
  });

  it('all error classes should extend Error', () => {
    expect(new BadRequestError('test') instanceof Error).toBe(true);
    expect(new UnauthorizedError() instanceof Error).toBe(true);
    expect(new ForbiddenError() instanceof Error).toBe(true);
    expect(new NotFoundError('test') instanceof Error).toBe(true);
    expect(new ConflictError('test') instanceof Error).toBe(true);
    expect(new ValidationError('test') instanceof Error).toBe(true);
    expect(new RateLimitError() instanceof Error).toBe(true);
    expect(new InternalServerError() instanceof Error).toBe(true);
    expect(new BadGatewayError() instanceof Error).toBe(true);
    expect(new ServiceUnavailableError() instanceof Error).toBe(true);
    expect(new GatewayTimeoutError() instanceof Error).toBe(true);
  });

  it('all error classes should have correct name property', () => {
    expect(new BadRequestError('test').name).toBe('Error');
    expect(new UnauthorizedError().name).toBe('Error');
    expect(new InternalServerError().name).toBe('Error');
  });
});
