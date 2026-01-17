import { Request, Response, NextFunction } from 'express';
import { AppError, logger, createErrorResponse, RateLimitError, ValidationError, isOperationalError } from '@apollo/shared';

/**
 * Global error handler middleware for Express applications
 * Handles all types of errors consistently and securely
 */
export const errorHandler = (
  err: Error | AppError,
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  // Generate request ID for tracking
  const requestId = (req as any).requestId || `req_${Date.now()}`;

  // Log error details (but sanitize for production)
  const errorLog = {
    requestId,
    method: req.method,
    path: req.path,
    error: err.message,
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
  };

  if (err instanceof AppError) {
    // Operational errors - expected, log as warning
    logger.warn(`[${requestId}] ${err.code}: ${err.message}`);

    const response: any = createErrorResponse(err.code, err.message);
    response.requestId = requestId;

    // Add validation details if present
    if (err instanceof ValidationError && err.details) {
      response.error.details = err.details;
    }

    // Add retry-after header for rate limit errors
    if (err instanceof RateLimitError && err.retryAfter) {
      res.setHeader('Retry-After', err.retryAfter);
    }

    // Don't leak stack traces in production
    if (process.env.NODE_ENV === 'development') {
      response.error.stack = err.stack;
    }

    res.status(err.statusCode).json(response);
  } else {
    // Unexpected errors - programming errors, log as error
    logger.error(`[${requestId}] Unexpected error:`, errorLog);

    // Generic response for unexpected errors (don't leak internal details)
    const response = createErrorResponse(
      'INTERNAL_ERROR',
      process.env.NODE_ENV === 'development'
        ? err.message
        : 'An unexpected error occurred. Please try again later.'
    );
    response.requestId = requestId;

    if (process.env.NODE_ENV === 'development' && response.error) {
      (response.error as any).stack = err.stack;
    }

    res.status(500).json(response);
  }
};

/**
 * 404 Not Found handler for unmatched routes
 */
export const notFoundHandler = (req: Request, res: Response): void => {
  const requestId = (req as any).requestId || `req_${Date.now()}`;
  res.status(404).json({
    success: false,
    error: {
      code: 'NOT_FOUND',
      message: `Route ${req.method} ${req.path} not found`,
    },
    requestId,
    timestamp: new Date().toISOString(),
  });
};

/**
 * Request ID middleware - adds unique ID to each request
 */
export const requestIdMiddleware = (req: Request, res: Response, next: NextFunction): void => {
  const requestId = req.headers['x-request-id'] as string || `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  (req as any).requestId = requestId;
  res.setHeader('X-Request-ID', requestId);
  next();
};

/**
 * Async handler wrapper to catch async errors
 */
export const asyncHandler = (fn: (req: Request, res: Response, next: NextFunction) => Promise<any>) => {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};
