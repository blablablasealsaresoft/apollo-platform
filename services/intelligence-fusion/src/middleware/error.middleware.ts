/**
 * Error Handling Middleware
 */

import { Request, Response, NextFunction } from 'express';

// Import logger with fallback for standalone operation
let logger: any = console;
try {
  const shared = require('@apollo/shared');
  logger = shared.logger || console;
} catch {
  logger = {
    info: (...args: any[]) => console.log('[INFO]', ...args),
    warn: (...args: any[]) => console.warn('[WARN]', ...args),
    error: (...args: any[]) => console.error('[ERROR]', ...args),
    debug: (...args: any[]) => console.debug('[DEBUG]', ...args)
  };
}

export interface AppError extends Error {
  statusCode?: number;
  code?: string;
  details?: Record<string, any>;
}

/**
 * Not found handler
 */
export function notFoundHandler(req: Request, res: Response, next: NextFunction) {
  const error: AppError = new Error(`Not Found - ${req.method} ${req.originalUrl}`);
  error.statusCode = 404;
  next(error);
}

/**
 * Global error handler
 */
export function errorHandler(
  err: AppError,
  req: Request,
  res: Response,
  next: NextFunction
) {
  const statusCode = err.statusCode || 500;
  const message = err.message || 'Internal Server Error';

  // Log error
  logger.error('Request error', {
    statusCode,
    message,
    path: req.path,
    method: req.method,
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
  });

  // Send response
  res.status(statusCode).json({
    error: {
      message,
      code: err.code,
      details: err.details,
      ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
    }
  });
}

/**
 * Validation error handler
 */
export function validationErrorHandler(errors: string[]): AppError {
  const error: AppError = new Error('Validation Error');
  error.statusCode = 400;
  error.code = 'VALIDATION_ERROR';
  error.details = { errors };
  return error;
}

/**
 * Async handler wrapper
 */
export function asyncHandler(
  fn: (req: Request, res: Response, next: NextFunction) => Promise<any>
) {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

export default {
  notFoundHandler,
  errorHandler,
  validationErrorHandler,
  asyncHandler
};
