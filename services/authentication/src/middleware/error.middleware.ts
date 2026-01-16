import { Request, Response, NextFunction } from 'express';
import { AppError, logger, createErrorResponse } from '@apollo/shared';

export const errorHandler = (
  err: Error | AppError,
  req: Request,
  res: Response,
  next: NextFunction,
): void => {
  if (err instanceof AppError) {
    logger.error(`${err.code}: ${err.message}`);
    res.status(err.statusCode).json(
      createErrorResponse(
        err.code,
        err.message,
        process.env.NODE_ENV === 'development' ? err.stack : undefined,
      ),
    );
    return;
  }

  // Unknown error
  logger.error(`Unexpected error: ${err.message}`, { stack: err.stack });
  res.status(500).json(
    createErrorResponse(
      'INTERNAL_ERROR',
      'An unexpected error occurred',
      process.env.NODE_ENV === 'development' ? err.stack : undefined,
    ),
  );
};
