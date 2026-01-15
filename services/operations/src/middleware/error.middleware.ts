import { Request, Response, NextFunction } from 'express';
import { AppError, createErrorResponse } from '@apollo/shared';

export const errorHandler = (err: Error | AppError, req: Request, res: Response, next: NextFunction): void => {
  if (err instanceof AppError) {
    res.status(err.statusCode).json(createErrorResponse(err.code, err.message));
  } else {
    res.status(500).json(createErrorResponse('INTERNAL_ERROR', 'An unexpected error occurred'));
  }
};
