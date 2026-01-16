import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { config, UnauthorizedError } from '@apollo/shared';

export const authenticate = (req: Request, res: Response, next: NextFunction): void => {
  try {
    // Skip auth for public endpoints
    const publicPaths = ['/api/auth/login', '/api/auth/register', '/api/auth/refresh', '/health'];
    if (publicPaths.some(path => req.path.startsWith(path))) {
      next();
      return;
    }

    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new UnauthorizedError('No token provided');
    }

    const token = authHeader.substring(7);

    try {
      const decoded = jwt.verify(token, config.jwt.secret);
      (req as any).user = decoded;
      next();
    } catch (error) {
      throw new UnauthorizedError('Invalid or expired token');
    }
  } catch (error) {
    res.status(401).json({
      success: false,
      error: {
        code: 'UNAUTHORIZED',
        message: error instanceof Error ? error.message : 'Authentication failed',
      },
    });
  }
};
