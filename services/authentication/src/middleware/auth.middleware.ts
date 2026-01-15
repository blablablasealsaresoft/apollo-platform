import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { config, UnauthorizedError, ForbiddenError, User, UserRole, ClearanceLevel, JWTPayload } from '@apollo/shared';

declare global {
  namespace Express {
    interface Request {
      user?: User;
    }
  }
}

export const authenticate = async (
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new UnauthorizedError('No token provided');
    }

    const token = authHeader.substring(7);

    try {
      const decoded = jwt.verify(token, config.jwt.secret) as JWTPayload;

      // Attach user to request
      req.user = {
        id: decoded.userId,
        email: decoded.email,
        role: decoded.role,
        clearanceLevel: decoded.clearanceLevel,
      } as User;

      next();
    } catch (error) {
      throw new UnauthorizedError('Invalid or expired token');
    }
  } catch (error) {
    next(error);
  }
};

export const authorize = (...roles: UserRole[]) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      if (!req.user) {
        throw new UnauthorizedError('User not authenticated');
      }

      if (!roles.includes(req.user.role)) {
        throw new ForbiddenError('Insufficient permissions');
      }

      next();
    } catch (error) {
      next(error);
    }
  };
};

export const requireClearance = (minClearanceLevel: ClearanceLevel) => {
  const clearanceLevels: Record<ClearanceLevel, number> = {
    [ClearanceLevel.UNCLASSIFIED]: 0,
    [ClearanceLevel.RESTRICTED]: 1,
    [ClearanceLevel.CONFIDENTIAL]: 2,
    [ClearanceLevel.SECRET]: 3,
    [ClearanceLevel.TOP_SECRET]: 4,
  };

  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      if (!req.user) {
        throw new UnauthorizedError('User not authenticated');
      }

      const userLevel = clearanceLevels[req.user.clearanceLevel];
      const requiredLevel = clearanceLevels[minClearanceLevel];

      if (userLevel < requiredLevel) {
        throw new ForbiddenError('Insufficient clearance level');
      }

      next();
    } catch (error) {
      next(error);
    }
  };
};
