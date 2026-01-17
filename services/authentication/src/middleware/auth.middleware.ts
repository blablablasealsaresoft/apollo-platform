import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { config, redis, UnauthorizedError, ForbiddenError, User, UserRole, ClearanceLevel, JWTPayload } from '@apollo/shared';
import { sessionService } from '../services/session.service';
import { apiKeyService, ApiKeyScope } from '../services/apikey.service';
import { mfaService, MfaFactorType } from '../services/mfa.service';

// Extended request interface
declare global {
  namespace Express {
    interface Request {
      user?: User;
      session?: {
        id: string;
        mfaVerified: boolean;
        biometricVerified: boolean;
      };
      apiKey?: {
        id: string;
        scopes: ApiKeyScope[];
        userId: string;
      };
    }
  }
}

/**
 * Standard JWT authentication middleware
 * Validates access token and attaches user to request
 */
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
      // Validate token and get session info
      const { user: decoded, sessionId, mfaVerified, biometricVerified } =
        await sessionService.validateAccessToken(token);

      // Attach user and session to request
      req.user = {
        id: decoded.userId,
        email: decoded.email,
        role: decoded.role,
        clearanceLevel: decoded.clearanceLevel,
      } as User;

      req.session = {
        id: sessionId,
        mfaVerified,
        biometricVerified,
      };

      next();
    } catch (error) {
      throw new UnauthorizedError('Invalid or expired token');
    }
  } catch (error) {
    next(error);
  }
};

/**
 * API Key authentication middleware
 * Validates API key and checks required scopes
 */
export const authenticateApiKey = (requiredScopes?: ApiKeyScope[]) => {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const apiKey = req.headers['x-api-key'] as string;

      if (!apiKey) {
        throw new UnauthorizedError('API key required');
      }

      const ipAddress = req.ip || req.connection.remoteAddress || 'unknown';
      const result = await apiKeyService.validateApiKey(apiKey, requiredScopes, ipAddress);

      if (!result.valid || !result.key) {
        throw new UnauthorizedError(result.error || 'Invalid API key');
      }

      // Attach API key info to request
      req.apiKey = {
        id: result.key.id,
        scopes: result.key.scopes,
        userId: result.key.userId,
      };

      // Set rate limit headers
      res.setHeader('X-RateLimit-Remaining', result.remainingRequests?.toString() || '0');
      if (result.resetTime) {
        res.setHeader('X-RateLimit-Reset', result.resetTime.toISOString());
      }

      next();
    } catch (error) {
      next(error);
    }
  };
};

/**
 * Hybrid authentication middleware
 * Accepts either JWT token or API key
 */
export const authenticateHybrid = (requiredScopes?: ApiKeyScope[]) => {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const authHeader = req.headers.authorization;
      const apiKey = req.headers['x-api-key'] as string;

      if (authHeader && authHeader.startsWith('Bearer ')) {
        // Use JWT authentication
        return authenticate(req, res, next);
      } else if (apiKey) {
        // Use API key authentication
        return authenticateApiKey(requiredScopes)(req, res, next);
      } else {
        throw new UnauthorizedError('Authentication required');
      }
    } catch (error) {
      next(error);
    }
  };
};

/**
 * MFA verification middleware
 * Requires MFA to be verified in the current session
 */
export const requireMfa = async (
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> => {
  try {
    if (!req.user || !req.session) {
      throw new UnauthorizedError('User not authenticated');
    }

    if (!req.session.mfaVerified) {
      throw new ForbiddenError('MFA verification required', {
        code: 'MFA_REQUIRED',
        sessionId: req.session.id,
      } as any);
    }

    next();
  } catch (error) {
    next(error);
  }
};

/**
 * Biometric verification middleware
 * Requires biometric authentication in the current session
 */
export const requireBiometric = async (
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> => {
  try {
    if (!req.user || !req.session) {
      throw new UnauthorizedError('User not authenticated');
    }

    if (!req.session.biometricVerified) {
      throw new ForbiddenError('Biometric verification required', {
        code: 'BIOMETRIC_REQUIRED',
        sessionId: req.session.id,
      } as any);
    }

    next();
  } catch (error) {
    next(error);
  }
};

/**
 * Multi-factor requirement middleware
 * Requires specific number of factors to be verified
 */
export const requireFactors = (minFactors: number, requiredTypes?: MfaFactorType[]) => {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      if (!req.user || !req.session) {
        throw new UnauthorizedError('User not authenticated');
      }

      let verifiedFactors = 0;
      const verifiedTypes: MfaFactorType[] = [];

      if (req.session.mfaVerified) {
        verifiedFactors++;
        verifiedTypes.push(MfaFactorType.TOTP);
      }

      if (req.session.biometricVerified) {
        verifiedFactors++;
        // Could be any biometric, we'll count it as one factor
        verifiedTypes.push(MfaFactorType.FINGERPRINT);
      }

      if (verifiedFactors < minFactors) {
        throw new ForbiddenError(
          `Multi-factor authentication required. ${minFactors - verifiedFactors} more factor(s) needed.`,
          {
            code: 'MFA_INSUFFICIENT_FACTORS',
            required: minFactors,
            verified: verifiedFactors,
          } as any,
        );
      }

      if (requiredTypes && requiredTypes.length > 0) {
        const missingTypes = requiredTypes.filter(t => !verifiedTypes.includes(t));
        if (missingTypes.length > 0) {
          throw new ForbiddenError(
            `Required authentication factors not verified: ${missingTypes.join(', ')}`,
            {
              code: 'MFA_MISSING_REQUIRED_TYPES',
              missingTypes,
            } as any,
          );
        }
      }

      next();
    } catch (error) {
      next(error);
    }
  };
};

/**
 * Clearance-based MFA requirement middleware
 * Automatically enforces MFA requirements based on user's clearance level
 */
export const requireClearanceMfa = async (
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> => {
  try {
    if (!req.user) {
      throw new UnauthorizedError('User not authenticated');
    }

    const result = await mfaService.checkMfaRequirements(
      (req.user as any).id,
      (req.user as any).clearanceLevel,
    );

    if (!result.meetsRequirements) {
      throw new ForbiddenError(
        `Your clearance level (${(req.user as any).clearanceLevel}) requires additional MFA factors`,
        {
          code: 'MFA_CLEARANCE_REQUIREMENTS_NOT_MET',
          requiredFactors: result.requiredFactors,
          enabledFactors: result.enabledFactors,
          missingRequiredTypes: result.missingRequiredTypes,
        } as any,
      );
    }

    next();
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

      if (!roles.includes((req.user as any).role)) {
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

      const userLevel = clearanceLevels[(req.user as any).clearanceLevel];
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
