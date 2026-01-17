import rateLimit, { RateLimitRequestHandler } from 'express-rate-limit';
import { config, logger } from '@apollo/shared';

// Standard rate limiter using config values
export const standardLimiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: config.rateLimit.maxRequests,
  message: {
    success: false,
    error: {
      code: 'RATE_LIMITED',
      message: 'Too many requests from this IP, please try again later',
    },
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res, next, options) => {
    logger.warn(`Rate limit exceeded for IP: ${req.ip} on ${req.path}`);
    res.status(429).json(options.message);
  },
});

// Strict rate limiter for authentication endpoints (prevent brute force)
export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 login attempts per 15 minutes
  message: {
    success: false,
    error: {
      code: 'RATE_LIMITED',
      message: 'Too many authentication attempts, please try again in 15 minutes',
    },
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false,
  handler: (req, res, next, options) => {
    logger.warn(`Auth rate limit exceeded for IP: ${req.ip}`);
    res.status(429).json(options.message);
  },
});

// Relaxed rate limiter for read-heavy endpoints
export const readLimiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: config.rateLimit.maxRequests * 2, // Double the standard limit for reads
  message: {
    success: false,
    error: {
      code: 'RATE_LIMITED',
      message: 'Too many requests, please slow down',
    },
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Very strict rate limiter for sensitive operations (password reset, etc.)
export const sensitiveLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // 5 attempts per hour
  message: {
    success: false,
    error: {
      code: 'RATE_LIMITED',
      message: 'Too many attempts for this operation, please try again later',
    },
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipFailedRequests: false,
  handler: (req, res, next, options) => {
    logger.warn(`Sensitive operation rate limit exceeded for IP: ${req.ip} on ${req.path}`);
    res.status(429).json(options.message);
  },
});

// Create custom rate limiter with specific settings
export function createRateLimiter(options: {
  windowMs: number;
  max: number;
  message?: string;
}): RateLimitRequestHandler {
  return rateLimit({
    windowMs: options.windowMs,
    max: options.max,
    message: {
      success: false,
      error: {
        code: 'RATE_LIMITED',
        message: options.message || 'Too many requests, please try again later',
      },
    },
    standardHeaders: true,
    legacyHeaders: false,
  });
}
