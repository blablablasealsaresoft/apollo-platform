import { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';

// Enhanced helmet configuration for API security
export const securityHeaders = helmet({
  // Content Security Policy
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"], // For Swagger UI
      styleSrc: ["'self'", "'unsafe-inline'"], // For Swagger UI
      imgSrc: ["'self'", 'data:', 'https:'],
      fontSrc: ["'self'", 'https:', 'data:'],
      connectSrc: ["'self'"],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      upgradeInsecureRequests: [],
    },
  },
  // Strict Transport Security
  hsts: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true,
  },
  // Prevent MIME type sniffing
  noSniff: true,
  // Prevent clickjacking
  frameguard: { action: 'deny' },
  // Hide X-Powered-By header
  hidePoweredBy: true,
  // XSS filter
  xssFilter: true,
  // Referrer Policy
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  // Don't allow cross-domain policies
  crossOriginEmbedderPolicy: false, // Disabled for API gateway
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  crossOriginResourcePolicy: { policy: 'same-origin' },
  // Origin-Agent-Cluster header
  originAgentCluster: true,
  // DNS Prefetch Control
  dnsPrefetchControl: { allow: false },
  // Download Options (IE specific)
  ieNoOpen: true,
  // Permitted Cross-Domain Policies
  permittedCrossDomainPolicies: { permittedPolicies: 'none' },
});

// Custom security headers middleware for additional headers
export const additionalSecurityHeaders = (req: Request, res: Response, next: NextFunction): void => {
  // Add request ID for tracing
  const requestId = req.headers['x-request-id'] || `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  res.setHeader('X-Request-ID', requestId as string);
  (req as any).requestId = requestId;

  // Cache control for API responses
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.setHeader('Surrogate-Control', 'no-store');

  // Additional security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');

  // Prevent caching of sensitive data
  res.setHeader('Clear-Site-Data', '"cache"');

  next();
};

// CORS preflight handler
export const handlePreflight = (req: Request, res: Response, next: NextFunction): void => {
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Max-Age', '86400'); // 24 hours
    res.status(204).end();
    return;
  }
  next();
};
