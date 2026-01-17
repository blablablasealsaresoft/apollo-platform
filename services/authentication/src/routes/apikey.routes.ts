/**
 * API Key Management Routes
 * Handles API key creation, rotation, and management
 */

import { Router, Request, Response, NextFunction } from 'express';
import { body, param, query, validationResult } from 'express-validator';
import { apiKeyService, ApiKeyScope, SCOPE_PRESETS } from '../services/apikey.service';
import { authenticate, requireMfa } from '../middleware/auth.middleware';
import { logger } from '@apollo/shared';

const router = Router();

// Validation middleware
const validate = (req: Request, res: Response, next: NextFunction) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      errors: errors.array(),
    });
  }
  next();
};

// List of valid scope values
const VALID_SCOPES = Object.values(ApiKeyScope);

/**
 * GET /api-keys
 * Get all API keys for the authenticated user
 */
router.get(
  '/',
  authenticate,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = (req.user as any).id;
      const keys = await apiKeyService.getUserApiKeys(userId);

      res.json({
        success: true,
        data: {
          keys,
          totalCount: keys.length,
        },
      });
    } catch (error) {
      next(error);
    }
  },
);

/**
 * GET /api-keys/scopes
 * Get available scope presets and individual scopes
 */
router.get(
  '/scopes',
  authenticate,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      res.json({
        success: true,
        data: {
          presets: Object.keys(SCOPE_PRESETS).map(name => ({
            name,
            scopes: SCOPE_PRESETS[name as keyof typeof SCOPE_PRESETS],
            description: getScopePresetDescription(name),
          })),
          availableScopes: VALID_SCOPES.map(scope => ({
            value: scope,
            category: scope.split(':')[0],
            action: scope.split(':')[1],
          })),
        },
      });
    } catch (error) {
      next(error);
    }
  },
);

/**
 * POST /api-keys
 * Create a new API key
 */
router.post(
  '/',
  authenticate,
  requireMfa, // Require MFA for API key creation
  [
    body('name').notEmpty().withMessage('API key name is required')
      .isLength({ max: 255 }).withMessage('Name must be less than 255 characters'),
    body('scopes').isArray().withMessage('Scopes must be an array'),
    body('scopes.*').isIn(VALID_SCOPES).withMessage('Invalid scope'),
    body('rateLimit').optional().isInt({ min: 1, max: 10000 }).withMessage('Rate limit must be between 1 and 10000'),
    body('rateLimitWindow').optional().isInt({ min: 1, max: 3600 }).withMessage('Rate limit window must be between 1 and 3600 seconds'),
    body('expiresIn').optional().isInt({ min: 1, max: 365 }).withMessage('Expiration must be between 1 and 365 days'),
    body('ipWhitelist').optional().isArray().withMessage('IP whitelist must be an array'),
    body('preset').optional().isIn(Object.keys(SCOPE_PRESETS)).withMessage('Invalid preset'),
  ],
  validate,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = (req.user as any).id;
      const { name, scopes, rateLimit, rateLimitWindow, expiresIn, ipWhitelist, preset, metadata } = req.body;

      // Use preset scopes if specified
      const finalScopes = preset
        ? SCOPE_PRESETS[preset as keyof typeof SCOPE_PRESETS]
        : scopes;

      const result = await apiKeyService.createApiKey({
        userId,
        name,
        scopes: finalScopes,
        rateLimit,
        rateLimitWindow,
        expiresIn,
        ipWhitelist,
        metadata,
      });

      logger.info(`API key created for user: ${userId}, name: ${name}`);

      res.status(201).json({
        success: true,
        message: 'API key created successfully. Store the key securely - it will not be shown again.',
        data: {
          id: result.id,
          apiKey: result.apiKey, // Only shown once!
          keyPrefix: result.keyPrefix,
          name: result.name,
          scopes: result.scopes,
          expiresAt: result.expiresAt,
        },
      });
    } catch (error) {
      next(error);
    }
  },
);

/**
 * GET /api-keys/:keyId
 * Get API key details (not the key itself)
 */
router.get(
  '/:keyId',
  authenticate,
  [
    param('keyId').isUUID().withMessage('Invalid key ID'),
  ],
  validate,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = (req.user as any).id;
      const keyId = req.params.keyId;

      const keys = await apiKeyService.getUserApiKeys(userId);
      const key = keys.find(k => k.id === keyId);

      if (!key) {
        return res.status(404).json({
          success: false,
          message: 'API key not found',
        });
      }

      res.json({
        success: true,
        data: key,
      });
    } catch (error) {
      next(error);
    }
  },
);

/**
 * GET /api-keys/:keyId/usage
 * Get API key usage statistics
 */
router.get(
  '/:keyId/usage',
  authenticate,
  [
    param('keyId').isUUID().withMessage('Invalid key ID'),
  ],
  validate,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = (req.user as any).id;
      const keyId = req.params.keyId;

      const stats = await apiKeyService.getKeyUsageStats(keyId, userId);

      res.json({
        success: true,
        data: stats,
      });
    } catch (error) {
      next(error);
    }
  },
);

/**
 * POST /api-keys/:keyId/rotate
 * Rotate an API key (generate new key, invalidate old)
 */
router.post(
  '/:keyId/rotate',
  authenticate,
  requireMfa, // Require MFA for key rotation
  [
    param('keyId').isUUID().withMessage('Invalid key ID'),
  ],
  validate,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = (req.user as any).id;
      const keyId = req.params.keyId;

      const result = await apiKeyService.rotateApiKey(keyId, userId);

      logger.info(`API key rotated: ${keyId} for user: ${userId}`);

      res.json({
        success: true,
        message: 'API key rotated successfully. Store the new key securely - it will not be shown again.',
        data: {
          id: result.id,
          newApiKey: result.newApiKey, // Only shown once!
          keyPrefix: result.keyPrefix,
        },
      });
    } catch (error) {
      next(error);
    }
  },
);

/**
 * PATCH /api-keys/:keyId/scopes
 * Update API key scopes
 */
router.patch(
  '/:keyId/scopes',
  authenticate,
  requireMfa, // Require MFA for scope changes
  [
    param('keyId').isUUID().withMessage('Invalid key ID'),
    body('scopes').isArray().withMessage('Scopes must be an array'),
    body('scopes.*').isIn(VALID_SCOPES).withMessage('Invalid scope'),
  ],
  validate,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = (req.user as any).id;
      const keyId = req.params.keyId;
      const { scopes } = req.body;

      await apiKeyService.updateScopes(keyId, userId, scopes);

      logger.info(`API key scopes updated: ${keyId} for user: ${userId}`);

      res.json({
        success: true,
        message: 'API key scopes updated successfully',
      });
    } catch (error) {
      next(error);
    }
  },
);

/**
 * PATCH /api-keys/:keyId/rate-limit
 * Update API key rate limits
 */
router.patch(
  '/:keyId/rate-limit',
  authenticate,
  [
    param('keyId').isUUID().withMessage('Invalid key ID'),
    body('rateLimit').isInt({ min: 1, max: 10000 }).withMessage('Rate limit must be between 1 and 10000'),
    body('rateLimitWindow').optional().isInt({ min: 1, max: 3600 }).withMessage('Rate limit window must be between 1 and 3600 seconds'),
  ],
  validate,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = (req.user as any).id;
      const keyId = req.params.keyId;
      const { rateLimit, rateLimitWindow } = req.body;

      await apiKeyService.updateRateLimit(keyId, userId, rateLimit, rateLimitWindow);

      logger.info(`API key rate limit updated: ${keyId} for user: ${userId}`);

      res.json({
        success: true,
        message: 'API key rate limit updated successfully',
      });
    } catch (error) {
      next(error);
    }
  },
);

/**
 * DELETE /api-keys/:keyId
 * Revoke an API key
 */
router.delete(
  '/:keyId',
  authenticate,
  [
    param('keyId').isUUID().withMessage('Invalid key ID'),
    body('reason').optional().isString().withMessage('Reason must be a string'),
  ],
  validate,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = (req.user as any).id;
      const keyId = req.params.keyId;
      const { reason } = req.body;

      await apiKeyService.revokeApiKey(keyId, userId, reason);

      logger.info(`API key revoked: ${keyId} for user: ${userId}, reason: ${reason}`);

      res.json({
        success: true,
        message: 'API key revoked successfully',
      });
    } catch (error) {
      next(error);
    }
  },
);

// Helper function for scope preset descriptions
function getScopePresetDescription(preset: string): string {
  const descriptions: Record<string, string> = {
    readonly: 'Read-only access to all resources',
    analyst: 'Full analyst access for investigations and intelligence',
    operator: 'Full operational access including targets and operations',
    admin: 'Full administrative access to all features',
    webhook: 'Limited access for webhook integrations',
  };
  return descriptions[preset] || 'Custom scope set';
}

export default router;
