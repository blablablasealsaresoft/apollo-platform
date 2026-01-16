import { Router } from 'express';
import { mfaService } from '../services/mfa.service';
import { authenticate } from '../middleware/auth.middleware';
import { validate } from '../middleware/validation.middleware';
import { mfaTokenSchema, disableMfaSchema } from '../validators/mfa.validators';
import { createSuccessResponse } from '@apollo/shared';

const router = Router();

// Setup MFA
router.post('/setup', authenticate, async (req, res, next) => {
  try {
    const userId = req.user!.id;
    const result = await mfaService.setupMfa(userId);
    res.json(createSuccessResponse(result));
  } catch (error) {
    next(error);
  }
});

// Enable MFA
router.post(
  '/enable',
  authenticate,
  validate(mfaTokenSchema),
  async (req, res, next) => {
    try {
      const userId = req.user!.id;
      const { token } = req.body;
      const result = await mfaService.enableMfa(userId, token);
      res.json(createSuccessResponse(result));
    } catch (error) {
      next(error);
    }
  },
);

// Verify MFA
router.post('/verify', validate(mfaTokenSchema), async (req, res, next) => {
  try {
    const { userId, token } = req.body;
    const isValid = await mfaService.verifyMfa(userId, token);
    res.json(createSuccessResponse({ valid: isValid }));
  } catch (error) {
    next(error);
  }
});

// Disable MFA
router.post(
  '/disable',
  authenticate,
  validate(disableMfaSchema),
  async (req, res, next) => {
    try {
      const userId = req.user!.id;
      const { password } = req.body;
      await mfaService.disableMfa(userId, password);
      res.json(createSuccessResponse({ message: 'MFA disabled successfully' }));
    } catch (error) {
      next(error);
    }
  },
);

// Regenerate backup codes
router.post(
  '/backup-codes/regenerate',
  authenticate,
  validate(disableMfaSchema),
  async (req, res, next) => {
    try {
      const userId = req.user!.id;
      const { password } = req.body;
      const result = await mfaService.regenerateBackupCodes(userId, password);
      res.json(createSuccessResponse(result));
    } catch (error) {
      next(error);
    }
  },
);

export default router;
