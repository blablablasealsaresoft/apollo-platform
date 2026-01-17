import { Router } from 'express';
import { authService } from '../services/auth.service';
import { validate } from '../middleware/validation.middleware';
import { authenticate } from '../middleware/auth.middleware';
import { rateLimiter } from '../middleware/rate-limit.middleware';
import {
  registerSchema,
  loginSchema,
  refreshTokenSchema,
  resetPasswordRequestSchema,
  resetPasswordSchema,
  changePasswordSchema,
} from '../validators/auth.validators';
import { createSuccessResponse, createErrorResponse } from '@apollo/shared';

const router = Router();

// Register
router.post(
  '/register',
  rateLimiter,
  validate(registerSchema),
  async (req, res, next) => {
    try {
      const result = await authService.register(req.body);
      res.status(201).json(createSuccessResponse(result));
    } catch (error) {
      next(error);
    }
  },
);

// Login
router.post(
  '/login',
  rateLimiter,
  validate(loginSchema),
  async (req, res, next) => {
    try {
      const { email, password } = req.body;
      const ipAddress = req.ip || 'unknown';
      const result = await authService.login(email, password, ipAddress);
      res.json(createSuccessResponse(result));
    } catch (error) {
      next(error);
    }
  },
);

// Logout
router.post('/logout', authenticate, async (req, res, next) => {
  try {
    const userId = (req.user as any).id;
    const refreshToken = req.body.refreshToken;
    await authService.logout(userId, refreshToken);
    res.json(createSuccessResponse({ message: 'Logged out successfully' }));
  } catch (error) {
    next(error);
  }
});

// Refresh token
router.post(
  '/refresh',
  validate(refreshTokenSchema),
  async (req, res, next) => {
    try {
      const { refreshToken } = req.body;
      const tokens = await authService.refreshAccessToken(refreshToken);
      res.json(createSuccessResponse(tokens));
    } catch (error) {
      next(error);
    }
  },
);

// Request password reset
router.post(
  '/reset-password/request',
  rateLimiter,
  validate(resetPasswordRequestSchema),
  async (req, res, next) => {
    try {
      const { email } = req.body;
      await authService.resetPasswordRequest(email);
      res.json(
        createSuccessResponse({
          message: 'If the email exists, a reset link has been sent',
        }),
      );
    } catch (error) {
      next(error);
    }
  },
);

// Reset password
router.post(
  '/reset-password',
  rateLimiter,
  validate(resetPasswordSchema),
  async (req, res, next) => {
    try {
      const { token, newPassword } = req.body;
      await authService.resetPassword(token, newPassword);
      res.json(createSuccessResponse({ message: 'Password reset successfully' }));
    } catch (error) {
      next(error);
    }
  },
);

// Change password
router.post(
  '/change-password',
  authenticate,
  validate(changePasswordSchema),
  async (req, res, next) => {
    try {
      const userId = (req.user as any).id;
      const { oldPassword, newPassword } = req.body;
      await authService.changePassword(userId, oldPassword, newPassword);
      res.json(createSuccessResponse({ message: 'Password changed successfully' }));
    } catch (error) {
      next(error);
    }
  },
);

// Validate token
router.get('/validate', authenticate, async (req, res, next) => {
  try {
    res.json(createSuccessResponse({ user: req.user, valid: true }));
  } catch (error) {
    next(error);
  }
});

// Get current user
router.get('/me', authenticate, async (req, res, next) => {
  try {
    res.json(createSuccessResponse(req.user));
  } catch (error) {
    next(error);
  }
});

export default router;
