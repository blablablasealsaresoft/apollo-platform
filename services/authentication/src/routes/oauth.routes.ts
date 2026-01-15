import { Router } from 'express';
import passport from 'passport';
import { authService } from '../services/auth.service';
import { createSuccessResponse } from '@apollo/shared';

const router = Router();

// Google OAuth
router.get(
  '/google',
  passport.authenticate('google', { scope: ['profile', 'email'], session: false }),
);

router.get(
  '/google/callback',
  passport.authenticate('google', { session: false, failureRedirect: '/login' }),
  async (req, res, next) => {
    try {
      const user = req.user as any;
      const { accessToken, refreshToken } = await authService.generateTokens(user);

      // Redirect to frontend with tokens
      const redirectUrl = `${process.env.FRONTEND_URL || 'http://localhost:5173'}/auth/callback?access_token=${accessToken}&refresh_token=${refreshToken}`;
      res.redirect(redirectUrl);
    } catch (error) {
      next(error);
    }
  },
);

// Microsoft OAuth
router.get(
  '/microsoft',
  passport.authenticate('microsoft', { session: false }),
);

router.get(
  '/microsoft/callback',
  passport.authenticate('microsoft', { session: false, failureRedirect: '/login' }),
  async (req, res, next) => {
    try {
      const user = req.user as any;
      const { accessToken, refreshToken } = await authService.generateTokens(user);

      const redirectUrl = `${process.env.FRONTEND_URL || 'http://localhost:5173'}/auth/callback?access_token=${accessToken}&refresh_token=${refreshToken}`;
      res.redirect(redirectUrl);
    } catch (error) {
      next(error);
    }
  },
);

// GitHub OAuth
router.get(
  '/github',
  passport.authenticate('github', { scope: ['user:email'], session: false }),
);

router.get(
  '/github/callback',
  passport.authenticate('github', { session: false, failureRedirect: '/login' }),
  async (req, res, next) => {
    try {
      const user = req.user as any;
      const { accessToken, refreshToken } = await authService.generateTokens(user);

      const redirectUrl = `${process.env.FRONTEND_URL || 'http://localhost:5173'}/auth/callback?access_token=${accessToken}&refresh_token=${refreshToken}`;
      res.redirect(redirectUrl);
    } catch (error) {
      next(error);
    }
  },
);

export default router;
