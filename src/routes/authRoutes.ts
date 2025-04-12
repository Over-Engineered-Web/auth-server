import express from 'express';
import * as authController from '../controllers/authControllers';
import {
  validateRegistration,
  validateLogin,
  validatePasswordReset,
  validateNewPassword,
  validateProfileUpdate,
} from '../middleware/validators';
import {
  authenticateJWT,
  isAuthenticated,
  requireAdmin,
} from '../middleware/auth';
import {
  loginLimiter,
  registrationLimiter,
  passwordResetLimiter,
} from '../middleware/rateLimiter';

const router = express.Router();

/**
 * Authentication routes
 */
// Registration
router.post(
  '/register',
  [registrationLimiter, ...validateRegistration],
  authController.register
);

// Email verification
router.get('/verify-email/:token', authController.verifyEmail);

// Login
router.post('/login', [loginLimiter, ...validateLogin], authController.login);

// Refresh token
router.post('/refresh-token', authController.refreshAccessToken);

// Password reset request
router.post(
  '/request-password-reset',
  [passwordResetLimiter, ...validatePasswordReset],
  authController.requestPasswordReset
);

// Password reset with token
router.post(
  '/reset-password',
  [...validateNewPassword],
  authController.resetPassword
);

// Logout
router.post('/logout', authenticateJWT, authController.logout);

/**
 * User profile routes (protected by JWT authentication)
 */
// Get current user profile
router.get('/me', authenticateJWT, authController.getCurrentUser);

// Update user profile
router.put(
  '/me',
  [authenticateJWT, ...validateProfileUpdate],
  authController.updateProfile
);

// Change password
router.post('/change-password', authenticateJWT, authController.changePassword);

export default router;
