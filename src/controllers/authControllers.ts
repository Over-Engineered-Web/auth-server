import { Request, Response } from 'express';
import passport from 'passport';
import User, { IUser } from '../models/User';
import { 
  generateToken, 
  generateRefreshToken, 
  generateVerificationToken,
  generatePasswordResetToken
} from '../utils/tokens';
import { logger, logAuthEvent } from '../utils/logger';
import { sanitizeUser, isSuspiciousLogin } from '../utils/security';

/**
 * Register a new user
 */
export const register = async (req: Request, res: Response): Promise<void> => {
  const { email, password, firstName, lastName } = req.body;
  
  try {
    // Check if user already exists
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    
    if (existingUser) {
      logger.info(`Registration attempt with existing email: ${email}`);
      res.status(400).json({ message: 'Email is already registered' });
      return;
    }
    
    // Generate verification token
    const verificationToken = generateVerificationToken();
    const verificationExpires = new Date();
    verificationExpires.setHours(verificationExpires.getHours() + 24); // Token valid for 24 hours
    
    // Create new user
    const newUser = new User({
      email: email.toLowerCase(),
      password,
      firstName,
      lastName,
      verificationToken,
      verificationExpires
    });
    
    await newUser.save();
    
    // Log registration event
    logAuthEvent('register', newUser.id, { email: email.toLowerCase() });
    
    // TODO: Send verification email with token
    // This would typically involve an email service like SendGrid, Mailgun, etc.
    
    // Return success response (without sensitive data)
    res.status(201).json({
      message: 'Registration successful! Please check your email to verify your account.',
      user: sanitizeUser(newUser.toObject())
    });
  } catch (error) {
    logger.error(`Registration error: ${(error as Error).message}`);
    res.status(500).json({ message: 'Registration failed. Please try again.' });
  }
};

/**
 * Handle user login
 */
export const login = async (req: Request, res: Response): Promise<void> => {
  passport.authenticate('local', { session: false }, (err: Error, user: IUser, info: any) => {
    if (err) {
      logger.error(`Login error: ${err.message}`);
      res.status(500).json({ message: 'Login failed due to server error' });
      return;
    }
    
    if (!user) {
      res.status(401).json({ message: info.message || 'Invalid credentials' });
      return;
    }
    
    // Check for suspicious login
    const isSuspicious = isSuspiciousLogin(
      user,
      req.ip!,
      req.headers['user-agent'] || 'unknown'
    );
    
    if (isSuspicious) {
      logAuthEvent('suspicious', user.id, {
        ip: req.ip,
        userAgent: req.headers['user-agent']
      });
      // You might want to implement additional security measures here
      // such as requiring email verification or CAPTCHA
    }
    
    // Update last login time
    user.lastLogin = new Date();
    user.save();
    
    // Generate access and refresh tokens
    const { token, expiresIn } = generateToken(user);
    const refreshToken = generateRefreshToken(user);
    
    // Log successful login
    logAuthEvent('login', user.id, {
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });
    
    res.json({
      message: 'Login successful',
      token,
      refreshToken: refreshToken.token,
      expiresIn,
      user: sanitizeUser(user.toObject())
    });
  })(req, res);
};

/**
 * Verify email with token
 */
export const verifyEmail = async (req: Request, res: Response): Promise<void> => {
  const { token } = req.params;
  
  try {
    // Find user with matching verification token
    const user = await User.findOne({
      verificationToken: token,
      verificationExpires: { $gt: new Date() } // Token must not be expired
    });
    
    if (!user) {
      logger.warn(`Invalid or expired verification token: ${token}`);
      res.status(400).json({ message: 'Invalid or expired verification token' });
      return;
    }
    
    // Update user verification status
    user.isEmailVerified = true;
    user.verificationToken = undefined;
    user.verificationExpires = undefined;
    
    await user.save();
    
    logAuthEvent('register', user.id, { verified: true });
    
    res.json({
      message: 'Email verification successful. You can now log in.'
    });
  } catch (error) {
    logger.error(`Email verification error: ${(error as Error).message}`);
    res.status(500).json({ message: 'Verification failed. Please try again.' });
  }
};

/**
 * Request password reset
 */
export const requestPasswordReset = async (req: Request, res: Response): Promise<void> => {
  const { email } = req.body;
  
  try {
    const user = await User.findOne({ email: email.toLowerCase() });
    
    // Always return success even if user not found (security best practice)
    if (!user) {
      logger.info(`Password reset requested for non-existent user: ${email}`);
      res.json({
        message: 'If your email is registered, you will receive password reset instructions'
      });
      return;
    }
    
    // Generate password reset token
    const resetToken = generatePasswordResetToken();
    const resetExpires = new Date();
    resetExpires.setHours(resetExpires.getHours() + 1); // Token valid for 1 hour
    
    // Update user with reset token
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = resetExpires;
    await user.save();
    
    logAuthEvent('passwordReset', user.id, { requested: true });
    
    // TODO: Send password reset email with token
    // This would typically involve an email service
    
    res.json({
      message: 'If your email is registered, you will receive password reset instructions'
    });
  } catch (error) {
    logger.error(`Password reset request error: ${(error as Error).message}`);
    res.status(500).json({ message: 'Password reset request failed. Please try again.' });
  }
};

/**
 * Reset password with token
 */
export const resetPassword = async (req: Request, res: Response): Promise<void> => {
  const { token, password } = req.body;
  
  try {
    // Find user with matching reset token
    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: new Date() } // Token must not be expired
    });
    
    if (!user) {
      logger.warn(`Invalid or expired password reset token: ${token}`);
      res.status(400).json({ message: 'Invalid or expired password reset token' });
      return;
    }
    
    // Update user password and clear reset token
    user.password = password;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    // Reset login attempts as well
    user.failedLoginAttempts = 0;
    user.lockUntil = undefined;
    
    await user.save();
    
    logAuthEvent('passwordReset', user.id, { completed: true });
    
    res.json({
      message: 'Password has been reset successfully. You can now log in with your new password.'
    });
  } catch (error) {
    logger.error(`Password reset error: ${(error as Error).message}`);
    res.status(500).json({ message: 'Password reset failed. Please try again.' });
  }
};

/**
 * Refresh access token using refresh token
 */
export const refreshAccessToken = async (req: Request, res: Response): Promise<void> => {
  const { refreshToken } = req.body;
  
  if (!refreshToken) {
    res.status(400).json({ message: 'Refresh token is required' });
    return;
  }
  
  try {
    // Verify the refresh token
    const decoded = require('jsonwebtoken').verify(
      refreshToken,
      process.env.JWT_SECRET || 'your-secret-key'
    );
    
    // Find the user
    const user = await User.findById(decoded.id);
    
    if (!user) {
      res.status(401).json({ message: 'Invalid refresh token' });
      return;
    }
    
    // Generate new access token
    const { token, expiresIn } = generateToken(user);
    
    res.json({
      token,
      expiresIn
    });
  } catch (error) {
    logger.error(`Token refresh error: ${(error as Error).message}`);
    res.status(401).json({ message: 'Invalid or expired refresh token' });
  }
};

/**
 * Get current user profile
 */
export const getCurrentUser = async (req: Request, res: Response): Promise<void> => {
  try {
    // User should be attached to request by auth middleware
    if (!req.user) {
      res.status(401).json({ message: 'Authentication required' });
      return;
    }
    
    // Return user data without sensitive fields
    res.json({
      user: sanitizeUser((req.user as IUser).toObject())
    });
  } catch (error) {
    logger.error(`Get current user error: ${(error as Error).message}`);
    res.status(500).json({ message: 'Failed to retrieve user profile' });
  }
};

/**
 * Update user profile
 */
export const updateProfile = async (req: Request, res: Response): Promise<void> => {
  try {
    // User should be attached to request by auth middleware
    if (!req.user) {
      res.status(401).json({ message: 'Authentication required' });
      return;
    }
    
    const user = req.user as IUser;
    const { firstName, lastName } = req.body;
    
    // Update user fields
    if (firstName) user.firstName = firstName;
    if (lastName) user.lastName = lastName;
    
    await user.save();
    
    res.json({
      message: 'Profile updated successfully',
      user: sanitizeUser(user.toObject())
    });
  } catch (error) {
    logger.error(`Update profile error: ${(error as Error).message}`);
    res.status(500).json({ message: 'Failed to update profile' });
  }
};

/**
 * Change password
 */
export const changePassword = async (req: Request, res: Response): Promise<void> => {
  try {
    // User should be attached to request by auth middleware
    if (!req.user) {
      res.status(401).json({ message: 'Authentication required' });
      return;
    }
    
    const user = req.user as IUser;
    const { currentPassword, newPassword } = req.body;
    
    // Verify current password
    const isMatch = await user.comparePassword(currentPassword);
    
    if (!isMatch) {
      res.status(400).json({ message: 'Current password is incorrect' });
      return;
    }
    
    // Update password
    user.password = newPassword;
    await user.save();
    
    logAuthEvent('passwordReset', user.id, { selfChange: true });
    
    res.json({
      message: 'Password changed successfully'
    });
  } catch (error) {
    logger.error(`Change password error: ${(error as Error).message}`);
    res.status(500).json({ message: 'Failed to change password' });
  }
};

/**
 * Logout user
 */
export const logout = async (req: Request, res: Response): Promise<void> => {
  try {
    // For JWT-based auth, client-side should remove the token
    // Here we log the logout action
    if (req.user) {
      logAuthEvent('logout', (req.user as IUser).id, {
        ip: req.ip,
        userAgent: req.headers['user-agent']
      });
    }
    
    res.json({
      message: 'Logged out successfully'
    });
  } catch (error) {
    logger.error(`Logout error: ${(error as Error).message}`);
    res.status(500).json({ message: 'Logout failed' });
  }
};