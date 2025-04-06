import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import { logger } from './logger';

/**
 * Check if a password meets security requirements
 */
export const isStrongPassword = (password: string): boolean => {
  // Password must be at least 8 characters long
  if (password.length < 8) {
    return false;
  }
  
  // Password must contain at least one lowercase letter
  if (!/[a-z]/.test(password)) {
    return false;
  }
  
  // Password must contain at least one uppercase letter
  if (!/[A-Z]/.test(password)) {
    return false;
  }
  
  // Password must contain at least one number
  if (!/[0-9]/.test(password)) {
    return false;
  }
  
  // Password must contain at least one special character
  if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    return false;
  }
  
  return true;
};

/**
 * Generate a secure random string
 */
export const generateSecureToken = (length: number = 32): string => {
  return crypto.randomBytes(length).toString('hex');
};

/**
 * Sanitize user data for response
 */
export const sanitizeUser = (user: any): any => {
  const sanitized = { ...user };
  
  // Remove sensitive fields
  delete sanitized.password;
  delete sanitized.resetPasswordToken;
  delete sanitized.resetPasswordExpires;
  delete sanitized.verificationToken;
  delete sanitized.verificationExpires;
  delete sanitized.failedLoginAttempts;
  delete sanitized.lockUntil;
  
  return sanitized;
};

/**
 * Check if a login attempt is suspicious
 */
export const isSuspiciousLogin = (
  user: any,
  ip: string,
  userAgent: string
): boolean => {
  // Example suspicious activity checks:
  
  // 1. User is logging in from a new IP (would require storing IPs in user history)
  // 2. User is logging in from a new device (would require device fingerprinting)
  // 3. User is logging in from a different country (would require IP geolocation)
  // 4. User has multiple failed login attempts recently
  
  // For this example, we'll just check for multiple recent failed attempts
  if (user.failedLoginAttempts >= 3) {
    logger.warn(`Suspicious login: Multiple failed attempts for user ${user.id} from IP ${ip}`);
    return true;
  }
  
  return false;
};

/**
 * Hash sensitive data (e.g., for logging)
 */
export const hashData = (data: string): string => {
  return crypto.createHash('sha256').update(data).digest('hex');
};

/**
 * Generate CSRF token
 */
export const generateCSRFToken = (): string => {
  return crypto.randomBytes(32).toString('hex');
};

/**
 * Encrypt sensitive data
 */
export const encryptData = (data: string, key: string): string => {
  const algorithm = 'aes-256-cbc';
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(algorithm, Buffer.from(key, 'hex'), iv);
  
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  return `${iv.toString('hex')}:${encrypted}`;
};

/**
 * Decrypt sensitive data
 */
export const decryptData = (encrypted: string, key: string): string => {
  const [ivHex, encryptedData] = encrypted.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key, 'hex'), iv);
  
  let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  
  return decrypted;
}