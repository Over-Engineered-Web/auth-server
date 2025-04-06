import rateLimit from 'express-rate-limit';
import { logger } from '../utils/logger';

/**
 * Rate limiter middleware for login attempts
 * Limits to 5 requests per 15 minutes from the same IP
 */
export const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn(`Rate limit exceeded for IP: ${req.ip}`);
    res.status(429).json({
      message: 'Too many login attempts, please try again later'
    });
  }
});

/**
 * Rate limiter middleware for registration
 * Limits to 3 requests per 60 minutes from the same IP
 */
export const registrationLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 60 minutes
  max: 3, // 3 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn(`Registration rate limit exceeded for IP: ${req.ip}`);
    res.status(429).json({
      message: 'Too many registration attempts, please try again later'
    });
  }
});

/**
 * Rate limiter middleware for password reset
 * Limits to 3 requests per 60 minutes from the same IP
 */
export const passwordResetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 60 minutes
  max: 3, // 3 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn(`Password reset rate limit exceeded for IP: ${req.ip}`);
    res.status(429).json({
      message: 'Too many password reset attempts, please try again later'
    });
  }
});

/**
 * General API rate limiter
 * Limits to 100 requests per 15 minutes from the same IP
 */
export const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn(`API rate limit exceeded for IP: ${req.ip}`);
    res.status(429).json({
      message: 'Too many requests, please try again later'
    });
  }
});