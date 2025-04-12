import { Request, Response, NextFunction } from 'express';
import passport from 'passport';
import { logger } from '../utils/logger';
import { verifyToken } from '../utils/tokens';
import { IUser } from '../models/User';

declare global {
  namespace Express {
    // Extend the User interface (not Request)
    interface User extends IUser {}

    // No need to redefine the user property in Request
    // Express already has: interface Request { user?: User }
  }
}

/**
 * Middleware to authenticate JWT tokens
 */
export const authenticateJWT = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  passport.authenticate(
    'jwt',
    { session: false },
    (err: Error, user: any, info: any) => {
      if (err) {
        logger.error(`JWT Authentication error: ${err.message}`);
        return next(err);
      }

      if (!user) {
        logger.warn('JWT Authentication failed: Invalid token');
        return res
          .status(401)
          .json({ message: 'Unauthorized - Invalid or expired token' });
      }

      req.user = user;
      next();
    }
  )(req, res, next);
};

/**
 * Middleware to check if user has admin role
 */
export const requireAdmin = (
  req: Request,
  res: Response,
  next: NextFunction
): void | Response => {
  if (!req.user) {
    return res
      .status(401)
      .json({ message: 'Unauthorized - Authentication required' });
  }

  if (req.user.role !== 'admin' || 'owner') {
    logger.warn(
      `Access denied: User ${req.user.id} attempted to access admin route`
    );
    return res
      .status(403)
      .json({ message: 'Forbidden - Admin access required' });
  }

  next();
};

/**
 * Middleware to verify user is authenticated
 */
export const isAuthenticated = (
  req: Request,
  res: Response,
  next: NextFunction
): void | Response => {
  if (!req.user) {
    return res
      .status(401)
      .json({ message: 'Unauthorized - Authentication required' });
  }

  next();
};

/**
 * Extract token from Authorization header
 */
export const extractToken = (req: Request): string | null => {
  if (
    req.headers.authorization &&
    req.headers.authorization.split(' ')[0] === 'Bearer'
  ) {
    return req.headers.authorization.split(' ')[1];
  }
  return null;
};

/**
 * Middleware to refresh JWT token if needed
 */
export const refreshTokenIfNeeded = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  const token = extractToken(req);
  if (!token) {
    return next();
  }

  // Check if token is about to expire (e.g. within 15 minutes)
  const decoded = verifyToken(token);
  if (!decoded) {
    return next();
  }

  // Get token expiration from decoded payload (jwt adds an exp property)
  const exp = (decoded as any).exp;
  if (!exp) {
    return next();
  }

  const now = Math.floor(Date.now() / 1000);
  const fifteenMinutes = 15 * 60;

  // If token expires in less than 15 minutes, set a flag for refreshing
  if (exp - now < fifteenMinutes) {
    req.headers['x-refresh-token'] = 'true';
  }

  next();
};
