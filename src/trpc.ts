// src/middleware/auth.ts
import { Request, Response, NextFunction, RequestHandler } from 'express';
import { verifyAuthTokens, setAuthCookies } from './createAuthTokens';
import { DbUser } from './db';

// Middleware to handle public routes
export const publicRoute = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  next();
};

interface AuthRequest extends Request {
  userId: string;
  user?: DbUser
}

// Middleware to handle private routes
export const privateRoute = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  try {
    if (!req.cookies.id && !req.cookies.rid) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { id, rid } = req.cookies;

    const { userId, user } = await verifyAuthTokens(id, rid);

    // Set userId on request
    req.userId = userId;

    // If we got back a user, set new cookies and attach user to request
    if (user) {
      setAuthCookies(res, user);
      req.user = user;
    }

    next();
  } catch (error) {
    res.status(401).json({ error: 'Unauthorized' });
  }
};

// Helper for creating route handlers with automatic error handling
export type RouteHandler = (
  req: Request,
  res: Response,
  next: NextFunction
) => Promise<void> | void;

export const createHandler = (
  handler: (
    req: Request,
    res: Response
  ) => Promise<void | Response> | void | Response
): RequestHandler => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      await handler(req, res);
    } catch (error) {
      next(error);
    }
  };
};
// Error handling middleware
export const errorHandler = (
  error: Error,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  console.error('Error:', error);
  res.status(500).json({ error: 'Internal server error' });
};
