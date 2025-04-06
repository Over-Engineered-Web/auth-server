import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { IUser } from '../models/User';

// Environment variables should be loaded from a .env file using dotenv
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1d';
const JWT_REFRESH_EXPIRES_IN = process.env.JWT_REFRESH_EXPIRES_IN || '7d';

interface TokenPayload {
  id: string;
  role: string;
}

interface TokenResponse {
  token: string;
  expiresIn: string;
}

/**
 * Generate a JSON Web Token for authenticated user
 */
export const generateToken = (user: IUser): TokenResponse => {
  const payload: TokenPayload = {
    id: user.id,
    role: user.role,
  };

  const token = jwt.sign(payload, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN
  });

  return {
    token,
    expiresIn: JWT_EXPIRES_IN
  };
};

/**
 * Generate a refresh token for extended sessions
 */
export const generateRefreshToken = (user: IUser): TokenResponse => {
  const payload: TokenPayload = {
    id: user.id,
    role: user.role,
  };

  const token = jwt.sign(payload, JWT_SECRET, {
    expiresIn: JWT_REFRESH_EXPIRES_IN
  });

  return {
    token,
    expiresIn: JWT_REFRESH_EXPIRES_IN
  };
};

/**
 * Verify token and return decoded payload
 */
export const verifyToken = (token: string): TokenPayload | null => {
  try {
    const decoded = jwt.verify(token, JWT_SECRET) as TokenPayload;
    return decoded;
  } catch (error) {
    return null;
  }
};

/**
 * Generate email verification token
 */
export const generateVerificationToken = (): string => {
  return uuidv4();
};

/**
 * Generate password reset token
 */
export const generatePasswordResetToken = (): string => {
  return uuidv4();
};