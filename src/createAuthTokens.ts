// src/auth/tokens.ts
import { Response } from 'express';
import jwt from 'jsonwebtoken';
import { db, DbUser } from './db';
import { userTable } from './schema';
import { eq } from 'drizzle-orm';

interface RefreshToken {
  userId: string;
  refreshTokenVersion?: number;
}

interface AccessToken {
  userId: string;
}

const cookieOptions = {
  httpOnly: true,
  sameSite: 'lax' as const,
  path: '/',
  domain: '',
  maxAge: 1000 * 60 * 60 * 24 * 365 * 10, // 10 years
};

export function createAuthTokens(user: DbUser): {
  refreshToken: string;
  accessToken: string;
} {
  const refreshToken = jwt.sign(
    {
      userId: user.id,
      refreshTokenVersion: user.refreshToken,
    },
    process.env.REFRESH_TOKEN_SECRET!,
    { expiresIn: '30d' }
  );

  const accessToken = jwt.sign(
    { userId: user.id },
    process.env.ACCESS_TOKEN_SECRET!,
    { expiresIn: '15min' }
  );

  return { refreshToken, accessToken };
}

export function setAuthCookies(res: Response, user: DbUser): void {
  const { refreshToken, accessToken } = createAuthTokens(user);
  res.cookie('id', accessToken, cookieOptions);
  res.cookie('rid', refreshToken, cookieOptions);
}

export async function verifyAuthTokens(
  accessToken: string,
  refreshToken: string
) {
  // First try to verify access token
  try {
    const data = jwt.verify(
      accessToken,
      process.env.ACCESS_TOKEN_SECRET!
    ) as AccessToken;

    return {
      userId: data.userId,
    };
  } catch {
    // Access token invalid, try refresh token
  }

  // No refresh token provided
  if (!refreshToken) {
    throw new Error('Unauthorized');
  }

  // Verify refresh token
  let refreshTokenData: RefreshToken;
  try {
    refreshTokenData = jwt.verify(
      refreshToken,
      process.env.REFRESH_TOKEN_SECRET!
    ) as RefreshToken;
  } catch {
    throw new Error('Unauthorized');
  }

  // Check if user exists and token version matches
  const user = await db.query.users.findFirst({
    where: eq(userTable.id, refreshTokenData.userId),
  });

  if (!user || user.refreshToken !== refreshTokenData.refreshTokenVersion) {
    throw new Error('Unauthorized');
  }

  return { userId: refreshTokenData.userId, user };
}

// Middleware to check authentication
export function requireAuth(requireUser: boolean = false) {
  return async ({ req, res, next }: any) => {
    try {
      const accessToken = req.cookies.id;
      const refreshToken = req.cookies.rid;

      if (!accessToken && !refreshToken) {
        throw new Error('Unauthorized');
      }

      const result = await verifyAuthTokens(accessToken, refreshToken);

      // Add user info to request
      req.userId = result.userId;
      if (result.user) {
        req.user = result.user;
        // Refresh the auth cookies
        setAuthCookies(res, result.user);
      } else if (requireUser) {
        throw new Error('User required');
      }

      next();
    } catch (err) {
      res.status(401).json({ error: 'Unauthorized' });
    }
  };
}
