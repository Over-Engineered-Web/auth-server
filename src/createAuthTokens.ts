import { db, DbUser } from './db';
import * as jwt from 'jsonwebtoken';
import { Response } from 'express';
import { TRPCError } from '@trpc/server';
import { userTable } from './schema';
import { eq } from 'drizzle-orm';

export type RefreshToken = {
  userId: string;
  refreshTokenVersion?: number;
};

export type AccessToken = {
  userId: string;
};

const createAuthToken = (
  user: DbUser
): { refreshToken: string; accessToken: string } => {
  const refreshToken = jwt.sign(
    { userId: user.id, refreshToken: user.refreshToken },
    process.env.REFRESH_TOKEN_SECRET!,
    {
      expiresIn: '30d',
    }
  );

  const accessToken = jwt.sign(
    { userId: user.id },
    process.env.ACCESS_TOKEN_SECRET!,
    {
      expiresIn: '15min',
    }
  );

  return { refreshToken, accessToken };
};

// TODO cookies

const cookieOpts = {
  httpOnly: true,
  sameSite: 'lax',
  path: '/',
  domain: '',
  maxAge: 1000 * 60 * 60 * 24 * 365 * 10,
} as const;

export const sendAuthCookies = (res: Response, user: DbUser) => {
  const { refreshToken, accessToken } = createAuthToken(user);
  res.cookie('id', accessToken, cookieOpts);
  res.cookie('rid', refreshToken, cookieOpts);
};

export const checkTokens = async (access: string, refresh: string) => {
  try {
    const data = <AccessToken>(
      jwt.verify(access, process.env.ACCESS_TOKEN_SECRET!)
    );

    return {
      userId: data.userId,
    };
  } catch {}

  if (!refresh) {
    throw new TRPCError({ code: 'UNAUTHORIZED' });
  }

  let data;
  try {
    // assign a token from user to variable
    data = <RefreshToken>jwt.verify(refresh, process.env.REFRESH_TOKEN_SECRET!);
  } catch {
    throw new TRPCError({ code: 'UNAUTHORIZED' });
  }

  // take a user with id 
  const user = await db.query.users.findFirst({
    where: eq(userTable.id, data.userId),
  });

  if (!user || user.refreshToken !== data.refreshTokenVersion) {
    throw new TRPCError({ code: 'UNAUTHORIZED' });
  }

  // after all checks return user
  return { userId: data.userId, user };
};
