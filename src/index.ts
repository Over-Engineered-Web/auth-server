import { config } from 'dotenv';
import express from 'express';
import passport from 'passport';
import { Strategy } from 'passport-discord-auth';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { DbUser, db } from './db';
import { eq } from 'drizzle-orm';
import { userTable } from './schema';
import { setAuthCookies } from './createAuthTokens';
import { privateRoute, createHandler } from './trpc';

config({ path: '.env' });

const app = express();

app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    maxAge: 86400,
    credentials: true,
    origin: process.env.FRONTEND_URL!,
  })
);

// Initialize passport
app.use(passport.initialize());

app.use(passport.initialize() as any);

passport.use(
  new Strategy(
    {
      clientId: process.env.DISCORD_CLIENT_ID!,
      clientSecret: process.env.DISCORD_SECRET!,
      callbackUrl: `${process.env.API_URL}/auth/discord/callback`,
      scope: ['identify'],
    },

    async (_accessToken, _refreshToken, profile, done) => {
      try {
        // Find or create user based on Discord ID
        const discordId = profile._json.id as string;

        let user = await db.query.users.findFirst({
          where: eq(userTable.discordId, discordId),
        });

        if (!user) {
          [user] = await db
            .insert(userTable)
            .values({
              discordId,
            })
            .returning();
        }

        return done(null, user);
      } catch (error) {
        return done(error as Error);
      }
    }
  ) as any
);

app.get('/auth/discord', passport.authenticate('discord', { session: false }));
app.get(
  '/auth/discord/callback',
  passport.authenticate('discord', {
    session: false,
  }),
  (req, res) => {
    setAuthCookies(res, req.user as DbUser);
    res.redirect(process.env.FRONTEND_URL!);
  }
);

app.get("/doThings", privateRoute, createHandler)


app.listen(process.env.PORT || 4000, () => {
  console.log('Server started at http://localhost:4000');
});
