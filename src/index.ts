import { config } from 'dotenv';
import Express from 'express';
import passport from 'passport';
import { Strategy } from 'passport-discord-auth';
import { DbUser, db } from './db';
import { eq } from 'drizzle-orm';
import { userTable } from './schema';
import { sendAuthCookies } from './createAuthTokens';
import { addTrpc } from './appRouter';

config({ path: '.env' });

async function main() {
  const app = Express();


  addTrpc(app);

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
        // 1. grab id
        const discordId = profile._json.id as string;

        // 2. db lookup
        let user = await db.query.users.findFirst({
          where: eq(userTable.discordId, discordId),
        });

        // 3. create user if not exists
        if (!user) {
          [user] = await db
            .insert(userTable)
            .values({
              discordId,
            })
            .returning();
        }

        // 4. return user
        done(null, user);
      }
    ) as any
  );

  app.get(
    '/auth/discord',
    passport.authenticate('discord', { session: false })
  );
  app.get(
    '/auth/discord/callback',
    passport.authenticate('discord', {
      session: false,
    }),
    (req, res) => {
      sendAuthCookies(res, req.user as DbUser);
      res.redirect(process.env.FRONTEND_URL!);
    }
  );

  app.listen(process.env.PORT || 4000, () => {
    console.log('Server started at http://localhost:4000');
  });
}

main();
