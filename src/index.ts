import path from "path";
import Express from "express"
import { migrate } from "drizzle-orm/postgres-js/migrator";
import { db, DbUser } from "./db";
import passport from "passport";
import { addTrpc } from "./appRouter";
import { userTable } from "./schema";
import { eq } from "drizzle-orm";
import { sendAuthCookies } from "./createAuthTokens";

const { Strategy: GoogleStrategy } = require('passport-google-oauth20');

async function main() {
  await migrate(db, {migrationsFolder: path.join(__dirname, "../drizzle")})

  const app = Express()

  addTrpc(app)

  app.use(passport.initialize())

  passport.use(
    new GoogleStrategy (
      {clientId: process.env.GOOGLE_CLIENT_ID!,
        clientSecret: process.env.GOOGLE_SECRET!,
        callbackUrl: `${process.env.NEXT_PUBLIC_API_URL}/auth/google/callback`,
        scope: ["identify"]
      },

      async (_accessToken: any, _refreshToken: any, profile: { _json: { id: string; }; }, done: (arg0: null, arg1: { id: string; googleId: string; refreshToken: number | null; }) => void) => {
        // scrap id from received object
        const googleId = profile._json.id as string 
      
        let user = await db.query.users.findFirst({where: eq(userTable.googleId, googleId)})
      

        if (!user) {
          [user] = await db.insert(userTable).values({googleId: googleId}).returning()
        }
        done(null, user)
      }
    )
  )

  app.get("/auth/google", passport.authenticate("google", {session: false}))

  app.get("/auth/google/callback", passport.authenticate("google", {session: false,}), (req, res) => {
    sendAuthCookies(res, req.user as DbUser);
    res.redirect(process.env.FRONTEND_URL!)
  })

  app.listen(process.env.PORT, () => {
    console.log("server is listening at http://localhost:4000")
  })
}

main()