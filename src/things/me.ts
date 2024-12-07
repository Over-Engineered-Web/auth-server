import { db, DbUser } from '../db';
import { publicProcedure } from '../trpc';
import { userTable } from '../schema';
import { eq } from 'drizzle-orm';
import { checkTokens } from '../createAuthTokens';

export const meQuery = publicProcedure.query(async ({ ctx }) => {
  const { id, rid } = ctx.req.cookies;
  let user: DbUser | null | undefined = null;

  try {
    const { userId, user: maybeUser } = await checkTokens(id, rid);
    if (maybeUser) {
      user = maybeUser;
    } else {
      user = await db.query.users.findFirst({
        where: eq(userTable.id, userId),
      });
    }

    return { user };
  } catch (e) {
    return { user: null };
  }
});
