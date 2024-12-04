import { initTRPC, TRPCError } from '@trpc/server';
import * as trpcExpress from '@trpc/server/adapters/express';
import { checkTokens, sendAuthCookies } from './createAuthTokens';

type Context = Awaited<ReturnType<typeof createContext>>;

export const createContext = ({
  req,
  res,
}: trpcExpress.CreateExpressContextOptions) => ({ req, res, userId: '' });

export const t = initTRPC.context<Context>().create();
export const publicProcedure = t.procedure;
export const privateProcedure = t.procedure.use(async req => {
  const { ctx } = req;
  if (!ctx.req.cookies.id && !ctx.req.cookies.rid) {
    throw new TRPCError({ code: 'UNAUTHORIZED' });
  }

  const { id, rid } = ctx.req.cookies;

  const { userId, user } = await checkTokens(id, rid);

  ctx.userId = userId;

  if (user) {
    sendAuthCookies(ctx.res, user);
    ctx.maybeUser = user;
  }

  return req.next(req);
});
