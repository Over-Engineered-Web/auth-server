import * as trpcExpress from '@trpc/server/adapters/express';
import { doThingQuery } from './modules/doThing';
import { meQuery } from './modules/me';
import { createContext, t } from './trpc';
import { Express } from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';

const appRouter = t.router({ doThing: doThingQuery, me: meQuery });

export function addTrpc(app: Express) {
  app.use(
    '/trpc',
    cors({
      maxAge: 86400,
      credentials: true,
      origin: process.env.FRONTEND_URL!,
    }),

    cookieParser(),
    trpcExpress.createExpressMiddleware({
      router: appRouter,
      createContext,
    })
  );
}

export type AppRouter = typeof appRouter;
