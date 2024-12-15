import { privateProcedure } from '../trpc';

export const doThingQuery = privateProcedure.query(async ({ ctx }) => {
  console.log('Current user ID is ', ctx.userId);
  return { ok: true };
});
