import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import { userTable } from './schema';

export type DbUser = typeof userTable.$inferSelect;

const queryClient = postgres(process.env.DATABASE_URL!);

export const db = drizzle(queryClient, {
  schema: {
    users: userTable,
  },
});
