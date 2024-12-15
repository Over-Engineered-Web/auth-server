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
// import { Env } from '@/utils/env'
// import { drizzle } from 'drizzle-orm/postgres-js'
// import { migrate } from 'drizzle-orm/postgres-js/migrator'
// import postgres from 'postgres'

// const migrationClient = postgres(Env.DATABASE_URL as string, { max: 1 })
// const db = drizzle(migrationClient) // this line fixed the issue

// async function startMigration() {
//     await migrate(db, { migrationsFolder: 'src/database/migrations' })
//     await migrationClient.end()
// }

// startMigration()