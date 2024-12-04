import { sql } from 'drizzle-orm';
import { pgTable, uuid, text, integer } from 'drizzle-orm/pg-core';

export const userTable = pgTable('users', {
  id: uuid('id')
    .primaryKey()
    .default(sql`uuid_generate_v4()`)
    .notNull(),

  googleId: text('google_id').notNull(),
  refreshToken: integer('refresh_token_version'),
});
