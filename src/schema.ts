import { sql } from 'drizzle-orm';
import { pgTable, uuid, text, integer, boolean } from 'drizzle-orm/pg-core';

export const userTable = pgTable('users', {
  id: uuid('id')
    .primaryKey()
    .default(sql`uuid_generate_v4()`)
    .notNull(),

  discordId: text('discord_id').notNull(),
  refreshToken: integer('refresh_token_version'),

  // name: text("name"),
  // role: text("role", { enum: ["admin", "user"] }).$default(() => {
  //   return "user";
  // }),
  // verified: boolean("verified").$default(() => {
  //   return false;
  // }),
  // email: text("name").notNull().unique(),
  // subscribed: boolean("verified").$default(() => {
  //   return false;
  // }),
  // image: text("image"),
});
