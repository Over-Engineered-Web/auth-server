CREATE TABLE IF NOT EXISTS "users" (
	"id" uuid PRIMARY KEY DEFAULT uuid_generate_v4() NOT NULL,
	"discord_id" text NOT NULL,
	"refresh_token_version" integer
);
