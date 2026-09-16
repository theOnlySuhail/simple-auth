import { Client } from 'pg';
import sql from 'sql-template-tag';

process.loadEnvFile();

const INIT_QUERY = sql`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    session_id VARCHAR(255)
  );

  INSERT INTO users (username, password_hash) 
    VALUES
      ('suhail', '$2b$10$IlFZq96zBzwjPf637SbDcepKAgu5yntrrhRCgmz07kONT4H0xIGym'),
      ('taha', '$2b$10$Rc.5wnjflkb2X8XLdLm1NOigE5KoHGF2nt40I1/QpPyWE5HVW58H.'),
      ('naser', '$2b$10$lFNLyxpV10gokc3GPXs11O0eEDsTvIlU6LcjgtDvBbvCzDxzHX7Dm');
`;

export async function init() {
  console.log('seeding...');

  const client = await new Client({
    connectionString: process.env.DATABASE_URL,
  }).connect();

  await client.query(INIT_QUERY);
  await client.end();

  console.log('done');
}


init();