import { Client } from 'pg';
import sql from 'sql-template-tag';
import { env } from '../../config/env.ts';

/* Passwords are <username123> 
  ex. username: suhail, pass: suhail123
  etc...
*/
const INIT_QUERY = sql`
  CREATE TABLE IF NOT EXISTS jwt_users (
    id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(255) NOT NULL,
    refresh_token VARCHAR(255)
  );

  INSERT INTO jwt_users(username, password_hash, role) 
    VALUES
      ('suhail', '$2b$10$IlFZq96zBzwjPf637SbDcepKAgu5yntrrhRCgmz07kONT4H0xIGym', 'admin'), 
      ('taha', '$2b$10$Rc.5wnjflkb2X8XLdLm1NOigE5KoHGF2nt40I1/QpPyWE5HVW58H.', 'admin'),
      ('naser', '$2b$10$lFNLyxpV10gokc3GPXs11O0eEDsTvIlU6LcjgtDvBbvCzDxzHX7Dm', 'user');
`;

export async function init() {
  console.log('seeding...');

  const client = await new Client({
    connectionString: env.DATABASE_URL,
  }).connect();

  await client.query(INIT_QUERY);
  await client.end();

  console.log('done');
}

init();
