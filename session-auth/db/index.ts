import { Pool } from 'pg';
import { env } from '../../config/env.ts';
import { type Sql } from 'sql-template-tag';

const pool = new Pool({
  host: 'localhost',
  user: 'suhail',
  database: 'users',
  password: env.DATABASE_PASSWORD,
  port: 5432,
});

export const query = (text: Sql, params: unknown[]) => {
  try {
    return pool.query(text, params);
  } catch (err) {
    console.error('Database query error:', err);
    throw err;
  }
};
