import express from 'express';
import type { Request, Response } from 'express';
import bcrypt from 'bcrypt';
import { env } from '../config/env.ts';
import sql from 'sql-template-tag';
import * as db from './db/index.ts';
import fs from 'fs/promises';
import path from 'path';

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

//* ----- TYPES -----

interface LoginRequestBody {
  username: string;
  password: string;
}

interface CreateRequestBody extends LoginRequestBody {
  confirmPassword: string;
}

//* ----- ENDPOINTS -----

app.get('/create', async (req: Request, res: Response) => {
  const createAccountFilePath = path.join(import.meta.dirname, '../pages/create-account.html');
  const html = await fs.readFile(createAccountFilePath, 'utf8');
  res.send(html);
});

app.post('/create', async (req: Request<{}, CreateRequestBody>, res: Response) => {
  const { username, password, confirmPassword } = req.body;

  if (await isUsernameTaken(username)) {
    return res.status(400).json({ err: 'username is taken, try a different one.' });
  }

  if (password !== confirmPassword) {
    return res.status(400).json({ err: 'Passwords do not match.' });
  }

  const passwordHash = await bcrypt.hash(password, 10);

  // add the user to db
  await db.query(
    sql`
      INSERT INTO users(username, password_hash)
      VALUES ($1, $2);
    `,
    [username, passwordHash],
  );

  return res.send('User created successfully!');
});

//* ----- HELPER FUNCTIONS -----

const isUsernameTaken = async (username: string): Promise<boolean> => {
  const result = await db.query(sql`SELECT username FROM users WHERE username = $1`, [username]);
  return !!result.rowCount;
};

app.listen(env.PORT, (err) => {
  if (err) console.error(err);
  console.log(`(Sessions) Server running on port: ${env.PORT}}`);
});
