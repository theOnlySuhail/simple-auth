import express from 'express';
import type { Request, Response } from 'express';
import bcrypt from 'bcrypt';
import { env } from '../config/env.ts';
import sql from 'sql-template-tag';
import * as db from './db/index.ts';
import fs from 'fs/promises';
import path from 'path';
import crypto from 'crypto';
import cookieParser from 'cookie-parser';

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

//* ----- TYPES -----

interface LoginRequestBody {
  username: string;
  password: string;
}

interface CreateRequestBody extends LoginRequestBody {
  confirmPassword: string;
}

//* ----- ENDPOINTS -----

app.get('/{home}', async (req: Request, res: Response) => {
  const sessionId = req.cookies.SESSION_ID;

  if (!sessionId) {
    return res.redirect('/login');
  }

  const result = await db.query(sql`SELECT username FROM users WHERE session_id = $1`, [sessionId]);
  if (!result.rowCount) {
    res.clearCookie('SESSION_ID');
    return res.redirect('/login');
  }

  const homeFilePath = path.join(import.meta.dirname, '../pages/home.html');
  const html = await fs.readFile(homeFilePath, 'utf8');
  return res.send(html.replace('{{username}}', result.rows[0].username));
});

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

app.get('/login', async (req: Request, res: Response) => {
  const createAccountFilePath = path.join(import.meta.dirname, '../pages/login.html');
  const html = await fs.readFile(createAccountFilePath, 'utf8');
  res.send(html);
});

app.post('/login', async (req: Request<{}, LoginRequestBody>, res: Response) => {
  const { username, password } = req.body;

  const result = await db.query(sql`SELECT * FROM users WHERE username = $1`, [username]);
  if (!result.rowCount) {
    return res.status(401).json({ err: 'Invalide username or password.' });
  }
  const passwordHash = result.rows[0].password_hash;

  const isValidPassowrd = await bcrypt.compare(password, passwordHash);
  if (!isValidPassowrd) {
    return res.status(400).json({ err: 'Invalide username or password.' });
  }

  const sessionId = crypto.randomBytes(64).toString('hex');

  // add the user to db
  await db.query(
    sql`
      UPDATE users
      SET session_id = $1
      WHERE username = $2
    `,
    [sessionId, username],
  );

  const cookie = `SESSION_ID=${sessionId}; httponly; secure; samesite=strict`;
  res.setHeader('set-cookie', cookie);

  return res.redirect('/');
});

//* ----- HELPER FUNCTIONS -----

const isUsernameTaken = async (username: string): Promise<boolean> => {
  const result = await db.query(sql`SELECT username FROM users WHERE username = $1`, [username]);
  return !!result.rowCount;
};

app.listen(env.PORT, (err) => {
  if (err) console.error(err);
  console.log(`(Sessions) Server running on port: ${env.PORT}`);
});
