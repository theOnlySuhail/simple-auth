import express from 'express';
import type { Request, Response, NextFunction } from 'express';
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

interface UserRow {
  username: string;
  password_hash: string;
  session_id: string;
  expires_at: Date;
}

declare global {
  namespace Express {
    interface Request {
      username?: string;
    }
  }
}

interface LoginRequestBody {
  username: string;
  password: string;
}

interface CreateRequestBody extends LoginRequestBody {
  confirmPassword: string;
}

//* ----- ENDPOINTS -----

app.get('/', validSession, async (req: Request, res: Response) => {
  const homeFilePath = path.join(import.meta.dirname, '../pages/home.html');
  const html = await fs.readFile(homeFilePath, 'utf8');
  return res.send(html.replace('{{username}}', req.username!));
});

app.get('/create', alreadyLoggedIn, async (req: Request, res: Response) => {
  const createAccountFilePath = path.join(import.meta.dirname, '../pages/create-account.html');
  const html = await fs.readFile(createAccountFilePath, 'utf8');
  res.send(html);
});

app.post('/create', async (req: Request<{}, CreateRequestBody>, res: Response) => {
  const { password, confirmPassword } = req.body;
  const username = escapeHtml(req.body.username);

  // validate username
  if (!/^[a-zA-Z0-9_]{3,30}$/.test(username)) {
    return res.status(400).json({ err: 'Invalid username.' });
  }

  if (await isUsernameTaken(username)) {
    return res.status(400).json({ err: 'username is taken, try a different one.' });
  }

  // validate password
  if (password !== confirmPassword) {
    return res.status(400).json({ err: 'Passwords do not match.' });
  }

  if (password.length < 4 || password.length > 30) {
    return res.status(400).json({ err: 'Password length must be 4 to 30 characters long' });
  }

  // hass the plaintext password and add user to db
  const passwordHash = await bcrypt.hash(password, 10);
  await db.query(
    sql`
      INSERT INTO sessions_users(username, password_hash)
      VALUES ($1, $2);
    `,
    [username, passwordHash],
  );

  return res.send('User created successfully!');
});

app.get('/login', alreadyLoggedIn, async (req: Request, res: Response) => {
  const createAccountFilePath = path.join(import.meta.dirname, '../pages/login.html');
  const html = await fs.readFile(createAccountFilePath, 'utf8');
  res.send(html);
});

app.post('/login', async (req: Request<{}, LoginRequestBody>, res: Response) => {
  const { username, password } = req.body;

  // check if username exists
  const result = await db.query(sql`SELECT * FROM sessions_users WHERE username = $1`, [username]);
  if (!result.rowCount) {
    return res.status(401).json({ err: 'Invalide username or password.' });
  }

  // grab and validate the password
  const { password_hash: passwordHash } = result.rows[0] as UserRow;

  const isValidPassowrd = await bcrypt.compare(password, passwordHash);
  if (!isValidPassowrd) {
    return res.status(400).json({ err: 'Invalide username or password.' });
  }

  // create a sessiond id (with expiration date) and store it in the db
  const sessionId = crypto.randomBytes(64).toString('hex');
  const expiresAt = new Date(Date.now() + 30000); // expires in 30 seconds

  await db.query(
    sql`
      UPDATE sessions_users
      SET session_id = $1,
          expires_at = $2
      WHERE username = $3
    `,
    [sessionId, expiresAt, username],
  );

  // set a cookie with the sessions id
  res.cookie('SESSION_ID', sessionId, {
    httpOnly: true,
    secure: env.NODE_ENV === 'production',
    sameSite: 'strict',
  });

  return res.redirect('/');
});

app.post('/logout', validSession, async (req: Request, res: Response) => {
  // null out the session_id and expiration date
  await db.query(
    sql`UPDATE sessions_users
        SET session_id = $1,
            expires_at = $2
        WHERE username = $3
            `,
    [null, null, req.username],
  );

  // delete SESSION_ID cookie
  res.clearCookie('SESSION_ID');

  return res.redirect('/');
});

//* ----- MIDDLEWARES -----

function alreadyLoggedIn(req: Request, res: Response, next: NextFunction) {
  if (req.cookies.SESSION_ID) {
    res.redirect('/');
  }
  return next();
}

async function validSession(req: Request, res: Response, next: NextFunction) {
  const sessionId = req.cookies.SESSION_ID;

  const result = await db.query(sql`SELECT * FROM sessions_users WHERE session_id = $1`, [
    sessionId,
  ]);

  if (!result.rowCount) {
    return res.redirect('/login');
  }

  const { username, expires_at: expiresAt } = result.rows[0] as UserRow;

  if (expiresAt <= new Date(Date.now())) {
    await db.query(
      sql`
        UPDATE sessions_users 
          SET session_id = $1, 
              expires_at = $2 
          WHERE username = $3
      `,
      [null, null, username],
    );

    res.clearCookie('SESSION_ID');
    return res.redirect('/login');
  }

  req.username = username;
  return next();
}

//* ----- HELPER FUNCTIONS -----

const isUsernameTaken = async (username: string): Promise<boolean> => {
  const result = await db.query(sql`SELECT username FROM sessions_users WHERE username = $1`, [
    username,
  ]);
  return !!result.rowCount;
};

const escapeHtml = (value: string): string =>
  value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');

// @ts-ignore
app.listen(env.PORT, (err) => {
  if (err) console.error(err);
  console.log(`(Sessions) Server running on port: ${env.PORT}`);
});
