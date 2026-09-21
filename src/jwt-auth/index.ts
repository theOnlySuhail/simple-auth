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
import jwt from 'jsonwebtoken';

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

//* ----- TYPES -----

interface UserRow {
  username: string;
  password_hash: string;
  role: 'admin' | 'user';
  refresh_token: string;
}

interface User {
  username: string;
  role: 'admin' | 'user';
}

declare global {
  namespace Express {
    interface Request {
      user?: User;
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
  return res.send(
    html.replace('{{username}}', req.user!.username).replace('{{role}}', req.user!.role),
  );
});

app.get('/create', alreadyLoggedIn, async (req: Request, res: Response) => {
  const createAccountFilePath = path.join(import.meta.dirname, '../pages/create-account.html');
  const html = await fs.readFile(createAccountFilePath, 'utf8');
  return res.send(html);
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

  const role = 'user';

  // create a refresh token
  const refreshToken = jwt.sign({}, env.REFRESH_TOKEN_SECRET, { expiresIn: '1m' });

  // hash the plaintext password and add the user to db
  const passwordHash = await bcrypt.hash(password, 10);
  await db.query(
    sql`
      INSERT INTO jwt_users(username, password_hash, role, refresh_token)
      VALUES ($1, $2, $3, $4);
    `,
    [username, passwordHash, role, refreshToken],
  );

  // create an access token
  const payload = { username, role };

  const accessToken = jwt.sign(payload, env.ACCESS_TOKEN_SECRET, { expiresIn: '30s' });

  res.cookie('ACCESS_TOKEN', accessToken, {
    httpOnly: true,
    sameSite: 'strict',
    secure: env.NODE_ENV === 'production',
  });

  return res.redirect('/');
});

app.get('/login', alreadyLoggedIn, async (req: Request, res: Response) => {
  const createAccountFilePath = path.join(import.meta.dirname, '../pages/login.html');
  const html = await fs.readFile(createAccountFilePath, 'utf8');
  return res.send(html);
});

app.post('/login', async (req: Request<{}, LoginRequestBody>, res: Response) => {
  const { username, password } = req.body;

  // check if username exists
  const usernameResult = await db.query(sql`SELECT * FROM jwt_users WHERE username = $1`, [
    username,
  ]);
  if (!usernameResult.rowCount) {
    return res.status(401).json({ err: 'Invalide username or password.' });
  }

  // grab and validate the password
  const { password_hash: passwordHash } = usernameResult.rows[0] as UserRow;

  const isValidPassowrd = await bcrypt.compare(password, passwordHash);
  if (!isValidPassowrd) {
    return res.status(400).json({ err: 'Invalide username or password.' });
  }

  // grap the refresh_token
  const userResult = await db.query(
    sql`SELECT * FROM jwt_users
        WHERE username = $1
    `,
    [username],
  );

  const { role, refreshToken } = userResult.rows[0];
  try {
    if (!refreshToken) throw new Error('no refresh token');
    jwt.verify(refreshToken, env.REFRESH_TOKEN_SECRET);
  } catch (err: unknown) {
    // recreate the refresh token
    const newRefreshToken = jwt.sign({}, env.REFRESH_TOKEN_SECRET, { expiresIn: '1m' });

    await db.query(
      sql`
        UPDATE jwt_users
        SET refresh_token = $1
        WHERE username = $2
    `,
      [newRefreshToken, username],
    );
  }

  // Create a new access token
  const payload = {
    username: username,
    role: role,
  };

  const newAccessToken = jwt.sign(payload, env.ACCESS_TOKEN_SECRET, { expiresIn: '30s' });

  res.cookie('ACCESS_TOKEN', newAccessToken, {
    httpOnly: true,
    sameSite: 'strict',
    secure: env.NODE_ENV === 'production',
  });

  req.user = payload;

  return res.redirect('/');
});


//* ----- MIDDLEWARES -----

function alreadyLoggedIn(req: Request, res: Response, next: NextFunction) {
  if (req.cookies.ACCESS_TOKEN) {
    return res.redirect('/');
  }
  return next();
}

async function validSession(req: Request, res: Response, next: NextFunction) {
  const accessToken = req.cookies.ACCESS_TOKEN;

  if (!accessToken) return res.redirect('/login');

  try {
    const decoded = jwt.verify(accessToken, env.ACCESS_TOKEN_SECRET);
    // @ts-ignore
    req.user = { username: decoded.user, role: decoded.role };
    return next();
  } catch (err: unknown) {
    // clear cookie and redirect user if any error occues except TokenExpiredError
    if (!(err instanceof jwt.TokenExpiredError)) {
      res.clearCookie('ACCESS_TOKEN');
      return res.redirect('/login');
    }
  }

  // Now the access token has expired, so we need to grab the refresh_token
  // and check whether it's valid or not, if valid => create a new access token
  // if not => redirect user to /login

  const decoded = jwt.decode(accessToken) as User;

  // grap the refresh_token
  const result = await db.query(
    sql`SELECT refresh_token FROM jwt_users
        WHERE username = $1
    `,
    [decoded.username],
  );

  const refreshToken = result.rows[0]?.refresh_token;
  try {
    if (!refreshToken) throw new Error('no refresh token');
    jwt.verify(refreshToken, env.REFRESH_TOKEN_SECRET);
  } catch (err: unknown) {
    // null out the refresh token in db and redirect user to /login
    await db.query(
      sql`UPDATE jwt_users
        SET refresh_token = $1
        WHERE username = $2
    `,
      [null, decoded.username],
    );
    res.clearCookie('ACCESS_TOKEN');
    return res.redirect('/login');
  }

  // if valid, create a new access token
  const payload = {
    username: decoded.username,
    role: decoded.role,
  };

  const newAccessToken = jwt.sign(payload, env.ACCESS_TOKEN_SECRET, { expiresIn: '30s' });
  console.log(`ACCESS_TOKEN REFRESHED\nOld: ${accessToken}\nNew:${newAccessToken}`);

  res.cookie('ACCESS_TOKEN', newAccessToken, {
    httpOnly: true,
    sameSite: 'strict',
    secure: env.NODE_ENV === 'production',
  });

  req.user = payload;

  return next();
}

//* ----- HELPER FUNCTIONS -----

const isUsernameTaken = async (username: string): Promise<boolean> => {
  const result = await db.query(sql`SELECT username FROM jwt_users WHERE username = $1`, [
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
  console.log(`(JWT) Server running on port: ${env.PORT}`);
});
