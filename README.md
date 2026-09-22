# Authentication practice

This project is a small authentication exercise for EYouth Academy. It shows two ways to authenticate users in an Express application:

- `session-auth` stores session IDs in PostgreSQL and sends the ID in an HTTP-only cookie.
- `jwt-auth` uses JSON Web Tokens for authentication.

<div style="border: 1px solid #d1242f; border-left: 5px solid #d1242f; padding: 12px; color: #d1242f;">
  <strong>Important:</strong> This project is for learning. It is not ready for production use.
</div>

## Setup

From the `src` directory, install the dependencies:

```bash
pnpm install
```

Create a `.env` file in `src` with these values:

```env
NODE_ENV=development
PORT=3000
DATABASE_URL=postgresql://user:password@localhost:5432/auth
DATABASE_PASSWORD=password
ACCESS_TOKEN_SECRET=replace-me
REFRESH_TOKEN_SECRET=replace-me-too
```

Set up PostgreSQL with the tables used by the auth example, then start one implementation:

```bash
pnpm session
```

Or:

```bash
pnpm jwt
```

Both commands use `tsx watch`, so the server restarts when the TypeScript files change.

## Project layout

- `session-auth/` contains the session-based implementation.
- `jwt-auth/` contains the JWT-based implementation.
- `pages/` contains the HTML pages used by the examples.
- `config/env.ts` loads and validates environment variables.

The goal is to compare how each approach logs users in, keeps them authenticated, and logs them out.