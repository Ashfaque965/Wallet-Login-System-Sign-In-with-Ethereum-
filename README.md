# Wallet Login System (Sign-In with Ethereum)

### Web3 Authentication & Identity Projects ####

Full-stack SIWE authentication system using EIP-4361:

- React frontend
- Node.js/Express backend
- `ethers.js` wallet signing
- SIWE message verification
- JWT auth + refresh session management
- Role-based auth + admin dashboard

## Stack

- Frontend: React, React Router, Vite, ethers, siwe
- Backend: Node.js, Express, ethers, siwe, jsonwebtoken

## Quick Start

### 1) Backend

```bash
cd backend
cp .env.example .env
npm install
npm run dev
```

Backend default URL: `http://localhost:4000`

### 2) Frontend

```bash
cd frontend
npm install
npm run dev
```

Frontend default URL: `http://localhost:5173`

## Environment

Configure in `backend/.env`:

- `PORT=4000`
- `JWT_SECRET=replace-with-strong-secret`
- `FRONTEND_ORIGIN=http://localhost:5173`
- `SIWE_ALLOWED_DOMAINS=localhost:5173`
- `ADMIN_WALLETS=0xYourAdminWalletAddress`
- `ACCESS_TOKEN_TTL=15m`
- `REFRESH_TOKEN_TTL_HOURS=168`
- `NONCE_TTL_SECONDS=300`

## Auth Flow (EIP-4361)

1. Frontend connects wallet.
2. Frontend requests nonce from backend (`/auth/nonce`).
3. Frontend builds SIWE message and signs it with wallet.
4. Backend verifies SIWE signature and nonce.
5. Backend issues access JWT and refresh token.
6. Frontend uses access token for protected APIs and refreshes session via `/auth/refresh`.

## API Summary

- `POST /auth/nonce`
- `POST /auth/verify`
- `POST /auth/refresh`
- `POST /auth/logout`
- `POST /auth/logout-all`
- `GET /auth/me`
- `GET /auth/sessions`
- `DELETE /auth/sessions/:sessionId`
- `GET /admin/dashboard` (admin only)
- `POST /admin/roles` (admin only)
