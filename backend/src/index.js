import crypto from 'node:crypto';
import dotenv from 'dotenv';
import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import { SiweMessage, generateNonce } from 'siwe';
import { isAddress, getAddress } from 'ethers';
import { v4 as uuidv4 } from 'uuid';

dotenv.config();

const app = express();

const config = {
  port: Number(process.env.PORT || 4000),
  jwtSecret: process.env.JWT_SECRET || 'dev-secret-change-me',
  frontendOrigin: process.env.FRONTEND_ORIGIN || 'http://localhost:5173',
  allowedDomains: (process.env.SIWE_ALLOWED_DOMAINS || 'localhost:5173')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean),
  adminWallets: new Set(
    (process.env.ADMIN_WALLETS || '')
      .split(',')
      .map((address) => address.trim().toLowerCase())
      .filter(Boolean)
  ),
  accessTokenTtl: process.env.ACCESS_TOKEN_TTL || '15m',
  refreshTokenTtlHours: Number(process.env.REFRESH_TOKEN_TTL_HOURS || 168),
  nonceTtlSeconds: Number(process.env.NONCE_TTL_SECONDS || 300)
};

app.use(
  cors({
    origin: config.frontendOrigin,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
  })
);
app.use(express.json());

const nonceStore = new Map();
const sessionsById = new Map();
const refreshTokenToSessionId = new Map();
const rolesByAddress = new Map();

function normalizeAddress(address) {
  return getAddress(address).toLowerCase();
}

function getRoleForAddress(address) {
  const normalized = normalizeAddress(address);
  if (rolesByAddress.has(normalized)) {
    return rolesByAddress.get(normalized);
  }
  if (config.adminWallets.has(normalized)) {
    return 'admin';
  }
  return 'user';
}

function issueAccessToken(session) {
  return jwt.sign(
    {
      sub: session.address,
      sid: session.id,
      role: session.role
    },
    config.jwtSecret,
    { expiresIn: config.accessTokenTtl }
  );
}

function buildSessionResponse(session) {
  const accessToken = issueAccessToken(session);
  return {
    accessToken,
    refreshToken: session.refreshToken,
    user: {
      address: session.address,
      role: session.role
    },
    session: {
      id: session.id,
      createdAt: session.createdAt,
      expiresAt: session.expiresAt,
      lastSeenAt: session.lastSeenAt
    }
  };
}

function upsertSession(address) {
  const now = Date.now();
  const refreshToken = crypto.randomBytes(48).toString('hex');
  const session = {
    id: uuidv4(),
    address: normalizeAddress(address),
    role: getRoleForAddress(address),
    refreshToken,
    createdAt: new Date(now).toISOString(),
    lastSeenAt: new Date(now).toISOString(),
    expiresAt: new Date(now + config.refreshTokenTtlHours * 60 * 60 * 1000).toISOString()
  };
  sessionsById.set(session.id, session);
  refreshTokenToSessionId.set(refreshToken, session.id);
  return session;
}

function rotateRefreshToken(session) {
  refreshTokenToSessionId.delete(session.refreshToken);
  session.refreshToken = crypto.randomBytes(48).toString('hex');
  session.lastSeenAt = new Date().toISOString();
  refreshTokenToSessionId.set(session.refreshToken, session.id);
  return session;
}

function removeSession(session) {
  refreshTokenToSessionId.delete(session.refreshToken);
  sessionsById.delete(session.id);
}

function getBearerToken(req) {
  const authHeader = req.headers.authorization || '';
  if (!authHeader.startsWith('Bearer ')) {
    return null;
  }
  return authHeader.slice('Bearer '.length);
}

function authenticate(req, res, next) {
  const token = getBearerToken(req);
  if (!token) {
    return res.status(401).json({ error: 'Missing bearer token' });
  }
  try {
    const payload = jwt.verify(token, config.jwtSecret);
    const session = sessionsById.get(payload.sid);
    if (!session) {
      return res.status(401).json({ error: 'Session is no longer active' });
    }
    if (new Date(session.expiresAt).getTime() < Date.now()) {
      removeSession(session);
      return res.status(401).json({ error: 'Session expired' });
    }

    session.lastSeenAt = new Date().toISOString();
    req.auth = {
      address: payload.sub,
      role: session.role,
      sessionId: payload.sid
    };
    return next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function requireRole(role) {
  return function roleMiddleware(req, res, next) {
    if (!req.auth || req.auth.role !== role) {
      return res.status(403).json({ error: 'Insufficient role' });
    }
    return next();
  };
}

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'siwe-backend' });
});

app.post('/auth/nonce', (req, res) => {
  const { address } = req.body || {};
  if (!address || !isAddress(address)) {
    return res.status(400).json({ error: 'A valid wallet address is required' });
  }

  const nonce = generateNonce();
  const normalizedAddress = normalizeAddress(address);
  nonceStore.set(normalizedAddress, {
    nonce,
    expiresAt: Date.now() + config.nonceTtlSeconds * 1000
  });

  return res.json({ nonce, expiresInSeconds: config.nonceTtlSeconds });
});

app.post('/auth/verify', async (req, res) => {
  const { message, signature } = req.body || {};
  if (!message || !signature) {
    return res.status(400).json({ error: 'Message and signature are required' });
  }

  try {
    const siwe = new SiweMessage(message);
    const normalizedAddress = normalizeAddress(siwe.address);
    const nonceRecord = nonceStore.get(normalizedAddress);

    if (!nonceRecord) {
      return res.status(400).json({ error: 'Nonce not found. Request a new nonce.' });
    }
    if (nonceRecord.expiresAt < Date.now()) {
      nonceStore.delete(normalizedAddress);
      return res.status(400).json({ error: 'Nonce expired. Request a new nonce.' });
    }
    if (!config.allowedDomains.includes(siwe.domain)) {
      return res.status(400).json({ error: 'SIWE domain is not allowed' });
    }

    await siwe.verify({
      signature,
      nonce: nonceRecord.nonce
    });

    nonceStore.delete(normalizedAddress);
    const session = upsertSession(normalizedAddress);
    return res.json(buildSessionResponse(session));
  } catch {
    return res.status(401).json({ error: 'SIWE verification failed' });
  }
});

app.post('/auth/refresh', (req, res) => {
  const { refreshToken } = req.body || {};
  if (!refreshToken) {
    return res.status(400).json({ error: 'refreshToken is required' });
  }
  const sessionId = refreshTokenToSessionId.get(refreshToken);
  if (!sessionId) {
    return res.status(401).json({ error: 'Invalid refresh token' });
  }
  const session = sessionsById.get(sessionId);
  if (!session) {
    refreshTokenToSessionId.delete(refreshToken);
    return res.status(401).json({ error: 'Session not found' });
  }
  if (new Date(session.expiresAt).getTime() < Date.now()) {
    removeSession(session);
    return res.status(401).json({ error: 'Refresh session expired' });
  }

  session.role = getRoleForAddress(session.address);
  rotateRefreshToken(session);
  return res.json(buildSessionResponse(session));
});

app.post('/auth/logout', authenticate, (req, res) => {
  const session = sessionsById.get(req.auth.sessionId);
  if (session) {
    removeSession(session);
  }
  return res.json({ success: true });
});

app.get('/auth/me', authenticate, (req, res) => {
  const session = sessionsById.get(req.auth.sessionId);
  if (!session) {
    return res.status(401).json({ error: 'Session missing' });
  }
  return res.json({
    user: {
      address: session.address,
      role: session.role
    },
    session: {
      id: session.id,
      createdAt: session.createdAt,
      lastSeenAt: session.lastSeenAt,
      expiresAt: session.expiresAt
    }
  });
});

app.get('/auth/sessions', authenticate, (req, res) => {
  const now = Date.now();
  const sessions = [...sessionsById.values()]
    .filter(
      (session) =>
        session.address === req.auth.address && new Date(session.expiresAt).getTime() > now
    )
    .sort((left, right) => {
      const leftSeen = new Date(left.lastSeenAt).getTime();
      const rightSeen = new Date(right.lastSeenAt).getTime();
      return rightSeen - leftSeen;
    })
    .map((session) => ({
      id: session.id,
      address: session.address,
      role: session.role,
      createdAt: session.createdAt,
      lastSeenAt: session.lastSeenAt,
      expiresAt: session.expiresAt,
      current: session.id === req.auth.sessionId
    }));

  return res.json({ sessions });
});

app.delete('/auth/sessions/:sessionId', authenticate, (req, res) => {
  const { sessionId } = req.params;
  const target = sessionsById.get(sessionId);
  if (!target) {
    return res.status(404).json({ error: 'Session not found' });
  }
  if (target.address !== req.auth.address && req.auth.role !== 'admin') {
    return res.status(403).json({ error: 'Cannot revoke this session' });
  }

  removeSession(target);
  return res.json({ success: true, revokedSessionId: sessionId });
});

app.post('/auth/logout-all', authenticate, (req, res) => {
  const allSessionsForUser = [...sessionsById.values()].filter(
    (session) => session.address === req.auth.address
  );

  for (const session of allSessionsForUser) {
    removeSession(session);
  }

  return res.json({ success: true, revokedSessions: allSessionsForUser.length });
});

app.get('/admin/dashboard', authenticate, requireRole('admin'), (_req, res) => {
  const now = Date.now();
  const activeSessions = [...sessionsById.values()].filter(
    (session) => new Date(session.expiresAt).getTime() > now
  );

  res.json({
    stats: {
      activeSessions: activeSessions.length,
      activeAdmins: activeSessions.filter((session) => session.role === 'admin').length,
      activeUsers: activeSessions.filter((session) => session.role === 'user').length
    },
    sessions: activeSessions.map((session) => ({
      id: session.id,
      address: session.address,
      role: session.role,
      createdAt: session.createdAt,
      lastSeenAt: session.lastSeenAt,
      expiresAt: session.expiresAt
    }))
  });
});

app.post('/admin/roles', authenticate, requireRole('admin'), (req, res) => {
  const { address, role } = req.body || {};
  if (!address || !isAddress(address)) {
    return res.status(400).json({ error: 'Valid address is required' });
  }
  if (role !== 'admin' && role !== 'user') {
    return res.status(400).json({ error: 'Role must be admin or user' });
  }

  const normalizedAddress = normalizeAddress(address);
  rolesByAddress.set(normalizedAddress, role);

  for (const session of sessionsById.values()) {
    if (session.address === normalizedAddress) {
      session.role = role;
    }
  }

  return res.json({ success: true, address: normalizedAddress, role });
});

setInterval(() => {
  const now = Date.now();

  for (const [address, nonceEntry] of nonceStore.entries()) {
    if (nonceEntry.expiresAt < now) {
      nonceStore.delete(address);
    }
  }

  for (const session of sessionsById.values()) {
    if (new Date(session.expiresAt).getTime() < now) {
      removeSession(session);
    }
  }
}, 60_000);

app.listen(config.port, () => {
  console.log(`SIWE backend running on http://localhost:${config.port}`);
});
