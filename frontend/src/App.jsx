import { useEffect, useMemo, useState } from 'react';
import { Link, Navigate, Route, Routes } from 'react-router-dom';
import { BrowserProvider } from 'ethers';
import {
  apiFetch,
  authedFetch,
  clearAuthState,
  getSavedUser,
  getRefreshToken,
  saveAuthState,
  refreshSession
} from './api';

function buildSiweMessage({ domain, address, statement, uri, version, chainId, nonce, issuedAt }) {
  return `${domain} wants you to sign in with your Ethereum account:\n${address}\n\n${statement}\n\nURI: ${uri}\nVersion: ${version}\nChain ID: ${chainId}\nNonce: ${nonce}\nIssued At: ${issuedAt}`;
}

function HomePage({ auth, setAuth, walletAddress, setWalletAddress, status, setStatus }) {
  const [sessions, setSessions] = useState([]);

  useEffect(() => {
    if (!auth) {
      setSessions([]);
      return;
    }
    authedFetch('/auth/sessions')
      .then((payload) => setSessions(payload.sessions || []))
      .catch(() => setSessions([]));
  }, [auth]);

  async function connectWallet() {
    if (!window.ethereum) {
      setStatus('Install MetaMask or a compatible wallet first.');
      return;
    }
    const provider = new BrowserProvider(window.ethereum);
    const accounts = await provider.send('eth_requestAccounts', []);
    setWalletAddress(accounts[0] || '');
    setStatus('Wallet connected.');
  }

  async function signInWithEthereum() {
    try {
      if (!window.ethereum) {
        throw new Error('No wallet provider found');
      }
      const provider = new BrowserProvider(window.ethereum);
      const signer = await provider.getSigner();
      const address = await signer.getAddress();
      const network = await provider.getNetwork();

      const noncePayload = await apiFetch('/auth/nonce', {
        method: 'POST',
        body: JSON.stringify({ address })
      });

      const message = buildSiweMessage({
        domain: window.location.host,
        address,
        statement: 'Sign in with Ethereum to the Wallet Login System.',
        uri: window.location.origin,
        version: '1',
        chainId: Number(network.chainId),
        nonce: noncePayload.nonce,
        issuedAt: new Date().toISOString()
      });
      const signature = await signer.signMessage(message);

      const verifyPayload = await apiFetch('/auth/verify', {
        method: 'POST',
        body: JSON.stringify({ message, signature })
      });

      saveAuthState(verifyPayload);
      setAuth({
        user: verifyPayload.user,
        session: verifyPayload.session
      });
      setWalletAddress(address);
      setStatus('Authenticated successfully.');
    } catch (error) {
      setStatus(error.message || 'Sign-in failed.');
    }
  }

  async function logout() {
    try {
      await authedFetch('/auth/logout', { method: 'POST' });
    } catch {
    } finally {
      clearAuthState();
      setAuth(null);
      setStatus('Logged out.');
    }
  }

  async function logoutAllSessions() {
    try {
      await authedFetch('/auth/logout-all', { method: 'POST' });
      clearAuthState();
      setAuth(null);
      setSessions([]);
      setStatus('All sessions revoked and logged out.');
    } catch (error) {
      setStatus(error.message || 'Failed to revoke all sessions.');
    }
  }

  async function revokeSession(sessionId, isCurrent) {
    try {
      await authedFetch(`/auth/sessions/${sessionId}`, { method: 'DELETE' });
      if (isCurrent) {
        clearAuthState();
        setAuth(null);
        setSessions([]);
        setStatus('Current session revoked. Logged out.');
        return;
      }

      const payload = await authedFetch('/auth/sessions');
      setSessions(payload.sessions || []);
      setStatus('Session revoked.');
    } catch (error) {
      setStatus(error.message || 'Failed to revoke session.');
    }
  }

  async function refreshAuth() {
    try {
      const payload = await refreshSession();
      setAuth({ user: payload.user, session: payload.session });
      setStatus('Session refreshed.');
    } catch (error) {
      clearAuthState();
      setAuth(null);
      setStatus(error.message || 'Refresh failed.');
    }
  }

  return (
    <div className="container">
      <h1>Wallet Login (EIP-4361 SIWE)</h1>
      <p className="muted">React + Node.js + ethers.js + JWT + RBAC</p>

      <div className="card">
        <h2>Wallet</h2>
        <p>Connected: {walletAddress || 'No wallet connected'}</p>
        <button onClick={connectWallet}>Connect Wallet</button>
      </div>

      <div className="card">
        <h2>Authentication</h2>
        {!auth ? (
          <button onClick={signInWithEthereum}>Sign-In with Ethereum</button>
        ) : (
          <>
            <p>Address: {auth.user.address}</p>
            <p>Role: {auth.user.role}</p>
            <p>Session: {auth.session.id}</p>
            <p>Expires: {new Date(auth.session.expiresAt).toLocaleString()}</p>
            <div className="row">
              <button onClick={refreshAuth}>Refresh Session</button>
              <button onClick={logout}>Logout</button>
              <button onClick={logoutAllSessions}>Logout All Sessions</button>
            </div>
          </>
        )}
      </div>

      {auth && (
        <div className="card">
          <h2>My Sessions</h2>
          {sessions.length === 0 ? (
            <p>No active sessions found.</p>
          ) : (
            <ul>
              {sessions.map((session) => (
                <li key={session.id}>
                  {session.current ? '[current] ' : ''}
                  {session.id} | last seen {new Date(session.lastSeenAt).toLocaleString()}
                  <button
                    style={{ marginLeft: '0.5rem' }}
                    onClick={() => revokeSession(session.id, session.current)}
                  >
                    Revoke
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {auth?.user?.role === 'admin' && (
        <div className="card">
          <h2>Admin</h2>
          <Link to="/admin">Open Admin Dashboard</Link>
        </div>
      )}

      {status && <p className="status">{status}</p>}
    </div>
  );
}

function AdminPage({ auth }) {
  const [dashboard, setDashboard] = useState(null);
  const [error, setError] = useState('');
  const [addressInput, setAddressInput] = useState('');
  const [roleInput, setRoleInput] = useState('user');

  const isAdmin = useMemo(() => auth?.user?.role === 'admin', [auth]);

  useEffect(() => {
    if (!isAdmin) {
      return;
    }

    authedFetch('/admin/dashboard')
      .then((payload) => setDashboard(payload))
      .catch((err) => setError(err.message || 'Failed to load dashboard'));
  }, [isAdmin]);

  async function assignRole(event) {
    event.preventDefault();
    setError('');
    try {
      await authedFetch('/admin/roles', {
        method: 'POST',
        body: JSON.stringify({ address: addressInput, role: roleInput })
      });
      const updated = await authedFetch('/admin/dashboard');
      setDashboard(updated);
      setAddressInput('');
    } catch (err) {
      setError(err.message || 'Unable to assign role');
    }
  }

  if (!auth) {
    return <Navigate to="/" replace />;
  }

  if (!isAdmin) {
    return (
      <div className="container">
        <h1>Admin Dashboard</h1>
        <p className="status">Access denied. Admin role required.</p>
        <Link to="/">Back</Link>
      </div>
    );
  }

  return (
    <div className="container">
      <h1>Admin Dashboard</h1>
      <Link to="/">Back to Home</Link>

      {dashboard && (
        <div className="card">
          <h2>Session Stats</h2>
          <p>Active Sessions: {dashboard.stats.activeSessions}</p>
          <p>Active Admins: {dashboard.stats.activeAdmins}</p>
          <p>Active Users: {dashboard.stats.activeUsers}</p>
        </div>
      )}

      <div className="card">
        <h2>Assign Role</h2>
        <form onSubmit={assignRole} className="form">
          <input
            value={addressInput}
            onChange={(event) => setAddressInput(event.target.value)}
            placeholder="0x... wallet address"
            required
          />
          <select value={roleInput} onChange={(event) => setRoleInput(event.target.value)}>
            <option value="user">user</option>
            <option value="admin">admin</option>
          </select>
          <button type="submit">Assign</button>
        </form>
      </div>

      <div className="card">
        <h2>Active Sessions</h2>
        <ul>
          {(dashboard?.sessions || []).map((session) => (
            <li key={session.id}>
              {session.address} | {session.role} | last seen {new Date(session.lastSeenAt).toLocaleString()}
            </li>
          ))}
        </ul>
      </div>

      {error && <p className="status">{error}</p>}
    </div>
  );
}

export default function App() {
  const [auth, setAuth] = useState(() => {
    const user = getSavedUser();
    if (!user) {
      return null;
    }
    return { user, session: { id: '-', expiresAt: new Date(Date.now() + 60_000).toISOString() } };
  });
  const [walletAddress, setWalletAddress] = useState('');
  const [status, setStatus] = useState('');

  useEffect(() => {
    const refreshToken = getRefreshToken();
    if (!refreshToken) {
      return;
    }
    refreshSession()
      .then((payload) => {
        return authedFetch('/auth/me').then((mePayload) => {
          setAuth({ user: mePayload.user, session: mePayload.session });
        });
      })
      .catch(() => {
        clearAuthState();
        setAuth(null);
      });
  }, []);

  return (
    <Routes>
      <Route
        path="/"
        element={
          <HomePage
            auth={auth}
            setAuth={setAuth}
            walletAddress={walletAddress}
            setWalletAddress={setWalletAddress}
            status={status}
            setStatus={setStatus}
          />
        }
      />
      <Route path="/admin" element={<AdminPage auth={auth} />} />
    </Routes>
  );
}
