const ACCESS_TOKEN_KEY = 'siwe_access_token';
const REFRESH_TOKEN_KEY = 'siwe_refresh_token';
const USER_KEY = 'siwe_user';

export function getAccessToken() {
  return localStorage.getItem(ACCESS_TOKEN_KEY);
}

export function getRefreshToken() {
  return localStorage.getItem(REFRESH_TOKEN_KEY);
}

export function getSavedUser() {
  const raw = localStorage.getItem(USER_KEY);
  return raw ? JSON.parse(raw) : null;
}

export function saveAuthState(payload) {
  localStorage.setItem(ACCESS_TOKEN_KEY, payload.accessToken);
  localStorage.setItem(REFRESH_TOKEN_KEY, payload.refreshToken);
  localStorage.setItem(USER_KEY, JSON.stringify(payload.user));
}

export function clearAuthState() {
  localStorage.removeItem(ACCESS_TOKEN_KEY);
  localStorage.removeItem(REFRESH_TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
}

async function apiFetch(path, options = {}) {
  const response = await fetch(`/api${path}`, {
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {})
    },
    ...options
  });

  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    const message = data.error || 'Request failed';
    throw new Error(message);
  }

  return response.json();
}

export async function refreshSession() {
  const refreshToken = getRefreshToken();
  if (!refreshToken) {
    throw new Error('No refresh token');
  }
  const payload = await apiFetch('/auth/refresh', {
    method: 'POST',
    body: JSON.stringify({ refreshToken })
  });
  saveAuthState(payload);
  return payload;
}

export async function authedFetch(path, options = {}, retry = true) {
  const token = getAccessToken();
  try {
    return await apiFetch(path, {
      ...options,
      headers: {
        ...(options.headers || {}),
        Authorization: `Bearer ${token}`
      }
    });
  } catch (error) {
    if (!retry) {
      throw error;
    }
    await refreshSession();
    return authedFetch(path, options, false);
  }
}

export { apiFetch, ACCESS_TOKEN_KEY, REFRESH_TOKEN_KEY, USER_KEY };
