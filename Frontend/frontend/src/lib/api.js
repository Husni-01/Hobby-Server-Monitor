// src/lib/api.js
// Central fetch wrapper — attaches the JWT and handles global 401/403 redirects.

const API_BASE = import.meta.env.PUBLIC_API_BASE || 'http://localhost:8000/api';

export async function fetchWithAuth(endpoint, options = {}) {
  const token = localStorage.getItem('session_token');

  if (!token && window.location.pathname !== '/login') {
    window.location.href = '/login';
    return null;
  }

  const res = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
      ...(options.headers || {}),
    },
  });

  if (res.status === 401) {
    localStorage.removeItem('session_token');
    localStorage.removeItem('user_data');
    window.location.href = '/login';
    return null;
  }

  return res;
}

/** Convenience wrappers */
export const api = {
  get:    (path)         => fetchWithAuth(path),
  post:   (path, body)   => fetchWithAuth(path, { method: 'POST',   body: JSON.stringify(body) }),
  patch:  (path, body)   => fetchWithAuth(path, { method: 'PATCH',  body: JSON.stringify(body) }),
  delete: (path)         => fetchWithAuth(path, { method: 'DELETE' }),
};
