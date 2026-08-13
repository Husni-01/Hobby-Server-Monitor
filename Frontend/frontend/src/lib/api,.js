// src/lib/api.js

const API_BASE = 'http://127.0.0.1:8000/api';

export async function fetchWithAuth(endpoint, options = {}) {
  // Retrieve the stateless JWT issued by our Falcon backend
  const token = localStorage.getItem('session_token');
  
  if (!token && window.location.pathname !== '/login') {
    window.location.href = '/login';
    return null;
  }

  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
      ...(options.headers || {})
    }
  });

  // Global trap for expired sessions or revoked access
  if (response.status === 401 || response.status === 403) {
    localStorage.removeItem('session_token');
    localStorage.removeItem('user_data');
    window.location.href = '/login';
    return null;
  }

  return response;
}