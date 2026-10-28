/* ================================================================
   auth.js — Shared authentication and utility helpers
   ================================================================
   Included by: waitingroom.html, waitingroom-detail.html,
                courses.html, teach-course.html, course.html
   ================================================================ */

/**
 * Read an auth value, migrating from localStorage → sessionStorage.
 * @param {string} key
 * @returns {string|null}
 */
function readAuthValue(key) {
  const fromSession = sessionStorage.getItem(key);
  if (fromSession) return fromSession;
  const fromLocal = localStorage.getItem(key);
  if (fromLocal) {
    sessionStorage.setItem(key, fromLocal);
    localStorage.removeItem(key);
  }
  return fromLocal;
}

/**
 * Write an auth value to sessionStorage (and clear localStorage copy).
 * @param {string} key
 * @param {string} value
 */
function writeAuthValue(key, value) {
  sessionStorage.setItem(key, value);
  localStorage.removeItem(key);
}

/**
 * Clear all auth tokens from both storage layers.
 */
function clearAuth() {
  sessionStorage.removeItem('edu_token');
  sessionStorage.removeItem('edu_user');
  localStorage.removeItem('edu_token');
  localStorage.removeItem('edu_user');
}

/**
 * Build an Authorization header object if a token exists.
 * @returns {Object}
 */
function authHeaders() {
  const token = readAuthValue('edu_token');
  return token ? { Authorization: `Bearer ${token}` } : {};
}

/**
 * HTML-escape a value for safe injection into innerHTML / attributes.
 * Handles &, <, >, ", and ' (defense-in-depth for attribute contexts).
 * @param {*} value
 * @returns {string}
 */
function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Decode the user payload from the first segment of a signed token.
 * @returns {{ id: string, username: string, role?: string } | null}
 */
function getUserFromToken() {
  const token = readAuthValue('edu_token');
  if (!token || !token.includes('.')) return null;
  try {
    const payload = token.split('.')[0];
    const normalized = payload.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized + '='.repeat((4 - normalized.length % 4) % 4);
    const decoded = atob(padded);
    const user = JSON.parse(decoded);
    if (!user || typeof user !== 'object') return null;
    return {
      id: String(user.id || '').trim(),
      username: String(user.username || '').trim(),
      role: String(user.role || '').trim()
    };
  } catch {
    return null;
  }
}

/**
 * Wire the nav user dropdown menu (open/close, logout).
 * Requires elements with ids: nav-user-menu, nav-user-dropdown, logout-btn.
 */
function wireUserMenu() {
  const navMenu = document.getElementById('nav-user-menu');
  const logoutBtn = document.getElementById('logout-btn');
  if (!navMenu || !logoutBtn) return;

  function setOpen(open) {
    navMenu.classList.toggle('open', open);
    navMenu.setAttribute('aria-expanded', open ? 'true' : 'false');
  }

  navMenu.addEventListener('click', (event) => {
    event.stopPropagation();
    setOpen(!navMenu.classList.contains('open'));
  });

  navMenu.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      setOpen(!navMenu.classList.contains('open'));
    } else if (event.key === 'Escape') {
      setOpen(false);
    }
  });

  logoutBtn.addEventListener('click', (event) => {
    event.stopPropagation();
    clearAuth();
    window.location.href = '/login.html';
  });

  document.addEventListener('click', (event) => {
    if (!navMenu.contains(event.target)) setOpen(false);
  });
}
