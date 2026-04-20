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

function writeAuthValue(key, value) {
  sessionStorage.setItem(key, value);
  localStorage.removeItem(key);
}

function clearAuth() {
  sessionStorage.removeItem('edu_token');
  sessionStorage.removeItem('edu_user');
  localStorage.removeItem('edu_token');
  localStorage.removeItem('edu_user');
}

function authHeaders() {
  const token = readAuthValue('edu_token');
  return token ? { Authorization: `Bearer ${token}` } : {};
}

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
      username: String(user.username || '').trim()
    };
  } catch {
    return null;
  }
}

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function normalizeParticipant(participant) {
  if (participant && typeof participant === 'object') {
    return {
      id: String(participant.id || '').trim(),
      name: String(participant.name || 'anonymous').trim() || 'anonymous'
    };
  }
  const name = String(participant || 'anonymous').trim() || 'anonymous';
  return { id: name.toLowerCase(), name };
}

async function fetchRoom(roomId) {
  const res = await fetch(`/api/waitingroom/${encodeURIComponent(roomId)}`, { headers: authHeaders() });
  if (!res.ok) throw new Error('Room not found');
  const data = await res.json();
  return data.room;
}

async function joinRoom(roomId, name, participantId) {
  const res = await fetch('/api/waitingroom/join', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify({ roomId, name, participantId })
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || 'Failed to join room');
  return body;
}

async function leaveRoom(roomId, name, participantId) {
  const res = await fetch('/api/waitingroom/leave', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify({ roomId, name, participantId })
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || 'Failed to leave room');
  return body;
}

async function deleteRoom(roomId, actor) {
  const res = await fetch('/api/waitingroom/delete', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify({ roomId, actor })
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || 'Failed to delete room');
  return body;
}

function getParticipantId(profile, currentUser) {
  if (profile?.id) return String(profile.id);
  const userKey = String(currentUser || 'guest').trim().toLowerCase().replace(/[^a-z0-9_-]/g, '_') || 'guest';
  const key = `waitingroom_participant_id_${userKey}`;
  let id = localStorage.getItem(key);
  if (!id) {
    id = `p_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
    localStorage.setItem(key, id);
  }
  return id;
}

function renderRoom(room, currentUser, participantId) {
  const participants = (Array.isArray(room.participants) ? room.participants : []).map(normalizeParticipant);
  const isJoined = participants.some((p) => p.id === participantId);
  const isCreator = String(room.creator || '').toLowerCase() === String(currentUser).toLowerCase();
  const isFulfilled = Boolean(room.fulfilled);
  document.getElementById('room-title').textContent = room.title || 'Untitled';
  document.getElementById('room-desc').textContent = room.desc || '';
  document.getElementById('room-status').innerHTML = `<span class="dot"></span> ${isFulfilled ? 'Fulfilled' : 'Open'}`;
  document.getElementById('room-subject').textContent = room.subject || 'General';
  document.getElementById('room-creator').textContent = room.creator || 'anonymous';
  document.getElementById('participant-count').textContent = String(participants.length);
  document.getElementById('room-linked-course').innerHTML = (isFulfilled && room.courseId)
    ? `Linked Course: <a href="/course.html?id=${encodeURIComponent(String(room.courseId))}">${escapeHtml(room.courseTitle || room.courseId)}</a>`
    : '';
  document.getElementById('room-tags').innerHTML = (Array.isArray(room.tags) && room.tags.length)
    ? room.tags.map((tag) => `<span class="tag">${escapeHtml(tag)}</span>`).join(' ')
    : '-';

  const list = document.getElementById('participant-list');
  if (!participants.length) {
    list.innerHTML = '<div style="color:#6b7280;font-size:14px">No participants yet.</div>';
  } else {
    list.innerHTML = participants.map((p) => {
      const initial = escapeHtml((p.name || 'a').slice(0, 1));
      const creatorPill = String(room.creator || '').toLowerCase() === String(p.name || '').toLowerCase()
        ? '<span class="creator-pill">Creator</span>'
        : '';
      return `
        <div class="participant">
          <span class="p-name"><span class="avatar">${initial}</span>${escapeHtml(p.name)}</span>
          ${creatorPill}
        </div>
      `;
    }).join('');
  }

  const actions = document.getElementById('actions');
  const buttons = [];
  if (!isFulfilled) {
    if (isJoined) {
      buttons.push('<button class="btn btn-leave" data-action="leave">Leave Request</button>');
    } else {
      buttons.push('<button class="btn btn-join" data-action="join">Join Request</button>');
    }
  }
  if (isCreator && !isFulfilled) {
    buttons.push('<button class="btn btn-join" data-action="teach">Teach This Course</button>');
    buttons.push('<button class="btn btn-delete" data-action="delete">Delete Room</button>');
  }
  actions.innerHTML = buttons.join('');
}

window.addEventListener('DOMContentLoaded', async () => {
  const token = readAuthValue('edu_token');
  if (!token) {
    window.location.href = '/login.html';
    return;
  }

  const params = new URLSearchParams(window.location.search);
  const roomId = params.get('id');
  if (!roomId) {
    document.getElementById('error').textContent = 'Missing room id.';
    return;
  }

  let tokenUser = getUserFromToken() || {};
  let profile = JSON.parse(readAuthValue('edu_user') || 'null') || {};

  try {
    const res = await fetch('/api/dashboard', { headers: authHeaders() });
    if (!res.ok) {
      clearAuth();
      window.location.href = '/login.html';
      return;
    }
    const dashboard = await res.json();
    const apiUser = dashboard?.user || {};
    profile = {
      ...profile,
      id: String(apiUser.id || tokenUser.id || profile.id || '').trim(),
      username: String(apiUser.username || tokenUser.username || profile.username || '').trim()
    };
    writeAuthValue('edu_user', JSON.stringify(profile));
  } catch {
    clearAuth();
    window.location.href = '/login.html';
    return;
  }

  const currentUser = String(profile.username || tokenUser.username || 'guest').trim();
  const currentParticipantId = getParticipantId({ id: profile.id || tokenUser.id || '' }, currentUser);
  document.getElementById('nav-user').textContent = currentUser;

  let room = null;
  let isRefreshing = false;
  async function refresh() {
    if (isRefreshing) return;
    isRefreshing = true;
    try {
      room = await fetchRoom(roomId);
      renderRoom(room, currentUser, currentParticipantId);
      document.getElementById('error').textContent = '';
    } finally {
      isRefreshing = false;
    }
  }

  try {
    await refresh();
  } catch (err) {
    document.getElementById('error').textContent = err.message || 'Failed to load room.';
    return;
  }

  document.getElementById('actions').addEventListener('click', async (event) => {
    const btn = event.target.closest('button[data-action]');
    if (!btn) return;
    const action = btn.getAttribute('data-action');
    try {
      if (action === 'join') {
        await joinRoom(roomId, currentUser, currentParticipantId);
      } else if (action === 'leave') {
        await leaveRoom(roomId, currentUser, currentParticipantId);
      } else if (action === 'teach') {
        window.location.href = `/teach-course.html?waitingRoomId=${encodeURIComponent(roomId)}`;
        return;
      } else if (action === 'delete') {
        await deleteRoom(roomId, currentUser);
        window.location.href = '/waitingroom.html';
        return;
      }
      await refresh();
    } catch (err) {
      document.getElementById('error').textContent = err.message || 'Action failed.';
    }
  });

  // Lightweight real-time sync without websockets: poll every 3s.
  const refreshInterval = setInterval(async () => {
    try {
      await refresh();
    } catch (err) {
      document.getElementById('error').textContent = err.message || 'Sync failed.';
    }
  }, 3000);

  document.addEventListener('visibilitychange', async () => {
    if (!document.hidden) {
      try {
        await refresh();
      } catch {
        // Keep UI stable; periodic polling will retry.
      }
    }
  });

  window.addEventListener('beforeunload', () => clearInterval(refreshInterval));
});
