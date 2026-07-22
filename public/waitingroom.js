async function fetchRooms() {
  const res = await fetch('/api/waitingrooms', { headers: authHeaders() });
  if (!res.ok) return [];
  const data = await res.json();
  return data.rooms || [];
}

function roomDetailUrl(roomId) {
  return `/waitingroom-detail.html?id=${encodeURIComponent(String(roomId || ''))}`;
}

async function createRoom(room) {
  const res = await fetch('/api/waitingroom/create', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify(room)
  });
  if (!res.ok) throw new Error('Failed to create room');
  return await res.json();
}

async function joinRoom(roomId, name, participantId) {
  const res = await fetch('/api/waitingroom/join', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify({ roomId, name, participantId })
  });
  if (!res.ok) throw new Error('Failed to join room');
  return await res.json();
}

async function leaveRoom(roomId, name, participantId) {
  const res = await fetch('/api/waitingroom/leave', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify({ roomId, name, participantId })
  });
  if (!res.ok) throw new Error('Failed to leave room');
  return await res.json();
}

async function deleteRoom(roomId, actor) {
  const res = await fetch('/api/waitingroom/delete', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify({ roomId, actor })
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || 'Failed to delete room');
  }
  return await res.json();
}

/* auth helpers (readAuthValue, writeAuthValue, clearAuth, authHeaders,
   escapeHtml, getUserFromToken, wireUserMenu)
   are loaded from /js/auth.js — do not duplicate here. */




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

function timeAgo(ts) {
  const s = Math.floor((Date.now() - Number(ts || 0)) / 1000);
  if (!Number.isFinite(s) || s <= 0) return 'just now';
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

function renderRooms(rooms, currentUser, currentParticipantId) {
  const grid = document.getElementById('rooms-grid');
  const roomCount = document.getElementById('room-count');
  const youLabel = document.getElementById('you-label');
  const tabCount = document.getElementById('tab-count');
  roomCount.textContent = String(rooms.length);
  if (youLabel) youLabel.textContent = currentUser;

  if (!rooms.length) {
    grid.innerHTML = '<div class="room-card"><div class="card-title">No waiting rooms yet</div><div class="card-desc">Create the first learning request to get started.</div></div>';
    if (tabCount) tabCount.textContent = '0';
    return;
  }

  let totalParticipants = 0;
  grid.innerHTML = rooms.map((room) => {
    const tags = Array.isArray(room.tags) ? room.tags : [];
    const participantList = (Array.isArray(room.participants) ? room.participants : []).map(normalizeParticipant);
    const participants = participantList.length;
    totalParticipants += participants;
    const isFulfilled = Boolean(room.fulfilled);
    const isJoined = participantList.some((p) => String(p.id) === String(currentParticipantId));
    const isCreator = String(room.creator || '').toLowerCase() === String(currentUser).toLowerCase();
    const tagsHtml = tags.length
      ? `<div class="card-tags">${tags.map((t) => `<span class="tag">${escapeHtml(t)}</span>`).join('')}</div>`
      : '';
    const participantsHtml = participantList.length
      ? `<div class="card-participants">${participantList.map((p) => `<span class="part-chip">${escapeHtml(p.name)}</span>`).join('')}</div>`
      : '';

    return `
      <div class="room-card" data-room-id="${escapeHtml(room.id)}" role="link" tabindex="0">
        <div class="card-top">
          <span class="card-interested">${escapeHtml(room.subject || 'General')} · ${participants} interested</span>
          <span class="open-badge"><span class="open-dot"></span>${isFulfilled ? 'Fulfilled' : 'Open'}</span>
        </div>
        <div class="card-title">${escapeHtml(room.title || 'Untitled')}</div>
        ${room.desc ? `<div class="card-desc">${escapeHtml(room.desc)}</div>` : ''}
        ${isFulfilled && room.courseId ? `<div class="card-desc"><a href="/course.html?id=${encodeURIComponent(String(room.courseId))}">Linked Course: ${escapeHtml(room.courseTitle || room.courseId)}</a></div>` : ''}
        ${tagsHtml}
        ${participantsHtml}
        <div class="card-footer">
          <span class="card-author">${escapeHtml(room.creator || 'anonymous')}</span>
          <div class="footer-right">
            <span class="card-time">${timeAgo(room.createdAt)}</span>
            ${isFulfilled ? '' : `<button class="btn-join ${isJoined ? 'leave' : ''}" data-action="${isJoined ? 'leave' : 'join'}" data-room-id="${escapeHtml(room.id)}">
              ${isJoined ? 'Leave' : 'Join'}
            </button>`}
            ${isCreator ? `<button class="btn-del" data-action="delete" data-room-id="${escapeHtml(room.id)}">Delete</button>` : ''}
          </div>
        </div>
      </div>
    `;
  }).join('');
  if (tabCount) tabCount.textContent = String(totalParticipants);
}

function toast(message) {
  const el = document.getElementById('toast');
  if (!el) return;
  el.textContent = message;
  el.classList.add('show');
  setTimeout(() => el.classList.remove('show'), 2500);
}

function wireModal(onCreate) {
  const modal = document.getElementById('modal');
  const createBtn = document.querySelector('.btn-create');
  const cancelBtn = document.querySelector('.btn-cancel');
  const submitBtn = document.querySelector('.btn-submit');

  const open = () => modal.classList.add('open');
  const close = () => modal.classList.remove('open');

  createBtn?.addEventListener('click', open);
  cancelBtn?.addEventListener('click', close);
  modal?.addEventListener('click', (event) => {
    if (event.target === modal) close();
  });

  submitBtn?.addEventListener('click', async () => {
    const title = document.getElementById('f-title').value.trim();
    if (!title) {
      toast('Topic title is required');
      return;
    }
    const payload = {
      title,
      subject: document.getElementById('f-subject').value.trim(),
      desc: document.getElementById('f-desc').value.trim(),
      tags: document.getElementById('f-tags').value.split(',').map((s) => s.trim()).filter(Boolean),
      creator: document.getElementById('nav-uname')?.textContent?.trim() || 'anonymous',
      createdAt: Date.now()
    };
    await onCreate(payload);
    close();
    document.getElementById('f-title').value = '';
    document.getElementById('f-desc').value = '';
    document.getElementById('f-tags').value = '';
  });
}




window.addEventListener('DOMContentLoaded', async () => {
  const token = readAuthValue('edu_token');
  if (!token) {
    window.location.href = '/login.html';
    return;
  }

  const tokenUser = getUserFromToken();
  const storedProfile = JSON.parse(readAuthValue('edu_user') || 'null');
  let profile = (tokenUser?.id || tokenUser?.username)
    ? { ...(storedProfile || {}), id: tokenUser.id || storedProfile?.id || '', username: tokenUser.username || storedProfile?.username || '' }
    : storedProfile;

  // Final source of truth: backend-authenticated user for this token.
  try {
    const res = await fetch('/api/dashboard', { headers: authHeaders() });
    if (!res.ok) {
      clearAuth();
      window.location.href = '/login.html';
      return;
    }
    const dashboard = await res.json();
    const apiUser = dashboard?.user || {};
    if (apiUser?.id || apiUser?.username) {
      profile = {
        ...(profile || {}),
        id: String(apiUser.id || profile?.id || '').trim(),
        username: String(apiUser.username || profile?.username || '').trim()
      };
    }
  } catch {
    clearAuth();
    window.location.href = '/login.html';
    return;
  }

  if (profile) {
    writeAuthValue('edu_user', JSON.stringify(profile));
  }

  const currentUser = (profile?.username || tokenUser?.username || document.getElementById('nav-uname')?.textContent || 'guest').trim();
  const currentParticipantId = getParticipantId({ id: profile?.id || tokenUser?.id || '' }, currentUser);
  document.getElementById('nav-uname').textContent = currentUser;
  document.getElementById('nav-avatar').textContent = currentUser.slice(0, 1).toUpperCase();
  wireUserMenu();

  let rooms = await fetchRooms();
  renderRooms(rooms, currentUser, currentParticipantId);

  // Lightweight real-time sync without websockets: poll every 3s.
  let isRefreshing = false;
  async function refreshRooms() {
    if (isRefreshing) return;
    isRefreshing = true;
    try {
      rooms = await fetchRooms();
      renderRooms(rooms, currentUser, currentParticipantId);
    } finally {
      isRefreshing = false;
    }
  }
  const refreshInterval = setInterval(refreshRooms, 3000);
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) refreshRooms();
  });
  window.addEventListener('beforeunload', () => clearInterval(refreshInterval));
  window.addEventListener('pagehide', () => clearInterval(refreshInterval));

  wireModal(async (payload) => {
    try {
      payload.creatorId = profile?.id || '';
      const created = await createRoom(payload);
      rooms = [created, ...rooms];
      renderRooms(rooms, currentUser, currentParticipantId);
      toast('Waiting room created');
    } catch {
      toast('Failed to create waiting room');
    }
  });

  document.getElementById('rooms-grid')?.addEventListener('click', async (event) => {
    const btn = event.target.closest('button[data-action]');
    if (!btn) {
      const card = event.target.closest('.room-card[data-room-id]');
      if (card) {
        const roomId = card.getAttribute('data-room-id');
        if (roomId) window.location.href = roomDetailUrl(roomId);
      }
      return;
    }
    const action = btn.getAttribute('data-action');
    const roomId = btn.getAttribute('data-room-id');
    if (!action || !roomId) return;

    try {
      if (action === 'join') {
        const updated = await joinRoom(roomId, currentUser, currentParticipantId);
        rooms = rooms.map((room) => (room.id === roomId ? updated : room));
        toast('Joined waiting room');
      } else if (action === 'leave') {
        const updated = await leaveRoom(roomId, currentUser, currentParticipantId);
        rooms = rooms.map((room) => (room.id === roomId ? updated : room));
        toast('Left waiting room');
      } else if (action === 'delete') {
        await deleteRoom(roomId, currentUser);
        rooms = rooms.filter((room) => room.id !== roomId);
        toast('Deleted waiting room');
      }
      renderRooms(rooms, currentUser, currentParticipantId);
    } catch (err) {
      toast(err?.message || 'Action failed');
    }
  });

  document.getElementById('rooms-grid')?.addEventListener('keydown', (event) => {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    if (event.target.closest('button[data-action]')) return;
    const card = event.target.closest('.room-card[data-room-id]');
    if (!card) return;
    event.preventDefault();
    const roomId = card.getAttribute('data-room-id');
    if (roomId) window.location.href = roomDetailUrl(roomId);
  });
});
