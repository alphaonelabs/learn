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

function wireUserMenu() {
  const navMenu = document.getElementById('nav-user-menu');
  const dropdown = document.getElementById('nav-user-dropdown');
  const logoutBtn = document.getElementById('logout-btn');
  if (!navMenu || !dropdown || !logoutBtn) return;

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

function authHeaders() {
  const token = readAuthValue('edu_token');
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function fetchRoom(roomId) {
  const res = await fetch(`/api/waitingroom/${encodeURIComponent(roomId)}`, { headers: authHeaders() });
  if (!res.ok) throw new Error('Waiting room not found');
  const data = await res.json();
  return data.room;
}

async function createCourse(payload) {
  const res = await fetch('/api/activities', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify(payload)
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || 'Failed to create course');
  return body.data;
}

async function createSession(payload) {
  const res = await fetch('/api/sessions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify(payload)
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || 'Failed to create session');
  return body.data;
}

async function fulfillRoom(roomId, actor, courseId, courseTitle) {
  const res = await fetch('/api/waitingroom/fulfill', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify({ roomId, actor, courseId, courseTitle, fulfilledAt: Date.now() })
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || 'Failed to mark waiting room fulfilled');
  return body;
}

function fmtDate(v) {
  return v ? String(v).replace('T', ' ') : '';
}

function replaceSelection(textarea, nextText, cursorOffset = 0) {
  const start = textarea.selectionStart ?? textarea.value.length;
  const end = textarea.selectionEnd ?? textarea.value.length;
  const before = textarea.value.slice(0, start);
  const selected = textarea.value.slice(start, end);
  const after = textarea.value.slice(end);
  const inserted = typeof nextText === 'function' ? nextText(selected) : nextText;
  textarea.value = before + inserted + after;
  const caret = before.length + inserted.length + cursorOffset;
  textarea.focus();
  textarea.setSelectionRange(caret, caret);
}

function lineifySelection(textarea, formatter) {
  const start = textarea.selectionStart ?? 0;
  const end = textarea.selectionEnd ?? 0;
  const value = textarea.value;
  const lineStart = value.lastIndexOf('\n', start - 1) + 1;
  const lineEndRaw = value.indexOf('\n', end);
  const lineEnd = lineEndRaw === -1 ? value.length : lineEndRaw;
  const selectedLines = value.slice(lineStart, lineEnd).split('\n');
  const formatted = selectedLines.map(formatter).join('\n');
  textarea.value = value.slice(0, lineStart) + formatted + value.slice(lineEnd);
  textarea.focus();
  textarea.setSelectionRange(lineStart, lineStart + formatted.length);
}

function wireDescriptionToolbar() {
  const toolbar = document.querySelector('.toolbar');
  const textarea = document.getElementById('description');
  const errEl = document.getElementById('err-msg');
  if (!toolbar || !textarea) return;

  toolbar.addEventListener('click', (event) => {
    const btn = event.target.closest('button[data-action]');
    if (!btn) return;
    const action = btn.getAttribute('data-action');
    if (!action) return;
    errEl.textContent = '';

    if (action === 'bold') {
      replaceSelection(textarea, (sel) => `**${sel || 'bold text'}**`, selOrFallbackOffset(textarea, 2, 'bold text'));
      return;
    }
    if (action === 'italic') {
      replaceSelection(textarea, (sel) => `*${sel || 'italic text'}*`, selOrFallbackOffset(textarea, 1, 'italic text'));
      return;
    }
    if (action === 'heading') {
      lineifySelection(textarea, (line) => line.startsWith('# ') ? line : `# ${line || 'Heading'}`);
      return;
    }
    if (action === 'quote') {
      lineifySelection(textarea, (line) => line.startsWith('> ') ? line : `> ${line || 'Quoted text'}`);
      return;
    }
    if (action === 'ul') {
      lineifySelection(textarea, (line) => line.startsWith('- ') ? line : `- ${line || 'List item'}`);
      return;
    }
    if (action === 'ol') {
      let index = 1;
      lineifySelection(textarea, (line) => {
        const out = `${index}. ${line || 'List item'}`;
        index += 1;
        return out;
      });
      return;
    }
    if (action === 'link') {
      const selected = textarea.value.slice(textarea.selectionStart, textarea.selectionEnd);
      const text = selected || 'link text';
      replaceSelection(textarea, `[${text}](https://example.com)`);
      return;
    }
    if (action === 'separator') {
      replaceSelection(textarea, '\n---\n');
      return;
    }
    if (action === 'help') {
      errEl.textContent = 'Formatting supports Markdown: **bold**, *italic*, # heading, > quote, lists, and [links](url).';
    }
  });
}

function selOrFallbackOffset(textarea, markerLen, fallback) {
  const hasSelection = (textarea.selectionEnd ?? 0) > (textarea.selectionStart ?? 0);
  return hasSelection ? 0 : -(fallback.length + markerLen);
}

window.addEventListener('DOMContentLoaded', async () => {
  wireDescriptionToolbar();
  const token = readAuthValue('edu_token');
  if (!token) {
    window.location.href = '/login.html';
    return;
  }

  const storedProfile = JSON.parse(readAuthValue('edu_user') || 'null');
  const currentUser = String(storedProfile?.username || '').trim();
  document.getElementById('nav-uname').textContent = currentUser || '...';
  document.getElementById('nav-avatar').textContent = (currentUser || 'L').slice(0, 1).toUpperCase();
  wireUserMenu();

  const params = new URLSearchParams(window.location.search);
  const waitingRoomId = params.get('waitingRoomId');
  if (!waitingRoomId) {
    document.getElementById('err-msg').textContent = 'Missing waiting room id.';
    return;
  }

  let room = null;
  try {
    const dashboardRes = await fetch('/api/dashboard', { headers: authHeaders() });
    if (!dashboardRes.ok) {
      clearAuth();
      window.location.href = '/login.html';
      return;
    }
    const dashboard = await dashboardRes.json();
    const apiUser = dashboard?.user || {};
    const profile = {
      ...(storedProfile || {}),
      id: String(apiUser.id || storedProfile?.id || '').trim(),
      username: String(apiUser.username || storedProfile?.username || '').trim()
    };
    writeAuthValue('edu_user', JSON.stringify(profile));
    document.getElementById('nav-uname').textContent = profile.username || '...';
    document.getElementById('nav-avatar').textContent = (profile.username || 'L').slice(0, 1).toUpperCase();

    room = await fetchRoom(waitingRoomId);
    const isCreator = String(room.creator || '').toLowerCase() === String(profile.username || '').toLowerCase();
    if (!isCreator) {
      document.getElementById('err-msg').textContent = 'Only the waiting room creator can teach this course.';
      document.getElementById('submit-btn').disabled = true;
      return;
    }
    if (room.fulfilled) {
      document.getElementById('ok-msg').textContent = 'This waiting room is already fulfilled.';
      document.getElementById('submit-btn').disabled = true;
      return;
    }

    document.getElementById('title').value = room.title || '';
    document.getElementById('description').value = room.desc || '';
    document.getElementById('subject').value = room.subject || '';
    document.getElementById('tags').value = Array.isArray(room.tags) ? room.tags.join(', ') : '';
  } catch (err) {
    document.getElementById('err-msg').textContent = err.message || 'Failed to load waiting room.';
    return;
  }

  document.getElementById('course-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const errEl = document.getElementById('err-msg');
    const okEl = document.getElementById('ok-msg');
    const btn = document.getElementById('submit-btn');
    errEl.textContent = '';
    okEl.textContent = '';
    btn.disabled = true;
    btn.textContent = 'Publishing...';

    try {
      const title = document.getElementById('title').value.trim();
      if (!title) throw new Error('Course title is required');
      const description = document.getElementById('description').value.trim();
      const tags = document.getElementById('tags').value.split(',').map((t) => t.trim()).filter(Boolean);

      const course = await createCourse({
        title,
        description,
        type: 'course',
        format: 'live',
        schedule_type: 'multi_session',
        tags
      });

      const startTime = fmtDate(document.getElementById('start-time').value);
      const endTime = fmtDate(document.getElementById('end-time').value);
      if (startTime || endTime) {
        await createSession({
          activity_id: course.id,
          title: `${title} - Session 1`,
          description: 'Session scheduled from waiting room flow',
          start_time: startTime,
          end_time: endTime,
          location: ''
        });
      }

      await fulfillRoom(waitingRoomId, document.getElementById('nav-uname').textContent.trim(), course.id, course.title || title);
      okEl.textContent = 'Course published and waiting room marked fulfilled.';
      window.location.href = `/courses.html?highlight=${encodeURIComponent(course.id)}`;
    } catch (err) {
      errEl.textContent = err.message || 'Failed to publish course';
      btn.disabled = false;
      btn.textContent = 'Publish Course';
    }
  });
});
