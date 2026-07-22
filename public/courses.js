/* auth helpers (readAuthValue, clearAuth, authHeaders, escapeHtml, wireUserMenu)
   are loaded from /js/auth.js — do not duplicate here. */

async function fetchCourses() {
  const res = await fetch('/api/activities?type=course', { headers: authHeaders() });
  if (!res.ok) return [];
  const data = await res.json();
  return data.activities || [];
}

async function fetchCourseWithSessions(courseId) {
  const res = await fetch(`/api/activities/${encodeURIComponent(courseId)}`, { headers: authHeaders() });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || 'Failed to load sessions');
  return { activity: body.activity, sessions: body.sessions || [], is_enrolled: body.is_enrolled, is_host: body.is_host };
}

function renderSessions(container, sessions, locked) {
  if (!sessions.length) {
    container.innerHTML = '<div class="session-sub">No sessions yet.</div>';
    return;
  }
  container.innerHTML = sessions.map((s) => {
    const title = escapeHtml(s.title || 'Session');
    const time = [s.start_time, s.end_time].filter(Boolean).join(' – ');
    const sub = locked ? 'Join to see location and details' : [s.location, s.description].filter(Boolean).join(' · ');
    return `
      <div class="session">
        <p class="session-title">${title}</p>
        ${time ? `<div class="session-sub">${escapeHtml(time)}</div>` : ''}
        ${sub ? `<div class="session-sub">${escapeHtml(sub)}</div>` : ''}
      </div>
    `;
  }).join('');
}

function highlightIfNeeded(courseId) {
  const params = new URLSearchParams(window.location.search);
  const target = params.get('highlight');
  if (!target || target !== String(courseId)) return;
  const el = document.getElementById(`course-${courseId}`);
  if (!el) return;
  el.classList.add('highlight');
  el.scrollIntoView({ behavior: 'smooth', block: 'center' });
}

window.addEventListener('DOMContentLoaded', async () => {
  const storedProfile = JSON.parse(readAuthValue('edu_user') || 'null');
  const uname = String(storedProfile?.username || '').trim() || '...';
  const avatar = uname.slice(0, 1).toUpperCase() || 'L';
  const navUname = document.getElementById('nav-uname');
  const navAvatar = document.getElementById('nav-avatar');
  if (navUname) navUname.textContent = uname;
  if (navAvatar) navAvatar.textContent = avatar;
  wireUserMenu();

  const courses = await fetchCourses();
  const grid = document.getElementById('courses');
  const empty = document.getElementById('empty');
  if (!courses.length) {
    empty.style.display = 'block';
    grid.innerHTML = '';
    return;
  }
  empty.style.display = 'none';

  grid.innerHTML = courses.map((c) => {
    const id = escapeHtml(c.id);
    const title = escapeHtml(c.title || 'Untitled course');
    const parts = Number(c.participant_count || 0);
    const sess = Number(c.session_count || 0);
    const tags = Array.isArray(c.tags) ? c.tags.slice(0, 3) : [];
    const tagHtml = tags.map((t) => `<span class="pill">#${escapeHtml(t)}</span>`).join(' ');
    return `
      <div class="course-card" id="course-${id}">
        <div class="course-top">
          <div style="min-width:0">
            <p class="course-title">${title}</p>
            <div class="course-meta">
              <span class="pill">👥 ${parts} participants</span>
              <span class="pill">🗓 ${sess} sessions</span>
              ${tagHtml}
            </div>
          </div>
          <a class="btn-small btn-ghost" href="/course.html?id=${id}">Open</a>
        </div>

        <div class="course-actions">
          <button class="btn-small" data-action="toggle" data-course-id="${id}">View Sessions</button>
        </div>

        <details data-course-id="${id}">
          <summary>Sessions</summary>
          <div class="sessions" id="sessions-${id}"><div class="session-sub">Loading…</div></div>
        </details>
      </div>
    `;
  }).join('');

  courses.forEach((c) => highlightIfNeeded(c.id));

  grid.addEventListener('click', async (event) => {
    const btn = event.target.closest('button[data-action="toggle"]');
    if (!btn) return;
    const id = btn.getAttribute('data-course-id');
    const details = grid.querySelector(`details[data-course-id="${CSS.escape(id)}"]`);
    if (!details) return;
    details.open = !details.open;
    if (!details.open) return;
    const sessionsEl = document.getElementById(`sessions-${id}`);
    if (!sessionsEl || sessionsEl.getAttribute('data-loaded') === '1') return;
    try {
      const data = await fetchCourseWithSessions(id);
      const locked = !(data.is_enrolled || data.is_host);
      renderSessions(sessionsEl, data.sessions, locked);
      sessionsEl.setAttribute('data-loaded', '1');
    } catch (err) {
      sessionsEl.innerHTML = `<div class="session-sub" style="color:#b91c1c;">${escapeHtml(err.message || 'Failed to load sessions')}</div>`;
    }
  });
});

