/* =========================================================
   activity.js  –  Activities browser + detail view logic
   ========================================================= */

// ── State ──────────────────────────────────────────────────
let _currentActivityId = null;
let _currentActivity   = null;
let _isHost            = false;
let _activeTags        = new Set();
let _allActivities     = [];
let _deleteTargetId    = null;

// ── Auth helpers ───────────────────────────────────────────
function _authToken() {
  const token = localStorage.getItem('edu_token') || localStorage.getItem('token') || '';
  if (token && !localStorage.getItem('edu_token')) {
    localStorage.setItem('edu_token', token);
  }
  return token;
}
function _authHeaders() {
  const t = _authToken();
  return t ? { 'Authorization': `Bearer ${t}` } : {};
}
function _currentUser() {
  // Token format: base64({"id":...,"username":...,"role":...}).hmac_hex
  // i.e. exactly TWO dot-separated parts: parts[0]=payload, parts[1]=sig
  const t = _authToken();
  if (!t) return null;
  try {
    const token = t.startsWith('Bearer ') ? t.slice(7) : t;
    const dot = token.lastIndexOf('.');
    if (dot === -1) return { _opaque: true };
    const b64 = token.slice(0, dot);
    // Fix base64 padding
    const padded = b64 + '==='.slice((b64.length + 3) % 4 || 4);
    return JSON.parse(atob(padded));
  } catch { /* ignore */ }
  return { _opaque: true };
}

// ── Toast ──────────────────────────────────────────────────
function showToast(msg, type = 'success') {
  const el   = document.getElementById('act-toast');
  const icon = document.getElementById('act-toast-icon');
  const txt  = document.getElementById('act-toast-msg');
  if (!el) return;
  const colours = {
    success: 'bg-teal-600',
    error:   'bg-red-600',
    info:    'bg-blue-600',
    warning: 'bg-amber-500',
  };
  const icons = {
    success: 'fa-check-circle',
    error:   'fa-exclamation-circle',
    info:    'fa-info-circle',
    warning: 'fa-exclamation-triangle',
  };
  el.className = `fixed bottom-6 right-6 z-50 flex items-center gap-3 px-5 py-3 rounded-xl shadow-xl text-white text-sm font-medium max-w-xs ${colours[type] || colours.success}`;
  icon.className = `fas ${icons[type] || icons.success} text-lg`;
  txt.textContent = msg;
  el.classList.remove('hidden');
  clearTimeout(el._timer);
  el._timer = setTimeout(() => el.classList.add('hidden'), 3500);
}

// ── Tab switching ──────────────────────────────────────────
function switchTab(name) {
  document.querySelectorAll('.tab-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.tab === name);
  });
  document.querySelectorAll('.tab-panel').forEach(p => {
    p.classList.toggle('active', p.id === `tab-${name}`);
  });
  if (name === 'materials') loadMaterials();
}

// ── View switching ─────────────────────────────────────────
function showBrowser() {
  document.getElementById('browser-view').classList.remove('hidden');
  document.getElementById('browser-view').classList.add('view-browser');
  document.getElementById('detail-view').classList.remove('active');
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function showDetail() {
  document.getElementById('browser-view').classList.add('hidden');
  document.getElementById('detail-view').classList.add('active');
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function backToBrowser() {
  _currentActivityId = null;
  _currentActivity   = null;
  _isHost            = false;
  showBrowser();
}

// ── Format helpers ─────────────────────────────────────────
function formatDate(iso) {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  } catch { return iso; }
}

function getFileIcon(title) {
  const t = (title || '').toLowerCase();
  if (t.endsWith('.pdf'))                          return { icon: 'fa-file-pdf',        colour: 'text-red-500' };
  if (t.endsWith('.doc') || t.endsWith('.docx'))   return { icon: 'fa-file-word',       colour: 'text-blue-500' };
  if (t.endsWith('.xls') || t.endsWith('.xlsx'))   return { icon: 'fa-file-excel',      colour: 'text-green-600' };
  if (t.endsWith('.ppt') || t.endsWith('.pptx'))   return { icon: 'fa-file-powerpoint', colour: 'text-orange-500' };
  if (t.endsWith('.zip') || t.endsWith('.rar'))    return { icon: 'fa-file-archive',    colour: 'text-yellow-600' };
  if (t.endsWith('.mp4') || t.endsWith('.mov'))    return { icon: 'fa-file-video',      colour: 'text-purple-500' };
  if (t.endsWith('.mp3') || t.endsWith('.wav'))    return { icon: 'fa-file-audio',      colour: 'text-pink-500' };
  if (t.endsWith('.png') || t.endsWith('.jpg') || t.endsWith('.jpeg') || t.endsWith('.gif') || t.endsWith('.webp'))
                                                   return { icon: 'fa-file-image',      colour: 'text-teal-500' };
  if (t.endsWith('.js') || t.endsWith('.py') || t.endsWith('.ts') || t.endsWith('.html') || t.endsWith('.css'))
                                                   return { icon: 'fa-file-code',       colour: 'text-indigo-500' };
  if (t.endsWith('.txt') || t.endsWith('.md'))     return { icon: 'fa-file-alt',        colour: 'text-gray-500' };
  return { icon: 'fa-file', colour: 'text-gray-400' };
}

// ── Activity card renderer ─────────────────────────────────
function renderActivityCard(act) {
  const typeColours = {
    course:    'bg-teal-100 text-teal-800 dark:bg-teal-900/40 dark:text-teal-300',
    workshop:  'bg-purple-100 text-purple-800 dark:bg-purple-900/40 dark:text-purple-300',
    seminar:   'bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-300',
    bootcamp:  'bg-orange-100 text-orange-800 dark:bg-orange-900/40 dark:text-orange-300',
    webinar:   'bg-pink-100 text-pink-800 dark:bg-pink-900/40 dark:text-pink-300',
  };
  const fmtColours = {
    online:    'bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300',
    in_person: 'bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-300',
    hybrid:    'bg-cyan-100 text-cyan-800 dark:bg-cyan-900/40 dark:text-cyan-300',
  };
  const typeC = typeColours[act.type] || 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300';
  const fmtC  = fmtColours[act.format] || 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300';
  const tags  = (act.tags || []).slice(0, 3).map(t =>
    `<span class="badge bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300 text-xs">${t}</span>`
  ).join('');

  return `
    <article class="card-hover rounded-2xl bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 shadow-md overflow-hidden cursor-pointer"
      onclick="openActivity('${act.id}')">
      <div class="p-6">
        <div class="flex items-start justify-between gap-3 mb-3">
          <h3 class="font-bold text-gray-900 dark:text-gray-100 text-lg leading-snug line-clamp-2">${act.title}</h3>
          <span class="badge ${typeC} shrink-0">${act.type || 'activity'}</span>
        </div>
        <p class="text-sm text-gray-500 dark:text-gray-400 line-clamp-2 mb-4">${act.description || 'No description provided.'}</p>
        <div class="flex flex-wrap gap-2 mb-4">${tags}</div>
        <div class="flex items-center justify-between text-xs text-gray-400 dark:text-gray-500">
          <span class="badge ${fmtC}">${(act.format || 'online').replace('_', ' ')}</span>
          <span><i class="fas fa-users mr-1"></i>${act.participant_count ?? act.member_count ?? 0} enrolled</span>
        </div>
      </div>
    </article>`;
}

// ── Browser: grid + filters ────────────────────────────────
function renderGrid(activities) {
  const grid = document.getElementById('activity-grid');
  const none = document.getElementById('no-results');
  if (!grid) return;
  if (!activities.length) {
    grid.innerHTML = '';
    none && none.classList.remove('hidden');
    return;
  }
  none && none.classList.add('hidden');
  grid.innerHTML = activities.map(renderActivityCard).join('');
}

function buildTagCloud(activities) {
  const counts = {};
  activities.forEach(a => (a.tags || []).forEach(t => { counts[t] = (counts[t] || 0) + 1; }));
  const cloud = document.getElementById('tag-cloud');
  if (!cloud) return;
  const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 20);
  cloud.innerHTML = sorted.map(([tag]) =>
    `<button class="tag-pill badge bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300 hover:bg-teal-100 dark:hover:bg-teal-900/40 text-xs"
      onclick="toggleTag('${tag}')">${tag}</button>`
  ).join('');
}

function toggleTag(tag) {
  if (_activeTags.has(tag)) _activeTags.delete(tag);
  else _activeTags.add(tag);
  document.querySelectorAll('.tag-pill').forEach(b => {
    b.classList.toggle('active', _activeTags.has(b.textContent.trim()));
  });
  applyFilters();
}

function applyFilters() {
  const q    = (document.getElementById('search')?.value || '').toLowerCase();
  const type = document.getElementById('filter-type')?.value || '';
  const fmt  = document.getElementById('filter-format')?.value || '';
  let list = _allActivities;
  if (q)    list = list.filter(a => (a.title + ' ' + (a.description || '')).toLowerCase().includes(q));
  if (type) list = list.filter(a => a.type === type);
  if (fmt)  list = list.filter(a => a.format === fmt);
  if (_activeTags.size) list = list.filter(a => [..._activeTags].every(t => (a.tags || []).includes(t)));
  renderGrid(list);
}

async function loadAllActivities() {
  try {
    const res  = await fetch('/api/activities');
    const data = await res.json();
    _allActivities = data.activities || [];
    renderGrid(_allActivities);
    buildTagCloud(_allActivities);
  } catch (e) {
    console.error('loadAllActivities', e);
    const grid = document.getElementById('activity-grid');
    if (grid) grid.innerHTML = '<p class="col-span-full text-center text-red-500 py-16">Failed to load activities.</p>';
  }
}

// ── Similar activities ─────────────────────────────────────
function getSimilarActivities(current) {
  if (!current) return [];
  return _allActivities
    .filter(a => a.id !== current.id)
    .map(a => {
      const sharedTags = (a.tags || []).filter(t => (current.tags || []).includes(t)).length;
      const sameType   = a.type === current.type ? 2 : 0;
      return { ...a, _score: sharedTags + sameType };
    })
    .filter(a => a._score > 0)
    .sort((a, b) => b._score - a._score)
    .slice(0, 5);
}

function renderSimilarActivities(similar) {
  const list = document.getElementById('similar-list');
  const card = document.getElementById('similar-card');
  if (!list) return;
  if (!similar.length) { card && card.classList.add('hidden'); return; }
  card && card.classList.remove('hidden');
  list.innerHTML = similar.map(a => `
    <li class="px-4 py-3 hover:bg-gray-50 dark:hover:bg-gray-700/50 cursor-pointer transition-colors"
      onclick="openActivity('${a.id}')">
      <p class="text-sm font-medium text-gray-800 dark:text-gray-200 line-clamp-1">${a.title}</p>
      <p class="text-xs text-gray-400 dark:text-gray-500 mt-0.5">${a.type || ''} · ${(a.format || '').replace('_', ' ')}</p>
    </li>`).join('');
}

// ── Open activity detail ───────────────────────────────────
async function openActivity(id) {
  _currentActivityId = id;
  showDetail();
  switchTab('overview');
  await loadActivityDetail(id);
}

async function loadActivityDetail(id) {
  try {
    const res  = await fetch(`/api/activities/${id}`, { headers: _authHeaders() });
    if (!res.ok) throw new Error('Not found');
    const data = await res.json();

    // API response shape:
    //   { activity: {..., host_name, participant_count, tags},
    //     sessions: [...],
    //     is_host: bool,
    //     is_enrolled: bool }
    const act      = data.activity || data;
    const sessions = data.sessions || [];
    _currentActivity = act;

    // Use the authoritative is_host flag returned by the server
    _isHost = !!(data.is_host);

    const setText = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val || ''; };
    const memberCount = act.participant_count ?? act.member_count ?? 0;

    // ── Hero / breadcrumb ──
    setText('crumb-title', act.title);
    const titleEl = document.getElementById('act-title');
    if (titleEl) titleEl.textContent = act.title || 'Activity';

    const metaEl = document.getElementById('act-meta');
    if (metaEl) metaEl.textContent =
      `${(act.type || 'activity').charAt(0).toUpperCase() + (act.type || 'activity').slice(1)} · ${(act.format || 'online').replace('_', ' ')} · ${memberCount} enrolled`;

    // ── Hero quick-info sidebar ──
    const detailsEl = document.getElementById('act-details');
    if (detailsEl) {
      detailsEl.innerHTML = `
        <div class="flex items-center gap-3 text-sm">
          <i class="fas fa-tag w-5 text-teal-300"></i>
          <span class="capitalize">${act.type || '—'}</span>
        </div>
        <div class="flex items-center gap-3 text-sm">
          <i class="fas fa-globe w-5 text-teal-300"></i>
          <span class="capitalize">${(act.format || '—').replace('_', ' ')}</span>
        </div>
        <div class="flex items-center gap-3 text-sm">
          <i class="fas fa-users w-5 text-teal-300"></i>
          <span>${memberCount} enrolled</span>
        </div>
        <div class="flex items-center gap-3 text-sm">
          <i class="fas fa-user-tie w-5 text-teal-300"></i>
          <span>${act.host_name || 'Unknown Host'}</span>
        </div>
        ${act.created_at ? `<div class="flex items-center gap-3 text-sm"><i class="fas fa-calendar w-5 text-teal-300"></i><span>Created ${formatDate(act.created_at)}</span></div>` : ''}
      `;
    }

    // ── Hero badges ──
    const badgesEl = document.getElementById('act-badges');
    if (badgesEl) {
      badgesEl.innerHTML = (act.tags || []).map(t =>
        `<span class="badge bg-white/20 text-white text-xs">${t}</span>`
      ).join('');
    }

    // ── Overview sidebar: description + tags ──
    setText('act-description', act.description || 'No description provided.');
    const actTagsEl = document.getElementById('act-tags');
    if (actTagsEl) {
      actTagsEl.innerHTML = (act.tags || []).map(t =>
        `<span class="badge bg-teal-100 text-teal-800 dark:bg-teal-900/40 dark:text-teal-300 text-xs">${t}</span>`
      ).join('') || '<span class="text-sm text-gray-400">No tags</span>';
    }

    // ── Welcome card ──
    setText('welcome-text', act.description || 'Welcome to this activity!');

    // ── Join / member CTA ──
    const joinCta    = document.getElementById('join-cta');
    const memberCard = document.getElementById('member-card');
    const enrDetails = document.getElementById('enr-details');

    if (_isHost) {
      joinCta    && joinCta.classList.add('hidden');
      memberCard && memberCard.classList.remove('hidden');
      if (enrDetails) enrDetails.innerHTML = `
        <span class="flex items-center gap-2 text-green-700 dark:text-green-300 font-semibold">
          <i class="fas fa-crown text-amber-500"></i>You are the host of this activity
        </span>`;
    } else if (data.is_enrolled) {
      joinCta    && joinCta.classList.add('hidden');
      memberCard && memberCard.classList.remove('hidden');
      if (enrDetails) enrDetails.innerHTML = `
        <span class="flex items-center gap-2 text-green-700 dark:text-green-300 font-semibold">
          <i class="fas fa-check-circle text-green-500"></i>You are enrolled
        </span>
        ${data.enrollment?.role ? `<span class="badge bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300 text-xs">${data.enrollment.role}</span>` : ''}`;
    } else {
      joinCta    && joinCta.classList.remove('hidden');
      memberCard && memberCard.classList.add('hidden');
    }

    // ── Sessions tab ──
    const sessionsEl = document.getElementById('sessions-list-tab');
    const sessEmpty  = document.getElementById('sessions-empty');
    const sessCount  = document.getElementById('tab-sessions-count');
    if (sessCount) {
      sessCount.textContent = sessions.length;
      sessCount.classList.toggle('hidden', sessions.length === 0);
    }
    if (sessionsEl) {
      if (!sessions.length) {
        sessEmpty && sessEmpty.classList.remove('hidden');
        sessionsEl.innerHTML = '';
      } else {
        sessEmpty && sessEmpty.classList.add('hidden');
        sessionsEl.innerHTML = sessions.map(s => `
          <li class="rounded-xl p-4 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 shadow-sm">
            <div class="flex items-start justify-between gap-3">
              <div>
                <p class="font-semibold text-gray-800 dark:text-gray-200">${s.title || 'Session'}</p>
                ${s.description ? `<p class="text-sm text-gray-500 dark:text-gray-400 mt-1">${s.description}</p>` : ''}
              </div>
              ${s.start_time ? `<span class="text-xs text-gray-400 shrink-0">${formatDate(s.start_time)}</span>` : ''}
            </div>
          </li>`).join('');
      }
    }

    // ── Host tab ──
    setText('host-name-tab', act.host_name || 'Unknown Host');
    const hostAvatar = document.getElementById('host-avatar');
    if (hostAvatar) {
      const name = act.host_name || '?';
      hostAvatar.textContent = name.charAt(0).toUpperCase();
    }

    // ── Similar activities ──
    renderSimilarActivities(getSimilarActivities(act));

  } catch (e) {
    console.error('loadActivityDetail', e);
    showToast('Failed to load activity details', 'error');
  }
}

// ── Join activity ──────────────────────────────────────────
async function joinActivity() {
  const user = _currentUser();
  if (!user) {
    window.location.href = '/login.html?redirect=' + encodeURIComponent(window.location.href);
    return;
  }
  const btn = document.getElementById('btn-join');
  if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Joining…'; }
  try {
    const res  = await fetch(`/api/activities/${_currentActivityId}/join`, {
      method: 'POST',
      headers: { ..._authHeaders(), 'Content-Type': 'application/json' },
    });
    const data = await res.json();
    if (res.ok) {
      showToast('Successfully joined the activity!', 'success');
      await loadActivityDetail(_currentActivityId);
    } else {
      showToast(data.error || 'Failed to join', 'error');
      if (btn) { btn.disabled = false; btn.innerHTML = '<i class="fas fa-plus mr-2"></i>Join Activity'; }
    }
  } catch {
    showToast('Network error — please try again', 'error');
    if (btn) { btn.disabled = false; btn.innerHTML = '<i class="fas fa-plus mr-2"></i>Join Activity'; }
  }
}

// ── Materials ──────────────────────────────────────────────
async function loadMaterials() {
  if (!_currentActivityId) return;

  const loadingEl = document.getElementById('mat-loading');
  const emptyEl   = document.getElementById('mat-empty');
  const errorEl   = document.getElementById('mat-error');
  const listEl    = document.getElementById('mat-list');
  const countLbl  = document.getElementById('mat-count-label');
  const tabCount  = document.getElementById('tab-materials-count');
  const uploadSec = document.getElementById('mat-upload-section');

  // Show/hide upload section based on host status
  if (uploadSec) uploadSec.classList.toggle('hidden', !_isHost);

  // Reset state
  loadingEl && loadingEl.classList.remove('hidden');
  emptyEl   && emptyEl.classList.add('hidden');
  errorEl   && errorEl.classList.add('hidden');
  listEl    && listEl.classList.add('hidden');

  try {
    const res  = await fetch(`/api/activities/${_currentActivityId}/materials`);
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to load');

    const materials = data.materials || [];
    loadingEl && loadingEl.classList.add('hidden');

    // Update counts
    if (countLbl) countLbl.textContent = `${materials.length} file${materials.length !== 1 ? 's' : ''}`;
    if (tabCount) {
      tabCount.textContent = materials.length;
      tabCount.classList.toggle('hidden', materials.length === 0);
    }

    if (!materials.length) {
      emptyEl && emptyEl.classList.remove('hidden');
      const sub = document.getElementById('mat-empty-sub');
      if (sub) sub.textContent = _isHost ? 'Upload your first material using the form above.' : 'No materials have been uploaded yet.';
      return;
    }

    listEl && listEl.classList.remove('hidden');
    listEl.innerHTML = materials.map(m => renderMaterialItem(m)).join('');

  } catch (e) {
    loadingEl && loadingEl.classList.add('hidden');
    errorEl   && errorEl.classList.remove('hidden');
    const msgEl = document.getElementById('mat-error-msg');
    if (msgEl) msgEl.textContent = e.message || 'Failed to load materials.';
  }
}

// Store material data for edit/delete lookups (avoids encoding issues in onclick)
const _matCache = {};

function renderMaterialItem(m) {
  // Cache the material so edit/delete buttons can retrieve it safely
  _matCache[m.id] = m;

  const { icon, colour } = getFileIcon(m.title);
  const hostControls = _isHost ? `
    <div class="flex items-center gap-2 mt-3 pt-3 border-t border-gray-100 dark:border-gray-700">
      <button data-action="edit" data-mid="${m.id}"
        class="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 hover:bg-gray-100 dark:hover:bg-gray-700 text-gray-600 dark:text-gray-300 transition-colors">
        <i class="fas fa-pencil-alt"></i> Edit
      </button>
      <button data-action="delete" data-mid="${m.id}"
        class="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border border-red-300 dark:border-red-700 hover:bg-red-50 dark:hover:bg-red-900/20 text-red-600 dark:text-red-400 transition-colors">
        <i class="fas fa-trash-alt"></i> Delete
      </button>
    </div>` : '';

  return `
    <li class="material-card rounded-xl bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 shadow-sm p-4">
      <div class="flex items-start gap-4">
        <div class="shrink-0 w-12 h-12 rounded-xl bg-gray-50 dark:bg-gray-700 flex items-center justify-center">
          <i class="fas ${icon} text-2xl ${colour}"></i>
        </div>
        <div class="flex-1 min-w-0">
          <div class="flex items-start justify-between gap-3">
            <div class="min-w-0">
              <p class="font-semibold text-gray-800 dark:text-gray-200 truncate">${m.title}</p>
              ${m.description ? `<p class="text-sm text-gray-500 dark:text-gray-400 mt-0.5 line-clamp-2">${m.description}</p>` : ''}
              <p class="text-xs text-gray-400 dark:text-gray-500 mt-1">${formatDate(m.created_at)}</p>
            </div>
            <button data-action="download" data-mid="${m.id}"
              class="shrink-0 flex items-center gap-2 px-4 py-2 rounded-lg bg-teal-600 hover:bg-teal-700 text-white text-sm font-medium transition-colors">
              <i class="fas fa-download"></i>
              <span class="hidden sm:inline">Download</span>
            </button>
          </div>
          ${hostControls}
        </div>
      </div>
    </li>`;
}

async function downloadMaterial(mid) {
  const token = _authToken();
  if (!token) {
    showToast('Please log in to download materials', 'warning');
    return;
  }
  try {
    const res  = await fetch(`/api/activities/${_currentActivityId}/materials/${mid}/download`, {
      headers: { 'Authorization': `Bearer ${token}` },
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Download failed');

    // Prefer a real presigned URL (works without auth header in browser).
    // For the local /api/r2/ fallback, append the token as a query param
    // since <a> navigation can't set Authorization headers.
    const payload  = data.data || data;
    let url        = payload.download_url || '';
    const filename = payload.filename || payload.title || 'download';

    if (url.startsWith('/api/r2/')) {
      url = `${url}?token=${encodeURIComponent(token)}`;
    }
    const a = document.createElement('a');
    a.href     = url;
    a.download = filename;          // sets the saved filename in the browser
    a.target   = '_blank';
    a.rel      = 'noopener noreferrer';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    showToast('Download started!', 'success');
  } catch (e) {
    showToast(e.message || 'Download failed', 'error');
  }
}

// ── Delete modal ───────────────────────────────────────────
function openDeleteModal(mid, title) {
  _deleteTargetId = mid;
  const modal = document.getElementById('mat-confirm-modal');
  const msg   = document.getElementById('mat-confirm-msg');
  if (msg) msg.textContent = `Delete "${title}"? This action cannot be undone.`;
  modal && modal.classList.remove('hidden');
  const okBtn = document.getElementById('mat-confirm-ok');
  if (okBtn) {
    okBtn.onclick = async () => {
      okBtn.disabled = true;
      okBtn.textContent = 'Deleting…';
      await confirmDelete();
      okBtn.disabled = false;
      okBtn.textContent = 'Delete';
    };
  }
}

function closeDeleteModal() {
  document.getElementById('mat-confirm-modal')?.classList.add('hidden');
  _deleteTargetId = null;
}

async function confirmDelete() {
  if (!_deleteTargetId) return;
  try {
    const res  = await fetch(`/api/activities/${_currentActivityId}/materials/${_deleteTargetId}`, {
      method: 'DELETE',
      headers: _authHeaders(),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Delete failed');
    closeDeleteModal();
    showToast('Material deleted', 'success');
    await loadMaterials();
  } catch (e) {
    closeDeleteModal();
    showToast(e.message || 'Delete failed', 'error');
  }
}

// ── Edit modal ─────────────────────────────────────────────
function openEditModal(mid, title, desc) {
  document.getElementById('mat-edit-id').value    = mid;
  document.getElementById('mat-edit-title').value = title;
  document.getElementById('mat-edit-desc').value  = desc || '';
  const errEl = document.getElementById('mat-edit-error');
  if (errEl) { errEl.textContent = ''; errEl.classList.add('hidden'); }
  document.getElementById('mat-edit-modal')?.classList.remove('hidden');
}

function closeEditModal() {
  document.getElementById('mat-edit-modal')?.classList.add('hidden');
}

// ── Upload form ────────────────────────────────────────────
function _initUploadForm() {
  const form      = document.getElementById('mat-upload-form');
  const dropZone  = document.getElementById('mat-drop-zone');
  const fileInput = document.getElementById('mat-file-input');
  const browseBtn = document.getElementById('mat-browse-link');
  const selFile   = document.getElementById('mat-selected-file');
  const progWrap  = document.getElementById('mat-upload-progress');
  const progBar   = document.getElementById('mat-upload-progress-bar');
  const progPct   = document.getElementById('mat-upload-pct');
  const errEl     = document.getElementById('mat-upload-error');
  const submitBtn = document.getElementById('mat-upload-btn');

  if (!form) return;

  // Browse link
  browseBtn && browseBtn.addEventListener('click', e => { e.preventDefault(); fileInput && fileInput.click(); });

  // File input change
  fileInput && fileInput.addEventListener('change', () => {
    const f = fileInput.files[0];
    if (f && selFile) {
      selFile.textContent = f.name;
      selFile.classList.remove('hidden');
    }
  });

  // Drag & drop
  if (dropZone) {
    dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
    dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
    dropZone.addEventListener('drop', e => {
      e.preventDefault();
      dropZone.classList.remove('drag-over');
      const f = e.dataTransfer.files[0];
      if (f) {
        const dt = new DataTransfer();
        dt.items.add(f);
        fileInput.files = dt.files;
        if (selFile) { selFile.textContent = f.name; selFile.classList.remove('hidden'); }
      }
    });
  }

  // Form submit
  form.addEventListener('submit', async e => {
    e.preventDefault();
    if (errEl) { errEl.textContent = ''; errEl.classList.add('hidden'); }

    const title = (document.getElementById('mat-title')?.value || '').trim();
    const desc  = (document.getElementById('mat-desc')?.value  || '').trim();
    const file  = fileInput?.files[0];

    if (!title) { if (errEl) { errEl.textContent = 'Title is required.'; errEl.classList.remove('hidden'); } return; }
    if (!file)  { if (errEl) { errEl.textContent = 'Please select a file.'; errEl.classList.remove('hidden'); } return; }

    // Show progress
    progWrap && progWrap.classList.remove('hidden');
    if (submitBtn) { submitBtn.disabled = true; submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Uploading…'; }

    // Simulate progress
    let pct = 0;
    const ticker = setInterval(() => {
      pct = Math.min(pct + Math.random() * 15, 85);
      if (progBar) progBar.style.width = pct + '%';
      if (progPct) progPct.textContent = Math.round(pct) + '%';
    }, 200);

    try {
      const fd = new FormData();
      fd.append('title', title);
      fd.append('description', desc);
      fd.append('file', file);

      const res  = await fetch(`/api/activities/${_currentActivityId}/materials`, {
        method: 'POST',
        headers: _authHeaders(),
        body: fd,
      });
      const data = await res.json();
      clearInterval(ticker);

      if (!res.ok) throw new Error(data.error || 'Upload failed');

      // Complete progress bar
      if (progBar) progBar.style.width = '100%';
      if (progPct) progPct.textContent = '100%';

      setTimeout(() => {
        progWrap && progWrap.classList.add('hidden');
        if (progBar) progBar.style.width = '0%';
        if (progPct) progPct.textContent = '0%';
      }, 600);

      // Reset form
      form.reset();
      if (selFile) { selFile.textContent = ''; selFile.classList.add('hidden'); }
      if (submitBtn) { submitBtn.disabled = false; submitBtn.innerHTML = '<i class="fas fa-upload mr-2"></i>Upload Material'; }

      showToast('Material uploaded successfully!', 'success');
      await loadMaterials();

    } catch (err) {
      clearInterval(ticker);
      progWrap && progWrap.classList.add('hidden');
      if (progBar) progBar.style.width = '0%';
      if (errEl) { errEl.textContent = err.message || 'Upload failed.'; errEl.classList.remove('hidden'); }
      if (submitBtn) { submitBtn.disabled = false; submitBtn.innerHTML = '<i class="fas fa-upload mr-2"></i>Upload Material'; }
    }
  });
}

// ── Edit form submit ───────────────────────────────────────
function _initEditForm() {
  const form = document.getElementById('mat-edit-form');
  if (!form) return;
  form.addEventListener('submit', async e => {
    e.preventDefault();
    const mid   = document.getElementById('mat-edit-id')?.value;
    const title = (document.getElementById('mat-edit-title')?.value || '').trim();
    const desc  = (document.getElementById('mat-edit-desc')?.value  || '').trim();
    const errEl = document.getElementById('mat-edit-error');
    const btn   = document.getElementById('mat-edit-btn');

    if (errEl) { errEl.textContent = ''; errEl.classList.add('hidden'); }
    if (!title) {
      if (errEl) { errEl.textContent = 'Title is required.'; errEl.classList.remove('hidden'); }
      return;
    }
    if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fas fa-spinner fa-spin mr-1"></i> Saving…'; }

    try {
      const res  = await fetch(`/api/activities/${_currentActivityId}/materials/${mid}`, {
        method: 'PATCH',
        headers: { ..._authHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ title, description: desc }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Update failed');
      closeEditModal();
      showToast('Material updated!', 'success');
      await loadMaterials();
    } catch (err) {
      if (errEl) { errEl.textContent = err.message || 'Update failed.'; errEl.classList.remove('hidden'); }
    } finally {
      if (btn) { btn.disabled = false; btn.innerHTML = '<i class="fas fa-save mr-1"></i> Save Changes'; }
    }
  });
}

// ── Init ───────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  // Wire up search + filters (HTML uses id="search", not "search-input")
  document.getElementById('search')?.addEventListener('input', applyFilters);
  document.getElementById('filter-type')?.addEventListener('change', applyFilters);
  document.getElementById('filter-format')?.addEventListener('change', applyFilters);

  // Event delegation for material list buttons (download / edit / delete)
  // Using delegation avoids onclick-in-HTML encoding issues with special chars
  document.getElementById('mat-list')?.addEventListener('click', e => {
    const btn = e.target.closest('[data-action]');
    if (!btn) return;
    const action = btn.dataset.action;
    const mid    = btn.dataset.mid;
    if (!mid) return;

    if (action === 'download') {
      downloadMaterial(mid);
    } else if (action === 'edit') {
      const mat = _matCache[mid];
      if (mat) openEditModal(mat.id, mat.title, mat.description || '');
    } else if (action === 'delete') {
      const mat = _matCache[mid];
      if (mat) openDeleteModal(mat.id, mat.title);
    }
  });

  // Init forms
  _initUploadForm();
  _initEditForm();

  // Load activities for browser view
  loadAllActivities();

  // Check if URL has ?id= param to open detail directly
  const params = new URLSearchParams(window.location.search);
  const actId  = params.get('id');
  if (actId) openActivity(actId);
});