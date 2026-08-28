/* Shared runtime for every page: theme, navigation state, fetch, toasts.
 * No framework and no build step - the whole site is files the Worker serves. */

export const $ = (s, r = document) => r.querySelector(s);
export const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

export function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

export function fmtDate(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (isNaN(d)) return String(iso).slice(0, 19).replace('T', ' ');
  return d.toLocaleString(undefined, { year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' });
}

// ---- theme ---------------------------------------------------------------
// The <head> of every page sets data-theme before first paint; this only handles
// the toggle. Storage can throw in a locked-down browser, so every touch is guarded.

export function theme() {
  try { return localStorage.getItem('aa-theme') || ''; } catch { return ''; }
}
export function toggleTheme() {
  const dark = document.documentElement.dataset.theme
    ? document.documentElement.dataset.theme === 'dark'
    : matchMedia('(prefers-color-scheme: dark)').matches;
  const next = dark ? 'light' : 'dark';
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem('aa-theme', next); } catch { /* private mode */ }
}

// ---- fetch ---------------------------------------------------------------

export async function api(path, opts = {}) {
  const init = { credentials: 'same-origin', headers: {}, ...opts };
  if (init.body !== undefined && typeof init.body !== 'string') {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(init.body);
    init.method = init.method || 'POST';
  }
  const r = await fetch(path, init);
  let data = null;
  try { data = await r.json(); } catch { /* non-JSON error page */ }
  if (!r.ok) {
    const e = new Error((data && data.error) || `Something went wrong (${r.status}).`);
    e.status = r.status;
    throw e;
  }
  return data;
}

let mePromise = null;
export function me(force) {
  if (force || !mePromise) mePromise = api('/api/me').catch(() => ({ user: null }));
  return mePromise;
}

// ---- toasts --------------------------------------------------------------

export function toast(message, bad) {
  let host = $('#toasts');
  if (!host) { host = document.createElement('div'); host.id = 'toasts'; document.body.appendChild(host); }
  const el = document.createElement('div');
  el.className = 'toast' + (bad ? ' bad' : '');
  el.setAttribute('role', 'status');
  el.textContent = message;
  host.appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

// ---- verdict language ----------------------------------------------------
// Colour never carries the meaning alone: every chip prints the word too.

export function band(verdict) {
  const v = String(verdict || '').toLowerCase();
  if (v.includes('confirm') || v === 'cheat' || v === 'flagged') return { cls: 'chip-bad', color: 'var(--bad)', word: 'Confirmed' };
  if (v.includes('review') || v.includes('likely') || v.includes('suspic')) return { cls: 'chip-warn', color: 'var(--warn)', word: 'Review' };
  if (v.includes('clean') || v.includes('verified')) return { cls: 'chip-good', color: 'var(--good)', word: 'Clean' };
  return { cls: 'chip-flat', color: 'var(--muted)', word: verdict || 'Unknown' };
}

export function chip(verdict) {
  const b = band(verdict);
  return `<span class="chip ${b.cls}">${esc(verdict || b.word)}</span>`;
}

// ---- entrance ------------------------------------------------------------

export function reveal(root = document) {
  const items = $$('.reveal:not(.armed)', root);
  if (!items.length) return;
  if (matchMedia('(prefers-reduced-motion: reduce)').matches || !('IntersectionObserver' in window)) return;
  items.forEach(el => el.classList.add('armed'));
  const io = new IntersectionObserver((entries) => {
    entries.forEach((e, i) => {
      if (!e.isIntersecting) return;
      setTimeout(() => e.target.classList.add('in'), Math.min(i, 6) * 45);
      io.unobserve(e.target);
    });
  }, { rootMargin: '0px 0px -8% 0px', threshold: .08 });
  items.forEach(el => io.observe(el));
}

// ---- navigation ----------------------------------------------------------

// The navigation and footer live here rather than in twelve copies of the same
// markup. Twelve copies is how one page keeps a link the others dropped.
const NAV = `
<div class="nav-shell"><nav class="nav" aria-label="Main">
  <a class="brand" href="/"><span class="dot" aria-hidden="true"></span>AsyncAnalyzer</a>
  <div class="nav-links">
    <a href="/how-it-works" class="hide-sm">How it works</a>
    <a href="/benchmarks" class="hide-sm">Benchmarks</a>
    <span id="nav-auth"></span>
    <button id="theme-toggle" class="icon-btn" type="button" aria-label="Switch between light and dark">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 3v18a9 9 0 0 0 0-18z" fill="currentColor" stroke="none"/></svg>
    </button>
  </div>
</nav></div>`;

const FOOT = `
<footer><div class="wrap">
  <span class="mono">AsyncAnalyzer</span>
  <a href="/how-it-works">How it works</a>
  <a href="/privacy">Privacy</a>
  <a href="https://github.com/QDHShamiro/AsyncAnalyzer">Source</a>
  <span class="spacer"></span>
  <span class="tiny">The scan runs on the suspect's own PC.</span>
</div></footer>`;

export async function mountNav() {
  const navSlot = $('#nav');
  if (navSlot && !navSlot.dataset.done) { navSlot.outerHTML = NAV; }
  const footSlot = $('#foot');
  if (footSlot) footSlot.outerHTML = FOOT;

  const toggle = $('#theme-toggle');
  if (toggle) toggle.addEventListener('click', toggleTheme);

  const here = location.pathname.replace(/\/$/, '') || '/';
  $$('.nav-links a, .tabs a').forEach(a => {
    const href = (a.getAttribute('href') || '').replace(/\/$/, '') || '/';
    if (href === here) a.setAttribute('aria-current', 'page');
  });

  const slot = $('#nav-auth');
  if (!slot) return;
  const state = await me();
  if (state && state.user) {
    slot.innerHTML = `<a href="/app">Dashboard</a>` +
      (state.staff ? `<a href="/admin" class="hide-sm">Admin</a>` : '');
  } else {
    slot.innerHTML = `<a href="/login">Log in</a>`;
  }
  $$('#nav-auth a').forEach(a => { if ((a.getAttribute('href') || '') === here) a.setAttribute('aria-current', 'page'); });
}

// Pages behind a login call this first. Sending people to /login with where they
// were going means the sign-in drops them back on the page they wanted, not home.
export async function requireAuth() {
  const state = await me();
  if (!state || !state.user) {
    location.replace('/login?next=' + encodeURIComponent(location.pathname + location.search));
    return null;
  }
  return state;
}

// ---- server pages --------------------------------------------------------
// /app/<slug>, /app/<slug>/team, /app/<slug>/setup and /app/<slug>/scan/<id> are
// four pages about one server, so the header and tabs are written once.

export function pathParts() { return location.pathname.split('/').filter(Boolean); }
export function serverSlug() {
  const p = pathParts();
  return p[0] === 'app' && p[1] ? decodeURIComponent(p[1]) : '';
}

export function serverHead(slug, server, role, active) {
  const base = '/app/' + encodeURIComponent(slug);
  const tab = (href, label) =>
    `<a href="${href}"${href === active ? ' aria-current="page"' : ''}>${label}</a>`;
  const suspended = server.status && server.status !== 'active'
    ? ` <span class="chip chip-warn">${esc(server.status)}</span>` : '';
  return `<div class="page-head">
    <div class="crumb"><a href="/app">Servers</a><span aria-hidden="true">/</span><span>${esc(server.name)}</span></div>
    <h1>${esc(server.name)}${suspended}</h1>
    <p class="muted small" style="margin-top:8px">You are ${role === 'owner' ? 'the owner' : role === 'staff' ? 'AsyncAnalyzer staff' : 'a moderator'} here.</p>
    <div class="tabs">${tab(base, 'Scans')}${tab(base + '/team', 'Team')}${tab(base + '/setup', 'Setup')}</div>
  </div>`;
}

// ---- one scan ------------------------------------------------------------
// The dashboard and the public share link show the same verdict from the same
// renderer. A shared result that is laid out differently from the internal one is
// a result somebody will argue is a different result.

function findings(list, title) {
  if (!list || !list.length) return '';
  return `<h3 style="margin:32px 0 14px">${title}</h3>` + list.map(m => {
    const b = band(m.verdict);
    const score = Number(m.score) || 0;
    return `<div class="finding" style="--band:${b.color}">
      <div class="finding-head">
        <b>${esc(m.name || 'unnamed jar')}</b>
        <span class="chip ${b.cls}">${esc(m.verdict || b.word)}</span>
        <span class="score num">${score}<span class="muted tiny">/100</span></span>
      </div>
      <div class="meter"><i style="width:${Math.max(0, Math.min(100, score))}%"></i></div>
      ${(m.reasons && m.reasons.length) ? `<ul class="reasons">${m.reasons.map(r => `<li>${esc(r)}</li>`).join('')}</ul>` : ''}
    </div>`;
  }).join('');
}

export function renderScan(s, opts = {}) {
  const b = band(s.verdict);
  const sess = s.session;
  const sb = sess ? band(sess.band) : null;
  const t = s.totals || {};

  const meta = [
    fmtDate(s.serverTs),
    s.scanner ? 'run by ' + esc(s.scanner) : '',
    s.toolVersion ? 'tool v' + esc(s.toolVersion) : '',
    opts.redacted ? '' : (s.pcName ? 'PC ' + esc(s.pcName) : ''),
  ].filter(Boolean).join(' · ');

  return `
  <div class="page-head">
    <div class="crumb">${opts.crumb || ''}</div>
    <h1>${esc(s.targetUser || 'Unknown player')}</h1>
    <div class="btn-row" style="margin-top:14px;align-items:center">
      <span class="chip ${b.cls}">${esc(s.verdict || b.word)}</span>
      ${s.scanId ? `<span class="chip chip-flat mono">Scan ${esc(s.scanId)}</span>` : ''}
      ${s.scanCode && !opts.redacted ? `<span class="chip chip-flat mono">Code ${esc(s.scanCode)}</span>` : ''}
    </div>
    <p class="muted small" style="margin-top:10px">${meta}</p>
    ${opts.actions || ''}
  </div>

  ${sess ? `<div class="finding reveal" style="--band:${sb.color};padding:22px">
    <div class="finding-head">
      <span class="chip ${sb.cls}">Overall verdict</span>
      <b style="font-family:inherit">${esc(sess.band || '')}</b>
      <span class="score num">${Number(sess.score) || 0}<span class="muted tiny">/100</span></span>
    </div>
    <div class="meter"><i style="width:${Math.max(0, Math.min(100, Number(sess.score) || 0))}%"></i></div>
    <p class="muted small" style="margin-top:12px">Judged on the whole scan — mods, system checks, processes, JVM and history — not one file at a time.</p>
    ${(sess.reasons && sess.reasons.length) ? `<ul class="reasons">${sess.reasons.map(r => `<li>${esc(r)}</li>`).join('')}</ul>` : ''}
  </div>` : ''}

  <div class="stats" style="margin-top:44px">
    <div class="stat"><b class="num">${t.total != null ? t.total : (t.scanned != null ? t.scanned : '—')}</b><span>Mods scanned</span></div>
    <div class="stat"><b class="num">${(s.flagged || []).length}</b><span>Flagged</span></div>
    <div class="stat"><b class="num">${(s.review || []).length}</b><span>Worth a look</span></div>
    ${opts.redacted ? '' : `<div class="stat"><b class="num">${(s.systemIssues || []).length}</b><span>System notes</span></div>`}
  </div>

  ${findings(s.flagged, 'Flagged')}
  ${findings(s.review, 'Worth a look')}

  ${(!opts.redacted && s.systemIssues && s.systemIssues.length) ? `
    <h3 style="margin:32px 0 14px">System notes</h3>
    <div class="panel"><ul class="reasons" style="margin:0">${s.systemIssues.map(i =>
      `<li>${esc(typeof i === 'string' ? i : (i.text || i.message || JSON.stringify(i)))}</li>`).join('')}</ul></div>` : ''}

  ${(!opts.redacted && s.modPath) ? `<p class="muted tiny mono" style="margin-top:26px">${esc(s.modPath)}</p>` : ''}
  ${(!(s.flagged || []).length && !(s.review || []).length) ? '<div class="empty"><h3>Nothing was flagged</h3><p>Every mod on this install checked out.</p></div>' : ''}`;
}

// ---- copy-to-clipboard ---------------------------------------------------

export function wireCopy(root = document) {
  $$('[data-copy]', root).forEach(btn => {
    btn.addEventListener('click', async () => {
      const text = btn.dataset.copy || ($(btn.dataset.copyFrom, root) || {}).textContent || '';
      try {
        await navigator.clipboard.writeText(text.trim());
        const old = btn.textContent;
        btn.textContent = 'Copied';
        setTimeout(() => { btn.textContent = old; }, 1400);
      } catch {
        toast('Your browser blocked the clipboard — select the text and copy it.', true);
      }
    });
  });
}

// Every page ends with this so nothing has to remember the boilerplate.
export function boot(fn) {
  const run = async () => {
    mountNav();
    try { if (fn) await fn(); } catch (e) { toast(e.message || 'Something went wrong.', true); }
    reveal();
    wireCopy();
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', run);
  else run();
}
