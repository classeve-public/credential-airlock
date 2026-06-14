/*
 * Credential Airlock — control-plane SPA.
 *
 * Self-contained, offline, CSP-friendly: no external resources, no inline event
 * handlers. Talks only to the loopback admin server.
 *
 * Auth bootstrap: the launch URL carries ?token=XXXX. We stash it in
 * sessionStorage and strip it from the address bar, then send it as the
 * `x-airlock-token` header on every /api/* call (and via ?token= for the
 * EventSource stream, which cannot set headers).
 */
'use strict';

/* =========================================================================
 * PRESETS — the single, canonical provider list. Inlined here because the
 * admin server serves only /index.html, /app.js and /style.css (see the STATIC
 * map in src/admin/server.ts), so there is no separate presets file to drift.
 * ========================================================================= */
const PRESETS = [
  {
    id: 'openai',
    label: 'OpenAI',
    hosts: ['api.openai.com'],
    placeholder: '__OPENAI_KEY__',
    injection: { mode: 'header', header: 'Authorization', valueTemplate: 'Bearer {{secret}}' },
    docs: 'https://platform.openai.com/docs/api-reference/authentication',
    note: 'Standard Bearer token in the Authorization header.',
  },
  {
    id: 'anthropic',
    label: 'Anthropic',
    hosts: ['api.anthropic.com'],
    placeholder: '__ANTHROPIC_KEY__',
    injection: { mode: 'header', header: 'x-api-key', valueTemplate: '{{secret}}' },
    docs: 'https://docs.anthropic.com/en/api/getting-started',
    note: 'Anthropic uses the raw key in the x-api-key header (no "Bearer " prefix).',
  },
  {
    id: 'stripe',
    label: 'Stripe',
    hosts: ['api.stripe.com'],
    placeholder: '__STRIPE_KEY__',
    injection: { mode: 'header', header: 'Authorization', valueTemplate: 'Bearer {{secret}}' },
    docs: 'https://stripe.com/docs/api/authentication',
    note: 'Money mover. Add an amountLimit rule on field "amount" in Policy to cap charges.',
    suggestAmountField: 'amount',
  },
  {
    id: 'github',
    label: 'GitHub',
    hosts: ['api.github.com'],
    placeholder: '__GITHUB_TOKEN__',
    injection: { mode: 'header', header: 'Authorization', valueTemplate: 'Bearer {{secret}}' },
    docs: 'https://docs.github.com/en/rest/authentication',
    note: 'Fine-grained PAT or classic token as a Bearer credential.',
  },
  {
    id: 'cloudflare',
    label: 'Cloudflare',
    hosts: ['api.cloudflare.com'],
    placeholder: '__CLOUDFLARE_TOKEN__',
    injection: { mode: 'header', header: 'Authorization', valueTemplate: 'Bearer {{secret}}' },
    docs: 'https://developers.cloudflare.com/fundamentals/api/get-started/create-token/',
    note: 'Use an API Token (not the legacy Global API Key) as a Bearer credential.',
  },
  {
    id: 'sendgrid',
    label: 'SendGrid',
    hosts: ['api.sendgrid.com'],
    placeholder: '__SENDGRID_KEY__',
    injection: { mode: 'header', header: 'Authorization', valueTemplate: 'Bearer {{secret}}' },
    docs: 'https://docs.sendgrid.com/api-reference/how-to-use-the-sendgrid-v3-api/authentication',
    note: 'Bearer token in the Authorization header.',
  },
  {
    id: 'slack',
    label: 'Slack',
    hosts: ['slack.com', 'api.slack.com'],
    placeholder: '__SLACK_TOKEN__',
    injection: { mode: 'header', header: 'Authorization', valueTemplate: 'Bearer {{secret}}' },
    docs: 'https://api.slack.com/authentication/token-types',
    note: 'Bot/user token (xoxb-/xoxp-) as a Bearer credential.',
  },
  {
    id: 'gemini',
    label: 'Google Gemini',
    hosts: ['generativelanguage.googleapis.com'],
    placeholder: '__GEMINI_KEY__',
    injection: { mode: 'query', queryParam: 'key' },
    docs: 'https://ai.google.dev/gemini-api/docs/api-key',
    note: 'Gemini takes the API key as a ?key= query parameter, not a header.',
  },
  {
    id: 'notion',
    label: 'Notion',
    hosts: ['api.notion.com'],
    placeholder: '__NOTION_TOKEN__',
    injection: { mode: 'header', header: 'Authorization', valueTemplate: 'Bearer {{secret}}' },
    docs: 'https://developers.notion.com/reference/authentication',
    note: 'Integration token as a Bearer credential. (Also set a Notion-Version header in your client.)',
  },
  {
    id: 'twilio',
    label: 'Twilio',
    hosts: ['api.twilio.com'],
    placeholder: '__TWILIO_AUTH__',
    injection: { mode: 'header', header: 'Authorization', valueTemplate: 'Basic {{secret}}' },
    docs: 'https://www.twilio.com/docs/usage/api',
    note: 'HTTP Basic auth: store the base64 of "AccountSID:AuthToken" as the secret value.',
  },
];

/* =========================================================================
 * Auth + API client
 * ========================================================================= */
const TOKEN_KEY = 'airlock_token';

function bootstrapToken() {
  try {
    const params = new URLSearchParams(location.search);
    const fromQuery = params.get('token');
    if (fromQuery) {
      sessionStorage.setItem(TOKEN_KEY, fromQuery);
      // Strip the token from the address bar / history without reloading.
      params.delete('token');
      const clean = location.pathname + (params.toString() ? '?' + params.toString() : '') + location.hash;
      history.replaceState(null, '', clean);
    }
  } catch (_) { /* sessionStorage may be unavailable; tolerate it */ }
  return getToken();
}

function getToken() {
  try { return sessionStorage.getItem(TOKEN_KEY) || ''; } catch (_) { return ''; }
}

let UNAUTHORIZED = false;

/** Thrown for non-2xx responses; carries status + parsed body. */
class ApiError extends Error {
  constructor(status, message, body) {
    super(message);
    this.status = status;
    this.body = body;
  }
}

async function api(path, opts = {}) {
  const token = getToken();
  const headers = Object.assign({ 'x-airlock-token': token }, opts.headers || {});
  let body = opts.body;
  if (body !== undefined && typeof body !== 'string') {
    headers['content-type'] = 'application/json';
    body = JSON.stringify(body);
  }
  let res;
  try {
    res = await fetch(path, {
      method: opts.method || 'GET',
      headers,
      body,
      credentials: 'same-origin',
      cache: 'no-store',
    });
  } catch (e) {
    // Network-level failure (server down, connection reset, etc.).
    throw new ApiError(0, 'Cannot reach the control plane. Is the airlock process still running?', null);
  }
  let data = null;
  const text = await res.text();
  if (text) { try { data = JSON.parse(text); } catch (_) { data = text; } }
  if (res.status === 401) {
    showAuthGate();
    throw new ApiError(401, 'unauthorized', data);
  }
  if (!res.ok) {
    const msg = (data && data.error) ? data.error : ('HTTP ' + res.status);
    throw new ApiError(res.status, msg, data);
  }
  clearAuthGate();
  return data;
}

/* =========================================================================
 * Tiny DOM helpers (no innerHTML for untrusted data)
 * ========================================================================= */
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null) continue;
    if (k === 'class') node.className = v;
    else if (k === 'text') node.textContent = v;
    else if (k === 'html') node.innerHTML = v; // only used with static, trusted strings
    else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2), v);
    else if (k === 'hidden') { if (v) node.hidden = true; }
    else node.setAttribute(k, v);
  }
  const kids = Array.isArray(children) ? children : [children];
  for (const c of kids) {
    if (c == null || c === false) continue;
    node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
  }
  return node;
}

function icon(id) {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
  use.setAttribute('href', '#' + id);
  svg.appendChild(use);
  return svg;
}

function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

function fmtTime(ts) {
  if (!ts) return '';
  const d = new Date(ts);
  if (isNaN(d.getTime())) return String(ts);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}
function fmtDateTime(ts) {
  if (!ts) return '';
  const d = new Date(ts);
  if (isNaN(d.getTime())) return String(ts);
  return d.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

/* =========================================================================
 * Toasts, auth gate, copy, modals
 * ========================================================================= */
function toast(message, kind = 'info', title = '') {
  const root = $('#toasts');
  const t = el('div', { class: 'toast ' + kind }, [
    title ? el('div', { class: 't-title', text: title }) : null,
    el('div', { text: message }),
  ]);
  root.appendChild(t);
  setTimeout(() => { t.style.opacity = '0'; setTimeout(() => t.remove(), 250); }, kind === 'error' ? 6500 : 3800);
}

/** Centralized error reporter — never lets a rejection crash the page. */
function reportError(e, context) {
  if (e instanceof ApiError && e.status === 401) return; // gate already shown
  const msg = (e && e.message) ? e.message : String(e);
  toast(msg, 'error', context || 'Error');
  // eslint-disable-next-line no-console
  console.error('[airlock]', context || '', e);
}

function showAuthGate() {
  UNAUTHORIZED = true;
  const g = $('#authGate');
  if (g) g.hidden = false;
}
function clearAuthGate() {
  if (!UNAUTHORIZED) return;
  UNAUTHORIZED = false;
  const g = $('#authGate');
  if (g) g.hidden = true;
}

async function copyText(text, okMsg = 'Copied') {
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      const ta = el('textarea', {}, []);
      ta.value = text;
      ta.style.position = 'fixed'; ta.style.opacity = '0';
      document.body.appendChild(ta); ta.select();
      document.execCommand('copy');
      ta.remove();
    }
    toast(okMsg, 'success');
  } catch (_) {
    toast('Copy failed — select and copy manually.', 'error');
  }
}

/** Promise-based modal. type: 'confirm' | 'prompt'. Returns value|true or null. */
function modal({ title, message, type = 'confirm', okText = 'OK', danger = false, placeholder = '', inputType = 'text' }) {
  return new Promise((resolve) => {
    const root = $('#modalRoot');
    let input = null;
    if (type === 'prompt') {
      input = el('input', { type: inputType, placeholder: placeholder, id: 'modalInput', autocomplete: 'new-password' });
    }
    const finish = (val) => { clear(root); root.hidden = true; document.removeEventListener('keydown', onKey); resolve(val); };
    const onOk = () => {
      if (type === 'prompt') {
        const v = input.value;
        if (!v) { input.focus(); return; }
        finish(v);
      } else finish(true);
    };
    const onKey = (ev) => {
      if (ev.key === 'Escape') finish(null);
      if (ev.key === 'Enter' && type === 'prompt') onOk();
    };
    const box = el('div', { class: 'modal' }, [
      el('h3', { text: title }),
      message ? el('p', { text: message }) : null,
      input,
      el('div', { class: 'modal-actions' }, [
        el('button', { class: 'btn', onclick: () => finish(null) }, 'Cancel'),
        el('button', { class: 'btn ' + (danger ? 'danger' : 'primary'), onclick: onOk }, okText),
      ]),
    ]);
    clear(root);
    root.appendChild(box);
    root.hidden = false;
    document.addEventListener('keydown', onKey);
    if (input) input.focus();
  });
}
function confirmDanger(title, message, okText = 'Confirm') {
  return modal({ title, message, type: 'confirm', okText, danger: true });
}

/* =========================================================================
 * App state + navigation
 * ========================================================================= */
const state = {
  status: null,
  proxyBusy: false,
  currentView: 'dashboard',
  audit: [],          // newest-first
  auditSeen: new Set(),
  approvals: { pending: [], recent: [] },
  agentRuntimes: {},  // id -> runtime (live overlay from SSE)
  openLogs: new Set(),
  countdownTimer: null,
};

const VIEW_TITLES = {
  dashboard: 'Dashboard', secrets: 'Secrets', policy: 'Policy',
  audit: 'Audit', approvals: 'Approvals', agents: 'Agents', migration: 'Migration',
};

function showView(view) {
  state.currentView = view;
  $$('.view').forEach((s) => { s.hidden = s.getAttribute('data-view') !== view; });
  $$('.nav-item').forEach((b) => b.classList.toggle('active', b.getAttribute('data-view') === view));
  const title = VIEW_TITLES[view] || 'Airlock';
  $('#viewTitle').textContent = title;
  $('.sidebar').classList.remove('open');
  // Lazy refreshers per view.
  if (view === 'audit') loadAudit().catch((e) => reportError(e, 'Audit'));
  if (view === 'approvals') loadApprovals().catch((e) => reportError(e, 'Approvals'));
  if (view === 'policy') renderPolicyEditor();
  if (view === 'agents') renderAgents();
  if (view === 'secrets') renderSecrets();
  if (view === 'migration') renderMigration();
}

/* =========================================================================
 * Status / Dashboard
 * ========================================================================= */
async function loadStatus() {
  const s = await api('/api/status');
  state.status = s;
  renderDashboard();
  renderMasterToggle();
  renderNavCounts();
  // Keep dependent views fresh if visible.
  if (state.currentView === 'secrets') renderSecrets();
  if (state.currentView === 'agents') renderAgents();
  if (state.currentView === 'migration') renderMigration();
  if (state.currentView === 'policy' && !policyDirty) renderPolicyEditor();
}

function setSwitch(node, on, busy) {
  node.setAttribute('aria-checked', on ? 'true' : 'false');
  node.classList.toggle('busy', !!busy);
}

function renderMasterToggle() {
  const on = !!(state.status && state.status.proxyRunning);
  const master = $('#masterToggle');
  setSwitch(master, on, state.proxyBusy);
  $('.master').classList.toggle('on', on);
  $('#masterState').textContent = state.proxyBusy ? '…' : (on ? 'on' : 'off');
  const big = $('#bigToggle');
  if (big) setSwitch(big, on, state.proxyBusy);
}

function renderDashboard() {
  const s = state.status;
  if (!s) return;
  const on = !!s.proxyRunning;
  $('#heroState').textContent = on ? 'Airlock is ARMED' : 'Airlock is OFF';
  $('#heroSub').textContent = on
    ? 'Traffic from launched agents is intercepted, policy-checked, and credential-injected.'
    : 'Agents cannot reach the network until the airlock is armed.';
  $('.hero').classList.toggle('armed', on);

  const proxyUrl = s.proxy ? `http://${s.proxy.host}:${s.proxy.port}` : '—';
  $('#proxyUrl').textContent = proxyUrl;

  // Sealer
  const sealer = s.sealer || {};
  $('#sealerKind').textContent = sealer.kind ? sealer.kind.toUpperCase() : '—';
  $('#sealerDesc').textContent = sealer.description || '';
  const warn = $('#sealerWarn');
  if (sealer && sealer.hardware === false) {
    warn.hidden = false;
    clear(warn);
    warn.appendChild(icon('i-warn'));
    warn.appendChild(document.createTextNode(' OS-bound (DPAPI), not hardware TPM — see docs.'));
  } else {
    warn.hidden = true;
  }

  // Counts
  $('#statSecrets').textContent = s.secretsCount != null ? s.secretsCount : (s.secrets ? s.secrets.length : 0);
  const agents = s.agents || [];
  $('#statAgents').textContent = agents.length;
  const running = agents.filter((a) => a.runtime && a.runtime.status === 'running').length;
  $('#statAgentsSub').textContent = running ? `${running} running` : 'registered';

  // Audit chain
  const auditPill = $('#statAudit');
  const a = s.audit || {};
  clear(auditPill);
  if (a.ok) {
    auditPill.appendChild(el('span', { class: 'pill ok' }, [icon('i-check'), 'verified']));
    $('#statAuditSub').textContent = (a.entries != null ? a.entries : 0) + ' entries, intact';
  } else {
    auditPill.appendChild(el('span', { class: 'pill bad' }, [icon('i-warn'), 'BROKEN at #' + (a.brokenAt != null ? a.brokenAt : '?')]));
    $('#statAuditSub').textContent = 'tamper detected';
  }

  // Migration
  const migPill = $('#statMigration');
  clear(migPill);
  migPill.appendChild(s.migrationConfigured
    ? el('span', { class: 'pill ok' }, 'configured')
    : el('span', { class: 'pill neutral' }, 'not set up'));

  $('#caPath').textContent = s.caCertPath ? ('(' + s.caCertPath + ')') : '';
}

function renderNavCounts() {
  const s = state.status;
  if (!s) return;
  $('#navSecrets').textContent = s.secretsCount != null ? s.secretsCount : '';
  $('#navAgents').textContent = (s.agents && s.agents.length) ? s.agents.length : '';
  renderApprovalsBadge();
}

function renderApprovalsBadge() {
  const badge = $('#navApprovals');
  const n = state.approvals.pending.length;
  if (n > 0) { badge.hidden = false; badge.textContent = String(n); }
  else { badge.hidden = true; }
}

/* ---- Master toggle behavior ---- */
async function toggleProxy() {
  if (state.proxyBusy) return;
  const on = !!(state.status && state.status.proxyRunning);
  if (on) {
    const ok = await confirmDanger(
      'Disarm the Airlock?',
      'Stopping the airlock cuts off all agent network access and credential injection. Running agents will lose connectivity.',
      'Stop airlock'
    );
    if (!ok) return;
  }
  state.proxyBusy = true;
  renderMasterToggle();
  try {
    const r = await api(on ? '/api/proxy/stop' : '/api/proxy/start', { method: 'POST' });
    if (state.status) state.status.proxyRunning = !!r.running;
    toast(on ? 'Airlock disarmed.' : 'Airlock armed.', 'success');
  } catch (e) {
    reportError(e, 'Proxy');
  } finally {
    state.proxyBusy = false;
    await loadStatus().catch(() => {});
    renderMasterToggle();
  }
}

/* =========================================================================
 * Secrets
 * ========================================================================= */
function modeLabel(inj) {
  if (!inj) return '—';
  if (inj.mode === 'header') return `header (${inj.header || '?'})`;
  if (inj.mode === 'query') return `query (${inj.queryParam || '?'})`;
  return 'placeholder';
}

function renderSecrets() {
  const body = $('#secretsBody');
  const secrets = (state.status && state.status.secrets) || [];
  clear(body);
  if (!secrets.length) {
    body.appendChild(el('tr', {}, el('td', { colspan: '6', class: 'empty' }, 'No secrets yet. Add one on the right.')));
    return;
  }
  for (const sec of secrets) {
    const hostTags = el('span', {}, (sec.allowedHosts || []).map((h) => el('span', { class: 'tag', text: h })));
    const actions = el('div', { class: 'row-actions' }, [
      el('button', { class: 'btn sm', title: 'Rotate value', onclick: () => rotateSecret(sec.name) }, 'Rotate'),
      el('button', { class: 'btn sm danger', title: 'Delete secret', onclick: () => deleteSecret(sec.name) }, [icon('i-trash')]),
    ]);
    body.appendChild(el('tr', {}, [
      el('td', {}, el('strong', { text: sec.name })),
      el('td', { text: modeLabel(sec.injection) }),
      el('td', {}, hostTags),
      el('td', {}, el('code', { text: sec.placeholder || '' })),
      el('td', { class: 'muted', text: fmtDateTime(sec.updatedAt || sec.createdAt) }),
      el('td', {}, actions),
    ]));
  }
}

function syncModeFields() {
  const mode = $('#sMode').value;
  $$('.mode-fields', $('#secretForm')).forEach((g) => { g.hidden = g.getAttribute('data-mode') !== mode; });
}

function applyPreset(id) {
  const note = $('#presetNote');
  const p = PRESETS.find((x) => x.id === id);
  if (!p) { note.hidden = true; return; }
  $('#sName').value = p.placeholder ? p.placeholder.replace(/^__|__$/g, '') : p.label.toUpperCase();
  $('#sHosts').value = (p.hosts || []).join(', ');
  $('#sMode').value = p.injection.mode;
  syncModeFields();
  if (p.injection.mode === 'header') {
    $('#sHeader').value = p.injection.header || '';
    $('#sTemplate').value = p.injection.valueTemplate || '{{secret}}';
  } else if (p.injection.mode === 'query') {
    $('#sQueryParam').value = p.injection.queryParam || '';
  } else {
    $('#sPlaceholder').value = p.placeholder || '';
  }
  // Show helpful note (+ amount-limit hint where relevant).
  let txt = p.note || '';
  if (p.suggestAmountField) txt += ` Tip: in Policy, add amountLimit { field:"${p.suggestAmountField}", max:… } to cap spend.`;
  note.textContent = txt;
  note.hidden = !txt;
}

function buildInjection() {
  const mode = $('#sMode').value;
  if (mode === 'header') {
    return { mode: 'header', header: ($('#sHeader').value || '').trim() || 'Authorization', valueTemplate: ($('#sTemplate').value || '').trim() || '{{secret}}' };
  }
  if (mode === 'query') {
    return { mode: 'query', queryParam: ($('#sQueryParam').value || '').trim() || 'key' };
  }
  const inj = { mode: 'placeholder' };
  const ph = ($('#sPlaceholder').value || '').trim();
  if (ph) inj.placeholder = ph;
  if ($('#sInjectBody').checked) inj.injectInBody = true;
  return inj;
}

async function submitSecret(ev) {
  ev.preventDefault();
  const name = $('#sName').value.trim();
  const value = $('#sValue').value;
  const hosts = $('#sHosts').value.split(',').map((h) => h.trim()).filter(Boolean);
  if (!name || !value || !hosts.length) { toast('Name, value and at least one host are required.', 'error'); return; }
  const injection = buildInjection();
  const placeholder = injection.placeholder || ('__' + name.toUpperCase() + '__');
  const desc = $('#sDesc').value.trim();
  const payload = { name, value, allowedHosts: hosts, injection, placeholder };
  if (desc) payload.description = desc;
  try {
    await api('/api/secrets', { method: 'POST', body: payload });
    toast(`Secret '${name}' saved (write-only).`, 'success');
    $('#secretForm').reset();
    $('#presetNote').hidden = true;
    syncModeFields();
    await loadStatus();
  } catch (e) { reportError(e, 'Save secret'); }
}

async function rotateSecret(name) {
  const value = await modal({ title: `Rotate '${name}'`, message: 'Enter the new value. It is write-only and will replace the current one.', type: 'prompt', okText: 'Rotate', placeholder: 'new value', inputType: 'password' });
  if (!value) return;
  try {
    await api(`/api/secrets/${encodeURIComponent(name)}/rotate`, { method: 'POST', body: { value } });
    toast(`Secret '${name}' rotated.`, 'success');
    await loadStatus();
  } catch (e) { reportError(e, 'Rotate'); }
}

async function deleteSecret(name) {
  const ok = await confirmDanger(`Delete '${name}'?`, 'This removes the secret and its auto-generated allow rule. This cannot be undone.', 'Delete');
  if (!ok) return;
  try {
    await api(`/api/secrets/${encodeURIComponent(name)}`, { method: 'DELETE' });
    toast(`Secret '${name}' deleted.`, 'success');
    await loadStatus();
  } catch (e) { reportError(e, 'Delete'); }
}

/* =========================================================================
 * Policy
 * ========================================================================= */
let policyDirty = false;

function renderPolicyEditor() {
  const ta = $('#policyText');
  if (policyDirty && ta.value) { renderPolicySummary(safeParse(ta.value)); return; }
  const p = (state.status && state.status.policy) || { defaultAction: 'deny', egressAllowlist: [], rules: [] };
  ta.value = JSON.stringify(p, null, 2);
  policyDirty = false;
  $('#policyErr').hidden = true;
  renderPolicySummary(p);
}

function safeParse(s) { try { return JSON.parse(s); } catch (_) { return null; } }

function renderPolicySummary(p) {
  const box = $('#policySummary');
  clear(box);
  if (!p) return;
  box.appendChild(el('span', { class: 'pill neutral' }, `default: ${p.defaultAction || 'deny'}`));
  box.appendChild(el('span', { class: 'pill neutral' }, `${(p.egressAllowlist || []).length} egress hosts`));
  box.appendChild(el('span', { class: 'pill neutral' }, `${(p.rules || []).length} rules`));
  const reqApproval = (p.rules || []).filter((r) => r.action === 'require_approval').length;
  if (reqApproval) box.appendChild(el('span', { class: 'pill' }, `${reqApproval} require approval`));
}

async function reloadPolicy() {
  policyDirty = false;
  try { await loadStatus(); } catch (e) { reportError(e, 'Policy'); }
  renderPolicyEditor();
  toast('Policy reloaded from server.', 'success');
}

function formatPolicy() {
  const parsed = safeParse($('#policyText').value);
  if (!parsed) { showPolicyErr('Cannot format: invalid JSON.'); return; }
  $('#policyText').value = JSON.stringify(parsed, null, 2);
  $('#policyErr').hidden = true;
  renderPolicySummary(parsed);
}

function showPolicyErr(msg) { const e = $('#policyErr'); e.textContent = msg; e.hidden = false; }

async function savePolicy() {
  const raw = $('#policyText').value;
  let parsed;
  try { parsed = JSON.parse(raw); }
  catch (e) { showPolicyErr('Invalid JSON: ' + e.message); return; }
  if (typeof parsed !== 'object' || parsed === null || !Array.isArray(parsed.egressAllowlist) || !Array.isArray(parsed.rules)) {
    showPolicyErr('Policy must be an object with array fields "egressAllowlist" and "rules".');
    return;
  }
  $('#policyErr').hidden = true;
  try {
    const r = await api('/api/policy', { method: 'PUT', body: parsed });
    policyDirty = false;
    if (r && r.policy && state.status) state.status.policy = r.policy;
    if (r && r.policy) { $('#policyText').value = JSON.stringify(r.policy, null, 2); renderPolicySummary(r.policy); }
    toast('Policy saved.', 'success');
  } catch (e) {
    showPolicyErr(e.message || 'Save failed.');
    reportError(e, 'Save policy');
  }
}

/* =========================================================================
 * Audit
 * ========================================================================= */
async function loadAudit() {
  const entries = await api('/api/audit?limit=200');
  state.audit = (Array.isArray(entries) ? entries : []).slice().sort((a, b) => b.seq - a.seq);
  state.auditSeen = new Set(state.audit.map((e) => e.seq));
  renderAuditTable();
}

function auditRow(e) {
  const hostPath = el('td', {}, [
    e.host ? el('span', { text: e.host }) : el('span', { class: 'muted', text: '' }),
    e.path ? el('code', { text: ' ' + e.path }) : null,
  ]);
  const injected = (e.injected && e.injected.length)
    ? el('td', {}, e.injected.map((n) => el('span', { class: 'tag', text: n })))
    : el('td', { class: 'muted', text: '' });
  return el('tr', { 'data-seq': e.seq }, [
    el('td', { text: String(e.seq) }),
    el('td', { class: 'muted', text: fmtTime(e.ts) }),
    el('td', {}, el('span', { class: 'tag', text: e.event || '' })),
    el('td', { text: e.method || '' }),
    hostPath,
    el('td', {}, e.decision ? el('span', { class: 'decision ' + e.decision, text: e.decision }) : el('span', { class: 'muted', text: '' })),
    el('td', { class: 'muted', text: e.reason || '' }),
    injected,
  ]);
}

function matchesFilter(e, q) {
  if (!q) return true;
  const hay = [e.seq, e.event, e.method, e.host, e.path, e.decision, e.reason, (e.injected || []).join(' ')].join(' ').toLowerCase();
  return hay.indexOf(q) !== -1;
}

function renderAuditTable() {
  const body = $('#auditBody');
  const q = ($('#auditFilter').value || '').trim().toLowerCase();
  const rows = state.audit.filter((e) => matchesFilter(e, q));
  clear(body);
  if (!rows.length) {
    body.appendChild(el('tr', {}, el('td', { colspan: '8', class: 'empty' }, state.audit.length ? 'No entries match the filter.' : 'No audit entries.')));
    return;
  }
  for (const e of rows) body.appendChild(auditRow(e));
}

/** Live append from SSE (newest first). */
function onAuditEvent(entry) {
  if (!entry || state.auditSeen.has(entry.seq)) return;
  state.auditSeen.add(entry.seq);
  state.audit.unshift(entry);
  if (state.audit.length > 2000) state.audit.length = 2000;
  if (state.currentView === 'audit') {
    const q = ($('#auditFilter').value || '').trim().toLowerCase();
    if (matchesFilter(entry, q)) {
      const body = $('#auditBody');
      const emptyRow = body.querySelector('.empty');
      if (emptyRow) clear(body);
      body.insertBefore(auditRow(entry), body.firstChild);
    }
  }
}

async function verifyAudit() {
  const box = $('#auditVerifyResult');
  clear(box);
  try {
    const r = await api('/api/audit/verify');
    if (r.ok) {
      box.appendChild(el('span', { class: 'pill ok' }, [icon('i-check'), `chain verified · ${r.entries} entries`]));
    } else {
      box.appendChild(el('span', { class: 'pill bad' }, [icon('i-warn'), `BROKEN at #${r.brokenAt}`]));
    }
  } catch (e) { reportError(e, 'Verify'); }
}

/* =========================================================================
 * Approvals
 * ========================================================================= */
async function loadApprovals() {
  const r = await api('/api/approvals');
  state.approvals = { pending: (r && r.pending) || [], recent: (r && r.recent) || [] };
  renderApprovals();
}

function onApprovalsEvent(payload) {
  state.approvals = { pending: (payload && payload.pending) || [], recent: (payload && payload.recent) || [] };
  renderApprovalsBadge();
  if (state.currentView === 'approvals') renderApprovals();
}

function countdownText(expiresAt) {
  const ms = new Date(expiresAt).getTime() - Date.now();
  if (isNaN(ms)) return '';
  if (ms <= 0) return 'expired';
  const s = Math.floor(ms / 1000);
  const m = Math.floor(s / 60);
  return m > 0 ? `${m}m ${s % 60}s left` : `${s}s left`;
}

function renderApprovals() {
  renderApprovalsBadge();
  const list = $('#pendingList');
  clear(list);
  const pending = state.approvals.pending;
  $('#approvalsHint').textContent = pending.length ? `${pending.length} awaiting a human decision` : 'requests awaiting a human decision';
  if (!pending.length) {
    list.appendChild(el('p', { class: 'empty' }, 'Nothing pending.'));
  } else {
    for (const a of pending) {
      const card = el('div', { class: 'approval', 'data-expires': a.expiresAt }, [
        el('h3', { text: a.summary || `${a.method} ${a.host}` }),
        el('div', { class: 'ap-meta', text: `${a.method || ''} ${a.host || ''}${a.path || ''}` }),
        a.amount ? el('div', { class: 'ap-amount', text: `${a.amount.value} ${a.amount.currency || ''} (${a.amount.field})` }) : null,
        el('div', { class: 'ap-count', text: countdownText(a.expiresAt) }),
        el('div', { class: 'ap-actions' }, [
          el('button', { class: 'btn primary sm', onclick: () => decideApproval(a.id, 'approve') }, 'Approve'),
          el('button', { class: 'btn danger sm', onclick: () => decideApproval(a.id, 'deny') }, 'Deny'),
        ]),
      ]);
      list.appendChild(card);
    }
  }

  const rb = $('#recentBody');
  clear(rb);
  const recent = state.approvals.recent;
  if (!recent.length) {
    rb.appendChild(el('tr', {}, el('td', { colspan: '5', class: 'empty' }, 'No recent decisions.')));
  } else {
    for (const a of recent) {
      rb.appendChild(el('tr', {}, [
        el('td', { class: 'muted', text: fmtDateTime(a.ts) }),
        el('td', { text: a.host || '' }),
        el('td', { text: a.method || '' }),
        el('td', { text: a.summary || '' }),
        el('td', {}, el('span', { class: 'decision ' + (a.status === 'approved' ? 'approved' : 'denied'), text: a.status || '' })),
      ]));
    }
  }
}

async function decideApproval(id, action) {
  if (action === 'deny') {
    const ok = await confirmDanger('Deny request?', 'The agent will be told this request was rejected.', 'Deny');
    if (!ok) return;
  }
  try {
    await api(`/api/approvals/${encodeURIComponent(id)}/${action}`, { method: 'POST' });
    toast(action === 'approve' ? 'Approved.' : 'Denied.', 'success');
    await loadApprovals().catch(() => {});
  } catch (e) { reportError(e, 'Approval'); }
}

/** Tick visible countdowns once a second. */
function startCountdowns() {
  if (state.countdownTimer) return;
  state.countdownTimer = setInterval(() => {
    if (state.currentView !== 'approvals') return;
    $$('.approval').forEach((card) => {
      const exp = card.getAttribute('data-expires');
      const c = card.querySelector('.ap-count');
      if (c && exp) c.textContent = countdownText(exp);
    });
  }, 1000);
}

/* =========================================================================
 * Agents
 * ========================================================================= */
function mergedRuntime(a) {
  // SSE pushes only runtime objects keyed by id; overlay them on the profile.
  return state.agentRuntimes[a.id] || a.runtime || { status: 'stopped' };
}

function renderAgents() {
  const list = $('#agentsList');
  clear(list);
  const agents = (state.status && state.status.agents) || [];
  const proxyOn = !!(state.status && state.status.proxyRunning);
  if (!agents.length) {
    list.appendChild(el('p', { class: 'empty' }, 'No agents registered. Add one on the right.'));
    return;
  }
  for (const a of agents) {
    const rt = mergedRuntime(a);
    const running = rt.status === 'running';
    const cmdLine = [a.command].concat(a.args || []).join(' ');

    const toggleBtn = running
      ? el('button', { class: 'btn danger sm', onclick: () => stopAgent(a.id) }, 'Stop')
      : el('button', {
          class: 'btn primary sm',
          disabled: proxyOn ? null : 'true',
          title: proxyOn ? 'Launch this agent' : 'Arm the Airlock first — launch is disabled while the proxy is off',
          onclick: () => launchAgent(a.id),
        }, 'Launch');

    const logsBtn = el('button', { class: 'btn sm', onclick: () => toggleLogs(a.id) }, state.openLogs.has(a.id) ? 'Hide logs' : 'View logs');
    const delBtn = el('button', { class: 'btn sm danger', title: 'Remove agent', onclick: () => removeAgent(a.id, a.name) }, [icon('i-trash')]);

    let statusTxt = rt.status || 'stopped';
    if (rt.status === 'exited' && rt.exitCode != null) statusTxt = `exited (code ${rt.exitCode})`;
    if (rt.status === 'running' && rt.pid) statusTxt = `running · pid ${rt.pid}`;

    const card = el('div', { class: 'agent', 'data-id': a.id }, [
      el('div', { class: 'agent-row' }, [
        el('div', { class: 'agent-name' }, [
          el('span', { class: 'sdot ' + (rt.status || 'stopped') }),
          el('span', { text: a.name }),
        ]),
        el('span', { class: 'agent-status-txt', text: statusTxt }),
        el('div', { class: 'agent-actions' }, [toggleBtn, logsBtn, delBtn]),
      ]),
      el('div', { class: 'agent-cmd', text: cmdLine + (a.cwd ? `   (cwd: ${a.cwd})` : '') }),
      (rt.status === 'error' && rt.lastError) ? el('div', { class: 'agent-err', text: rt.lastError }) : null,
    ]);

    if (state.openLogs.has(a.id)) {
      const pre = el('pre', { class: 'agent-logs', id: 'logs-' + a.id, text: 'loading logs…' });
      card.appendChild(pre);
      loadAgentLogs(a.id);
    }
    list.appendChild(card);
  }
}

async function loadAgentLogs(id) {
  try {
    const r = await api(`/api/agents/${encodeURIComponent(id)}/logs`);
    const pre = $('#logs-' + id);
    if (pre) pre.textContent = (r && r.logs && r.logs.length) ? r.logs.join('\n') : '(no output yet)';
  } catch (e) {
    const pre = $('#logs-' + id);
    if (pre) pre.textContent = 'Failed to load logs: ' + (e.message || e);
  }
}

function toggleLogs(id) {
  if (state.openLogs.has(id)) state.openLogs.delete(id);
  else state.openLogs.add(id);
  renderAgents();
}

async function launchAgent(id) {
  try {
    const r = await api(`/api/agents/${encodeURIComponent(id)}/launch`, { method: 'POST' });
    if (r && r.ok) toast('Agent launched.', 'success');
    else toast(r && r.reason ? r.reason : 'Launch failed.', 'error', 'Launch');
    await loadStatus();
  } catch (e) { reportError(e, 'Launch'); }
}

async function stopAgent(id) {
  const ok = await confirmDanger('Stop agent?', 'The agent process will be terminated.', 'Stop');
  if (!ok) return;
  try {
    await api(`/api/agents/${encodeURIComponent(id)}/stop`, { method: 'POST' });
    toast('Agent stopped.', 'success');
    await loadStatus();
  } catch (e) { reportError(e, 'Stop'); }
}

async function removeAgent(id, name) {
  const ok = await confirmDanger(`Remove '${name}'?`, 'This stops the agent (if running) and removes its profile.', 'Remove');
  if (!ok) return;
  try {
    await api(`/api/agents/${encodeURIComponent(id)}`, { method: 'DELETE' });
    state.openLogs.delete(id);
    delete state.agentRuntimes[id];
    toast('Agent removed.', 'success');
    await loadStatus();
  } catch (e) { reportError(e, 'Remove'); }
}

async function submitAgent(ev) {
  ev.preventDefault();
  const name = $('#aName').value.trim();
  const command = $('#aCommand').value.trim();
  if (!name || !command) { toast('Name and command are required.', 'error'); return; }
  const args = $('#aArgs').value.split('\n').map((s) => s.trim()).filter(Boolean);
  const cwd = $('#aCwd').value.trim();
  const description = $('#aDesc').value.trim();
  const payload = { name, command, args };
  if (cwd) payload.cwd = cwd;
  if (description) payload.description = description;
  try {
    await api('/api/agents', { method: 'POST', body: payload });
    toast(`Agent '${name}' added.`, 'success');
    $('#agentForm').reset();
    await loadStatus();
  } catch (e) { reportError(e, 'Add agent'); }
}

function onAgentsEvent(payload) {
  // payload = { agents: { id -> runtime } }
  if (!payload || !payload.agents) return;
  state.agentRuntimes = payload.agents;
  // Reflect onto the status snapshot so dashboard counts stay live too.
  if (state.status && Array.isArray(state.status.agents)) {
    for (const a of state.status.agents) {
      if (payload.agents[a.id]) a.runtime = payload.agents[a.id];
    }
    renderDashboard();
  }
  if (state.currentView === 'agents') renderAgents();
}

/* =========================================================================
 * Migration
 * ========================================================================= */
function renderMigration() {
  const configured = !!(state.status && state.status.migrationConfigured);
  $('#migrationConfigured').hidden = !configured;
}

async function submitMigration(ev) {
  ev.preventDefault();
  const p1 = $('#mPass').value;
  const p2 = $('#mPass2').value;
  const err = $('#migErr');
  err.hidden = true;
  if (p1.length < 12) { err.textContent = 'Passphrase must be at least 12 characters.'; err.hidden = false; return; }
  if (p1 !== p2) { err.textContent = 'Passphrases do not match.'; err.hidden = false; return; }
  const proceed = await confirmDanger(
    'Set up migration?',
    'This splits the vault key into a 2-of-3 recovery set and re-keys the vault. The offline share will be shown only once.',
    'Set up'
  );
  if (!proceed) return;
  try {
    const r = await api('/api/migration/setup', { method: 'POST', body: { passphrase: p1 } });
    $('#migrationForm').reset();
    revealShare(r && r.offlineShare);
    await loadStatus();
  } catch (e) {
    err.textContent = e.message || 'Setup failed.';
    err.hidden = false;
    reportError(e, 'Migration');
  }
}

function revealShare(share) {
  if (!share) { toast('Setup succeeded but no offline share was returned.', 'error'); return; }
  $('#offlineShare').textContent = share;
  $('#shareReveal').hidden = false;
  $('#shareReveal').scrollIntoView({ behavior: 'smooth', block: 'center' });
}

/* =========================================================================
 * SSE live stream
 * ========================================================================= */
let evtSource = null;

function startSSE() {
  const token = getToken();
  if (!token) return;
  try {
    if (evtSource) { evtSource.close(); evtSource = null; }
    evtSource = new EventSource('/api/events?token=' + encodeURIComponent(token));
    evtSource.addEventListener('open', () => setConn('live', 'live'));
    evtSource.addEventListener('error', () => {
      setConn('lost', 'reconnecting…');
      // EventSource auto-reconnects; nothing else to do.
    });
    evtSource.addEventListener('audit', (e) => { try { onAuditEvent(JSON.parse(e.data)); } catch (_) {} });
    evtSource.addEventListener('approvals', (e) => { try { onApprovalsEvent(JSON.parse(e.data)); } catch (_) {} });
    evtSource.addEventListener('agents', (e) => { try { onAgentsEvent(JSON.parse(e.data)); } catch (_) {} });
  } catch (_) {
    setConn('lost', 'no live feed');
  }
}

function setConn(cls, txt) {
  const c = $('#conn');
  c.classList.remove('live', 'lost');
  if (cls) c.classList.add(cls);
  $('#connTxt').textContent = txt;
}

/* =========================================================================
 * Wiring + boot
 * ========================================================================= */
function wireEvents() {
  // Nav
  $('#nav').addEventListener('click', (e) => {
    const btn = e.target.closest('.nav-item');
    if (btn) showView(btn.getAttribute('data-view'));
  });
  $('#hamburger').addEventListener('click', () => $('.sidebar').classList.toggle('open'));

  // Master toggles
  $('#masterToggle').addEventListener('click', toggleProxy);
  $('#bigToggle').addEventListener('click', toggleProxy);

  // Copy buttons (delegated)
  document.body.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-copy-target]');
    if (!btn) return;
    const target = document.getElementById(btn.getAttribute('data-copy-target'));
    if (target) copyText(target.textContent.trim());
  });

  // Auth gate retry
  $('#authRetry').addEventListener('click', () => { clearAuthGate(); refreshAll(); startSSE(); });

  // Secrets
  $('#presetPick').addEventListener('change', (e) => applyPreset(e.target.value));
  $('#sMode').addEventListener('change', syncModeFields);
  $('#secretForm').addEventListener('submit', submitSecret);

  // Policy
  $('#policyText').addEventListener('input', () => { policyDirty = true; });
  $('#policyReload').addEventListener('click', reloadPolicy);
  $('#policyFormat').addEventListener('click', formatPolicy);
  $('#policySave').addEventListener('click', savePolicy);

  // Audit
  $('#auditFilter').addEventListener('input', renderAuditTable);
  $('#auditVerify').addEventListener('click', verifyAudit);

  // Agents
  $('#agentForm').addEventListener('submit', submitAgent);

  // Migration
  $('#migrationForm').addEventListener('submit', submitMigration);
  $('#shareDone').addEventListener('click', () => { $('#shareReveal').hidden = true; $('#offlineShare').textContent = ''; });
}

function populatePresetPicker() {
  const sel = $('#presetPick');
  for (const p of PRESETS) sel.appendChild(el('option', { value: p.id, text: p.label }));
}

async function refreshAll() {
  try {
    await loadStatus();
    await loadApprovals().catch(() => {}); // for the badge even before opening the view
  } catch (e) {
    reportError(e, 'Status');
  }
}

function startStatusPolling() {
  // Fallback in case SSE drops or the server restarts.
  setInterval(() => {
    if (UNAUTHORIZED) return;
    loadStatus().catch(() => {});
  }, 5000);
}

function boot() {
  bootstrapToken();
  wireEvents();
  populatePresetPicker();
  syncModeFields();
  showView('dashboard');

  if (!getToken()) {
    showAuthGate();
    $('#authGateMsg').textContent = 'No token found. Re-open the control panel using the URL printed in the terminal (it contains the token).';
    return;
  }

  refreshAll();
  startSSE();
  startStatusPolling();
  startCountdowns();
}

// Last-resort guard: surface unexpected errors as a toast instead of a blank page.
window.addEventListener('error', (e) => { try { reportError(e.error || e.message, 'Unexpected'); } catch (_) {} });
window.addEventListener('unhandledrejection', (e) => { try { if (!(e.reason instanceof ApiError && e.reason.status === 401)) reportError(e.reason, 'Unexpected'); } catch (_) {} });

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
else boot();
