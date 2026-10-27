const API = '/api';
const $ = (id) => document.getElementById(id);
let vaultKey = null;
let vaultSalt = null;
let vaultUnlocked = false;
let currentUser = null;
let registrationEnabled = true;

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let n = bytes / 1024, i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(1)} ${units[i]}`;
}
function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function setStatus(id, message, isError = false) {
  const el = $(id); if (!el) return;
  el.textContent = message;
  el.classList.toggle('is-error', isError);
}
function showAuthDialog(message = '') {
  const dialog = $('auth-dialog');
  if (message) setStatus('auth-status', message, true);
  if (dialog && !dialog.open) dialog.showModal();
}
async function api(path, options = {}) {
  const method = (options.method || 'GET').toUpperCase();
  const headers = new Headers(options.headers || {});
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) headers.set('X-Nova-Request', '1');
  const response = await fetch(`${API}${path}`, { ...options, headers, credentials: 'same-origin' });
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try { message = (await response.json()).detail || message; } catch {}
    const error = new Error(message); error.status = response.status;
    if (response.status === 401 && !path.startsWith('/auth/')) showAuthDialog('Your session has expired. Please sign in again.');
    throw error;
  }
  if (response.status === 204) return null;
  const type = response.headers.get('content-type') || '';
  return type.includes('application/json') ? response.json() : response;
}
function openDialog(name) {
  if (!currentUser) { showAuthDialog('Sign in to open your private workspace.'); return; }
  const dialog = $(`${name}-dialog`);
  if (dialog && !dialog.open) dialog.showModal();
  if (name === 'cloud') loadFiles();
  if (name === 'vault') loadVaultSalt().catch(e => setStatus('vault-status', e.message, true));
}
document.querySelectorAll('[data-open]').forEach(el => el.addEventListener('click', (event) => {
  event.preventDefault(); openDialog(el.dataset.open);
}));
document.querySelectorAll('[data-close]').forEach(el => el.addEventListener('click', () => el.closest('dialog').close()));
document.querySelectorAll('dialog').forEach(dialog => dialog.addEventListener('click', (e) => {
  if (dialog.id !== 'auth-dialog' && e.target === dialog) dialog.close();
}));
$('signin-button').addEventListener('click', () => showAuthDialog());

function switchAuthTab(tab) {
  const login = tab === 'login';
  $('login-form').hidden = !login;
  $('register-form').hidden = login;
  $('show-login').classList.toggle('is-active', login);
  $('show-register').classList.toggle('is-active', !login);
  $('show-login').setAttribute('aria-selected', String(login));
  $('show-register').setAttribute('aria-selected', String(!login));
  setStatus('auth-status', '');
}
$('show-login').addEventListener('click', () => switchAuthTab('login'));
$('show-register').addEventListener('click', () => switchAuthTab('register'));

function setSignedIn(user) {
  currentUser = user;
  $('account-name').textContent = user.display_name;
  $('account-name').hidden = false;
  $('logout-button').hidden = false;
  $('signin-button').hidden = true;
  if ($('auth-dialog').open) $('auth-dialog').close();
  loadStatus();
}
$('login-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  setStatus('auth-status', 'Signing in…');
  const payload = { email: $('login-email').value.trim(), password: $('login-password').value };
  try {
    await api('/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
    $('login-password').value = '';
    const user = await api('/me'); setSignedIn(user);
  } catch (e) { setStatus('auth-status', e.message, true); }
});
$('register-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  setStatus('auth-status', 'Creating your account…');
  const payload = {
    display_name: $('register-name').value.trim(),
    email: $('register-email').value.trim(),
    password: $('register-password').value
  };
  try {
    await api('/auth/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
    $('register-password').value = '';
    const user = await api('/me'); setSignedIn(user);
  } catch (e) { setStatus('auth-status', e.message, true); }
});
$('logout-button').addEventListener('click', async () => {
  try { await api('/auth/logout', { method: 'POST' }); } catch {}
  currentUser = null; vaultKey = null; vaultSalt = null; vaultUnlocked = false;
  $('account-name').hidden = true; $('logout-button').hidden = true; $('signin-button').hidden = false;
  $('vault-form').hidden = true; $('vault-list').innerHTML = '<p class="empty-state">Vault is locked.</p>';
  setStatus('system-state', 'system.locked'); showAuthDialog('You have been signed out.');
});

function tick() {
  if ($('clock')) $('clock').textContent = new Date().toLocaleTimeString();
  if ($('year')) $('year').textContent = new Date().getFullYear();
}
tick(); setInterval(tick, 1000);

async function loadStatus() {
  if (!currentUser) return;
  try {
    const status = await api('/status');
    $('system-state').textContent = 'system.online';
    $('storage-value').innerHTML = `${formatBytes(status.storage_used)} <em>/ ${formatBytes(status.storage_limit)}</em>`;
    $('storage-bar').style.width = `${Math.min(100, status.storage_used / status.storage_limit * 100)}%`;
    $('uptime-value').textContent = status.uptime;
    $('sync-value').textContent = 'Just now';
  } catch {
    $('system-state').textContent = 'system.offline';
    $('storage-value').textContent = 'API unavailable';
    $('uptime-value').textContent = '—';
    $('sync-value').textContent = 'Not connected';
  }
}

async function loadFiles() {
  const tbody = $('file-list'); tbody.innerHTML = '<tr><td colspan="4">Loading files…</td></tr>';
  try {
    const files = await api('/files');
    if (!files.length) { tbody.innerHTML = '<tr><td colspan="4">No files yet. Upload your first file above.</td></tr>'; return; }
    tbody.innerHTML = files.map(file => `<tr><td>${escapeHtml(file.filename)}</td><td>${formatBytes(file.size)}</td><td>${new Date(file.created_at).toLocaleString()}</td><td><button class="mini-button" data-download="${file.id}">Download</button> <button class="mini-button danger" data-delete="${file.id}">Delete</button></td></tr>`).join('');
    tbody.querySelectorAll('[data-download]').forEach(button => button.addEventListener('click', () => downloadFile(button.dataset.download)));
    tbody.querySelectorAll('[data-delete]').forEach(button => button.addEventListener('click', () => deleteFile(button.dataset.delete)));
  } catch (e) { tbody.innerHTML = `<tr><td colspan="4">${escapeHtml(e.message)}</td></tr>`; }
}
$('upload-form').addEventListener('submit', async (event) => {
  event.preventDefault(); const file = $('file-input').files[0]; if (!file) return;
  const form = new FormData(); form.append('file', file);
  setStatus('upload-status', 'Uploading…');
  try { await api('/files', { method: 'POST', body: form }); $('file-input').value = ''; setStatus('upload-status', 'Upload complete.'); await loadFiles(); loadStatus(); }
  catch (e) { setStatus('upload-status', e.message, true); }
});
async function downloadFile(id) {
  try {
    const response = await api(`/files/${encodeURIComponent(id)}/download`);
    const blob = await response.blob();
    const disposition = response.headers.get('content-disposition') || '';
    const match = disposition.match(/filename\*?=(?:UTF-8''|\")?([^;\"]+)/i);
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = match ? decodeURIComponent(match[1].replaceAll('"', '')) : 'download'; a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  } catch (e) { alert(e.message); }
}
async function deleteFile(id) {
  if (!confirm('Delete this file permanently?')) return;
  try { await api(`/files/${encodeURIComponent(id)}`, { method: 'DELETE' }); await loadFiles(); loadStatus(); }
  catch (e) { alert(e.message); }
}

function bytesToBase64(bytes) { return btoa(String.fromCharCode(...new Uint8Array(bytes))); }
function base64ToBytes(value) { return Uint8Array.from(atob(value), c => c.charCodeAt(0)); }
async function loadVaultSalt() {
  const result = await api('/vault/salt'); vaultSalt = base64ToBytes(result.salt);
}
async function deriveVaultKey(passphrase) {
  if (!vaultSalt) await loadVaultSalt();
  const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: vaultSalt, iterations: 310000, hash: 'SHA-256' }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function encryptVaultEntry(entry) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(entry));
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, vaultKey, plaintext);
  return { iv: bytesToBase64(iv), ciphertext: bytesToBase64(encrypted) };
}
async function decryptVaultEntry(record) {
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: base64ToBytes(record.iv) }, vaultKey, base64ToBytes(record.ciphertext));
  return JSON.parse(new TextDecoder().decode(plain));
}
$('unlock-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const passphrase = $('master-passphrase').value;
  if (passphrase.length < 8) { setStatus('vault-status', 'Use at least 8 characters.', true); return; }
  try {
    vaultKey = await deriveVaultKey(passphrase);
    const records = await api('/vault');
    if (records.length) await decryptVaultEntry(records[0]);
    vaultUnlocked = true; $('vault-form').hidden = false; $('master-passphrase').value = '';
    setStatus('vault-status', records.length ? 'Vault unlocked. Entries are encrypted in your browser.' : 'Vault initialized. Remember this passphrase; it cannot be recovered.');
    await renderVault();
  } catch (e) {
    vaultKey = null; vaultUnlocked = false; $('vault-form').hidden = true;
    setStatus('vault-status', e.name === 'OperationError' ? 'Could not decrypt entries. Check your master passphrase.' : e.message, true);
  }
});
async function renderVault() {
  const container = $('vault-list');
  if (!vaultUnlocked) { container.innerHTML = '<p class="empty-state">Vault is locked.</p>'; return; }
  try {
    const records = await api('/vault');
    if (!records.length) { container.innerHTML = '<p class="empty-state">No entries yet. Add your first credential above.</p>'; return; }
    const entries = await Promise.all(records.map(async r => ({ id: r.id, created_at: r.created_at, ...(await decryptVaultEntry(r)) })));
    container.innerHTML = entries.map(entry => `<article class="vault-entry"><div><h3>${escapeHtml(entry.site)}</h3><p>${escapeHtml(entry.username)}</p><p class="vault-secret">${escapeHtml(entry.password)}</p>${entry.notes ? `<p>${escapeHtml(entry.notes)}</p>` : ''}</div><button class="mini-button danger" data-vault-delete="${entry.id}">Delete</button></article>`).join('');
    container.querySelectorAll('[data-vault-delete]').forEach(button => button.addEventListener('click', async () => {
      if (!confirm('Delete this vault entry?')) return;
      try { await api(`/vault/${encodeURIComponent(button.dataset.vaultDelete)}`, { method: 'DELETE' }); await renderVault(); }
      catch (e) { setStatus('vault-status', e.message, true); }
    }));
  } catch (e) { setStatus('vault-status', e.message, true); }
}
$('vault-form').addEventListener('submit', async (event) => {
  event.preventDefault(); if (!vaultUnlocked || !vaultKey) return;
  const entry = { site: $('vault-site').value.trim(), username: $('vault-username').value.trim(), password: $('vault-password').value, notes: $('vault-notes').value.trim() };
  try {
    const encrypted = await encryptVaultEntry(entry);
    await api('/vault', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(encrypted) });
    $('vault-site').value = ''; $('vault-username').value = ''; $('vault-password').value = ''; $('vault-notes').value = '';
    setStatus('vault-status', 'Encrypted entry saved.'); await renderVault();
  } catch (e) { setStatus('vault-status', e.message, true); }
});
$('lock-vault').addEventListener('click', () => {
  vaultKey = null; vaultUnlocked = false; $('vault-form').hidden = true; $('vault-list').innerHTML = '<p class="empty-state">Vault is locked.</p>'; setStatus('vault-status', 'Vault locked.');
});

$('contact-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const body = { name: $('contact-name').value.trim(), email: $('contact-email').value.trim(), subject: $('contact-subject').value.trim(), message: $('contact-message').value.trim() };
  setStatus('contact-status', 'Sending…');
  try { await api('/contact', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }); $('contact-form').reset(); setStatus('contact-status', 'Message saved successfully. Email delivery is not configured.'); }
  catch (e) { setStatus('contact-status', e.message, true); }
});

async function initializeApp() {
  try {
    const config = await api('/auth/config');
    registrationEnabled = config.registration_enabled;
    if (!registrationEnabled) $('show-register').hidden = true;
    const user = await api('/me');
    setSignedIn(user);
  } catch (e) {
    if (e.status === 401) showAuthDialog();
    else { setStatus('system-state', 'system.offline'); showAuthDialog('Could not connect to Nova. Check that the backend is running.'); }
  }
}
initializeApp();
