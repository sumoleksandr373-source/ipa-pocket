'use strict';

const $ = id => document.getElementById(id);
const loginPanel = $('loginPanel');
const workspace = $('workspace');
const loginForm = $('loginForm');
const loginError = $('loginError');
const uploadForm = $('uploadForm');
const ipaFile = $('ipaFile');
const dropZone = $('dropZone');
const inspectBtn = $('inspectBtn');
const uploadError = $('uploadError');
const resultPanel = $('resultPanel');
const toast = $('toast');
let selectedFile = null;
let currentInstallUrl = '';
let toastTimer = null;

function humanBytes(value) {
  const bytes = Number(value || 0);
  if (bytes < 1024) return `${bytes} Б`;
  const units = ['КБ', 'МБ', 'ГБ', 'ТБ'];
  let size = bytes / 1024;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) { size /= 1024; unit++; }
  return `${size.toLocaleString('ru-RU', { maximumFractionDigits: 1 })} ${units[unit]}`;
}
function showToast(message) {
  toast.textContent = message;
  toast.classList.add('visible');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove('visible'), 2800);
}
function showError(el, message) {
  el.textContent = message || '';
  el.classList.toggle('hidden', !message);
}
async function api(url, options = {}) {
  const response = await fetch(url, { credentials: 'same-origin', ...options });
  const type = response.headers.get('content-type') || '';
  const payload = type.includes('application/json') ? await response.json() : null;
  if (!response.ok) throw new Error(payload?.error || `Ошибка запроса (${response.status}).`);
  return payload;
}
function setAuthenticated(yes) {
  loginPanel.classList.toggle('hidden', yes);
  workspace.classList.toggle('hidden', !yes);
  $('logoutBtn').classList.toggle('hidden', !yes);
}
async function restoreSession() {
  try {
    const state = await api('/api/status');
    setAuthenticated(true);
    $('linkTtl').textContent = `Ссылки до ${state.linkTtlHours} ч.`;
    $('serverStatus').textContent = state.httpsReady ? 'Сервер защищён HTTPS' : 'Сервер работает без HTTPS';
    if (!state.httpsReady) $('serverStatus').style.color = '#f4c46b';
  } catch (_) {
    setAuthenticated(false);
  }
}
loginForm.addEventListener('submit', async event => {
  event.preventDefault();
  showError(loginError, '');
  const button = loginForm.querySelector('button[type="submit"]');
  button.disabled = true;
  try {
    await api('/api/auth', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ accessKey: $('accessKey').value }) });
    $('accessKey').value = '';
    await restoreSession();
  } catch (error) {
    showError(loginError, error.message);
  } finally { button.disabled = false; }
});
$('toggleKey').addEventListener('click', () => {
  const input = $('accessKey');
  const reveal = input.type === 'password';
  input.type = reveal ? 'text' : 'password';
  $('toggleKey').textContent = reveal ? 'Скрыть' : 'Показать';
});
$('logoutBtn').addEventListener('click', async () => {
  try { await api('/api/logout', { method: 'POST' }); } catch (_) {}
  setAuthenticated(false);
  resultPanel.classList.add('hidden');
  showToast('Ты вышел из IPA Pocket.');
});
function displayFile(file) {
  selectedFile = file || null;
  const hasFile = Boolean(selectedFile);
  $('selectedFile').classList.toggle('hidden', !hasFile);
  if (hasFile) {
    $('selectedName').textContent = selectedFile.name;
    $('selectedSize').textContent = humanBytes(selectedFile.size);
    $('dropTitle').textContent = 'IPA готов к анализу';
    $('dropSubtitle').textContent = 'Нажми сюда, чтобы выбрать другой файл';
  } else {
    $('dropTitle').textContent = 'Нажми, чтобы выбрать IPA';
    $('dropSubtitle').textContent = 'или перетащи файл сюда · только .ipa';
  }
  inspectBtn.disabled = !hasFile || !selectedFile.name.toLowerCase().endsWith('.ipa');
  showError(uploadError, '');
}
dropZone.addEventListener('click', () => ipaFile.click());
ipaFile.addEventListener('change', () => {
  const file = ipaFile.files && ipaFile.files[0];
  if (file && !file.name.toLowerCase().endsWith('.ipa')) {
    displayFile(null);
    showError(uploadError, 'Выбери файл с расширением .ipa.');
    return;
  }
  displayFile(file);
});
$('clearFile').addEventListener('click', () => { ipaFile.value = ''; displayFile(null); });
for (const eventName of ['dragenter', 'dragover']) dropZone.addEventListener(eventName, event => { event.preventDefault(); dropZone.classList.add('drag-over'); });
for (const eventName of ['dragleave', 'drop']) dropZone.addEventListener(eventName, event => { event.preventDefault(); dropZone.classList.remove('drag-over'); });
dropZone.addEventListener('drop', event => {
  const file = event.dataTransfer && event.dataTransfer.files && event.dataTransfer.files[0];
  if (!file) return;
  if (!file.name.toLowerCase().endsWith('.ipa')) { displayFile(null); showError(uploadError, 'Выбери файл с расширением .ipa.'); return; }
  displayFile(file);
  // Keep the file object independently. Assigning input.files is not supported in every browser.
});
function addWarning(text) {
  const li = document.createElement('li');
  li.textContent = text;
  $('warningList').appendChild(li);
}
function populateResult(data) {
  const m = data.metadata;
  $('appTitle').textContent = m.displayName;
  $('appBundle').textContent = m.bundleId;
  $('appVersion').textContent = `v${m.version}`;
  $('minIos').textContent = m.minimumOS || 'Не указана';
  $('ipaSize').textContent = humanBytes(m.fileSize);
  $('profileStatus').textContent = m.hasProvision ? 'Найден' : 'Не найден';
  $('profileStatus').className = m.hasProvision ? 'status-ok' : 'status-bad';
  $('signatureStatus').textContent = m.signatureClues ? 'Есть признаки' : 'Не подтверждены';
  $('signatureStatus').className = m.signatureClues ? 'status-ok' : 'status-bad';
  $('warningList').replaceChildren();
  for (const warning of data.warnings || []) addWarning(warning);
  $('resultPanel').classList.remove('hidden');
  $('installActions').classList.toggle('hidden', !data.canOta);
  $('httpsOnlyNotice').classList.toggle('hidden', data.canOta);
  if (data.canOta) {
    currentInstallUrl = data.installUrl;
    $('installBtn').href = data.installUrl;
    $('downloadBtn').href = data.downloadUrl;
    $('expiresText').textContent = `Ссылка доступна примерно ${data.expiresInHours} ч. после загрузки. Держи сервер активным до окончания установки.`;
  } else {
    currentInstallUrl = '';
    $('expiresText').textContent = 'Открой сайт через публичный HTTPS-адрес, чтобы сформировать ссылку установки.';
  }
  $('resultPanel').scrollIntoView({ behavior: 'smooth', block: 'start' });
}
uploadForm.addEventListener('submit', async event => {
  event.preventDefault();
  showError(uploadError, '');
  if (!selectedFile) { showError(uploadError, 'Сначала выбери IPA-файл.'); return; }
  if (!selectedFile.name.toLowerCase().endsWith('.ipa')) { showError(uploadError, 'Выбери файл с расширением .ipa.'); return; }
  const oldLabel = inspectBtn.querySelector('span').textContent;
  inspectBtn.disabled = true;
  inspectBtn.querySelector('span').textContent = 'Анализируем IPA…';
  inspectBtn.classList.add('loading');
  resultPanel.classList.add('hidden');
  try {
    const body = new FormData();
    body.append('ipa', selectedFile, selectedFile.name);
    const data = await api('/api/inspect', { method: 'POST', body });
    populateResult(data);
  } catch (error) {
    showError(uploadError, error.message);
  } finally {
    inspectBtn.disabled = !selectedFile;
    inspectBtn.querySelector('span').textContent = oldLabel;
    inspectBtn.classList.remove('loading');
  }
});
$('copyInstallBtn').addEventListener('click', async () => {
  if (!currentInstallUrl) return;
  try {
    await navigator.clipboard.writeText(currentInstallUrl);
    showToast('Ссылка установки скопирована. Открой её в Safari на iPhone.');
  } catch (_) {
    const area = document.createElement('textarea');
    area.value = currentInstallUrl;
    area.style.position = 'fixed'; area.style.opacity = '0';
    document.body.appendChild(area); area.select();
    const copied = document.execCommand('copy'); area.remove();
    showToast(copied ? 'Ссылка установки скопирована.' : 'Не удалось скопировать. Открой ссылку непосредственно в Safari.');
  }
});
$('newUploadBtn').addEventListener('click', () => {
  resultPanel.classList.add('hidden');
  ipaFile.value = '';
  displayFile(null);
  $('uploadForm').scrollIntoView({ behavior: 'smooth', block: 'center' });
});
restoreSession();
