'use strict';

require('dotenv').config();
const crypto = require('node:crypto');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');
const express = require('express');
const helmet = require('helmet');
const multer = require('multer');
const unzipper = require('unzipper');
const plist = require('plist');
const bplistParser = require('bplist-parser');

const app = express();
const HOST = process.env.HOST || '0.0.0.0';
const PORT = Number.parseInt(process.env.PORT || '3000', 10);
const ACCESS_KEY = process.env.ACCESS_KEY || '';
const MAX_FILE_SIZE = Math.max(1024 * 1024, Number.parseInt(process.env.MAX_FILE_SIZE || String(2 * 1024 * 1024 * 1024), 10));
const LINK_TTL_HOURS = Math.max(1, Math.min(24, Number.parseInt(process.env.INSTALL_LINK_TTL_HOURS || '2', 10) || 2));
const DATA_DIR = path.resolve(process.env.DATA_DIR || './data');
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
const SIGNING_CACHE_DIR = path.join(DATA_DIR, 'signing-cache');
const SIDESIGN_BIN = process.env.SIDESIGN_BIN || '/usr/local/bin/sidesign';
// SideSign's --source expects a *catalog* JSON ({"servers":[{"name","address"}, ...]}), the same shape as
// https://servers.sidestore.io/servers.json - it does NOT accept a single anisette server address directly
// (pointing --source straight at https://ani.sidestore.io fails with "No active servers found in catalog").
// The real servers.json also mixes in personal/community-hosted entries, some of which present self-signed
// or otherwise untrusted certs - TLS verification correctly refuses those (never bypassed here) and made
// --failover land on a broken entry. Fix: serve our own small catalog, same shape, containing only
// SideStore's own officially-run servers, over loopback (no TLS needed, nothing secret in it - it's the
// same public names/addresses as the real catalog, just filtered).
const ANISETTE_CATALOG = {
  servers: [
    { name: 'SideStore', address: 'https://ani.sidestore.io' },
    { name: 'SideStore (.app)', address: 'https://ani.sidestore.app' },
    { name: 'SideStore (.zip)', address: 'https://ani.sidestore.zip' }
  ],
  cache: 'http://127.0.0.1:' + PORT + '/internal/anisette-catalog.json.hash'
};
const ANISETTE_CATALOG_JSON = JSON.stringify(ANISETTE_CATALOG);
const ANISETTE_CATALOG_HASH = crypto.createHash('sha256').update(ANISETTE_CATALOG_JSON).digest('hex');
const DEFAULT_ANISETTE_SOURCE = `http://127.0.0.1:${PORT}/internal/anisette-catalog.json`;
const RAW_ANISETTE_SOURCE = (process.env.SIDESIGN_ANISETTE_SOURCE || '').trim();
// Guard against a stale/bad SIDESIGN_ANISETTE_SOURCE (e.g. a leftover comma-separated list from an older
// build): --source needs one well-formed absolute URL, and SideSign surfaces a malformed one as an opaque
// "NSURLErrorDomain error -1000" rather than a clear message. Fall back to the local catalog instead of
// passing junk through, and say so on startup so it's obvious in the Render logs.
let SIDESIGN_ANISETTE_SOURCE = DEFAULT_ANISETTE_SOURCE;
if (RAW_ANISETTE_SOURCE) {
  try {
    // WHATWG's URL() is lenient enough to "parse" a comma-joined list (the comma just ends up inside the
    // hostname) instead of throwing, so reject commas/whitespace/control chars explicitly before trusting it.
    if (/[,\s\u0000-\u001f]/.test(RAW_ANISETTE_SOURCE)) throw new Error('contains a comma or whitespace - looks like a list of servers, not a single catalog URL');
    const parsed = new URL(RAW_ANISETTE_SOURCE);
    if (!/^https?:$/.test(parsed.protocol)) throw new Error('not http(s)');
    if (!parsed.hostname || !parsed.hostname.includes('.')) throw new Error('no valid hostname');
    SIDESIGN_ANISETTE_SOURCE = RAW_ANISETTE_SOURCE;
  } catch (_) {
    console.error(`[IPA Pocket] SIDESIGN_ANISETTE_SOURCE="${RAW_ANISETTE_SOURCE}" не является одним корректным URL (ожидается ссылка на каталог вида servers.json) - используем встроенный каталог вместо него. Проверь/очисти эту переменную в Render.`);
  }
}
const signJobs = new Map();
let signingBusy = false;
const COOKIE_NAME = 'ipa_pocket_session';
const SESSION_TOKEN = ACCESS_KEY ? crypto.createHmac('sha256', ACCESS_KEY).update('ipa-pocket-ota-session-v1').digest('hex') : '';
const packages = new Map();

if (ACCESS_KEY.length < 16 || ACCESS_KEY.startsWith('CHANGE-')) {
  console.error('[IPA Pocket] Set ACCESS_KEY in .env to a unique secret of at least 16 characters.');
  process.exit(1);
}
if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) {
  console.error('[IPA Pocket] PORT must be between 1 and 65535.');
  process.exit(1);
}

function safeString(value, max = 300) {
  return String(value || '').replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, max);
}
function redactForJob(job, value) {
  let text = String(value || '').replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, '');
  for (const secret of (job.redactions || [])) {
    if (secret && secret.length >= 3) text = text.split(secret).join('[скрыто]');
  }
  return text;
}
function appendJobLog(job, value) {
  const text = redactForJob(job, value);
  job.logs = (job.logs + text).slice(-14000);
  const promptish = /(two.?factor|verification code|verification method|trusted device|enter.*code|code.*sent|choose (an )?(option|method|device|team)|select (an )?(option|method|device|team)|enter choice|enter.*number|choose.*number|press enter|input required)/i.test(text);
  if (promptish && job.status === 'running') {
    job.status = 'awaiting_input';
    job.prompt = text.trim().slice(-700);
  }
}
function runSideSign(job, args, options = {}) {
  return new Promise(resolve => {
    if (!fs.existsSync(SIDESIGN_BIN)) {
      return resolve({ code: -1, output: `SideSign CLI не найден по пути ${SIDESIGN_BIN}. Сборка Docker могла не завершиться.` });
    }
    job.status = 'running';
    job.prompt = '';
    job.stage = options.stage || 'Выполняем команду подписи';
    const child = spawn(SIDESIGN_BIN, args, {
      cwd: job.workDir,
      env: {
        ...process.env,
        // Explicitly use the refreshed OS CA bundle for SideSign/Anisette HTTPS.
        // Keep TLS certificate verification enabled; never use an insecure bypass.
        SSL_CERT_FILE: '/etc/ssl/certs/ca-certificates.crt',
        SSL_CERT_DIR: '/etc/ssl/certs',
        CURL_CA_BUNDLE: '/etc/ssl/certs/ca-certificates.crt',
        HOME: job.signingHome,
        XDG_CONFIG_HOME: path.join(job.signingHome, '.config'),
        XDG_DATA_HOME: path.join(job.signingHome, '.local', 'share'),
        CI: '1'
      },
      stdio: ['pipe', 'pipe', 'pipe']
    });
    job.child = child;
    let output = '';
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      appendJobLog(job, '\n[IPA Pocket] Истёк лимит времени команды.\n');
      child.kill('SIGTERM');
      setTimeout(() => { try { child.kill('SIGKILL'); } catch (_) {} }, 5000).unref();
    }, 10 * 60 * 1000);
    const collect = (chunk) => {
      const value = chunk.toString('utf8');
      output += value;
      appendJobLog(job, value);
    };
    child.stdout.on('data', collect);
    child.stderr.on('data', collect);
    child.on('error', error => {
      if (settled) return;
      settled = true; clearTimeout(timer); job.child = null;
      resolve({ code: -1, output: `${output}\n${error.message}` });
    });
    child.on('close', code => {
      if (settled) return;
      settled = true; clearTimeout(timer); job.child = null;
      job.status = 'running'; job.prompt = '';
      resolve({ code: Number.isInteger(code) ? code : -1, output });
    });
  });
}
function runSideSignVariants(job, attempts, isArtifact) {
  return (async () => {
    let last = { code: -1, output: '' };
    for (const args of attempts) {
      last = await runSideSign(job, args, { stage: `Пробуем команду SideSign: ${args.slice(0, 3).join(' ')}` });
      if (isArtifact && fs.existsSync(isArtifact)) return last;
      if (isArtifact && /\.p12$/i.test(isArtifact)) {
        const foundP12 = (await fsp.readdir(job.signingHome).catch(() => []))
          .filter(name => /\.p12$/i.test(name))
          .map(name => path.join(job.signingHome, name))
          .find(full => full !== isArtifact);
        if (foundP12) { await fsp.copyFile(foundP12, isArtifact); return last; }
      }
      if (last.code === 0 && !isArtifact) return last;
      if (last.code === 0 && isArtifact && /\.mobileprovision$/i.test(isArtifact)) {
        const foundProfile = await findProvisioningFile(job.workDir);
        if (foundProfile) return last;
      }
      const output = last.output.toLowerCase();
      if (!(output.includes('invalid') || output.includes('unknown') || output.includes('unsupported') || output.includes('usage:') || output.includes('unrecognized') || output.includes('missing required') || output.includes('must be one of') || (last.code === 0 && isArtifact))) break;
    }
    return last;
  })();
}
function encryptCachedPassword(plain, accountHash) {
  const key = crypto.createHash('sha256').update(`${ACCESS_KEY}:${accountHash}:ipa-pocket-cache-v1`).digest();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const data = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  return JSON.stringify({ iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), data: data.toString('base64') });
}
function decryptCachedPassword(encoded, accountHash) {
  const record = JSON.parse(encoded);
  const key = crypto.createHash('sha256').update(`${ACCESS_KEY}:${accountHash}:ipa-pocket-cache-v1`).digest();
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(record.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(record.tag, 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(record.data, 'base64')), decipher.final()]).toString('utf8');
}
async function findProvisioningFile(folder) {
  const names = await fsp.readdir(folder).catch(() => []);
  for (const name of names) {
    const full = path.join(folder, name);
    const stat = await fsp.stat(full).catch(() => null);
    if (stat && stat.isFile() && /\.mobileprovision$/i.test(name) && stat.size > 100) return full;
  }
  return null;
}
async function signingStep(job, args, stage, allowAlready = false) {
  const result = await runSideSign(job, args, { stage });
  if (result.code === 0) return result;
  if (allowAlready && /(already exists|already registered|duplicate|already been registered|already in use)/i.test(result.output)) {
    appendJobLog(job, '\n[IPA Pocket] Запись уже существует; продолжаем.\n');
    return result;
  }
  const detail = result.output.trim().slice(-1500) || 'SideSign завершился без диагностического сообщения.';
  throw new Error(`${stage}. Ответ SideSign:\n${detail}`);
}
async function performSigning(job, item, credentials) {
  const accountHash = crypto.createHash('sha256').update(credentials.appleId.toLowerCase()).digest('hex').slice(0, 24);
  job.signingHome = path.join(SIGNING_CACHE_DIR, accountHash);
  await fsp.mkdir(job.signingHome, { recursive: true, mode: 0o700 });
  await fsp.chmod(job.signingHome, 0o700).catch(() => {});
  job.workDir = path.join(DATA_DIR, 'jobs', job.id);
  await fsp.mkdir(job.workDir, { recursive: true, mode: 0o700 });
  await fsp.chmod(job.workDir, 0o700).catch(() => {});
  job.stage = 'Проверяем SideSign';
  const binary = spawnSync(SIDESIGN_BIN, ['--help'], { encoding: 'utf8', timeout: 15000, env: { ...process.env, HOME: job.signingHome } });
  const helpOutput = `${binary.stdout || ''} ${binary.stderr || ''}`;
  if (binary.error || !/sidesign/i.test(helpOutput)) {
    throw new Error('SideSign CLI не запускается в контейнере. Проверь журнал сборки Render; текущая версия сайта ещё не готова к подписанию.');
  }

  // Password is passed only to the short-lived child process and is never added to job metadata/logs.
  // --source must point to a catalog JSON ({"servers":[{"name","address"}]}); SIDESIGN_ANISETTE_SOURCE
  // defaults to our own filtered local catalog (see ANISETTE_CATALOG above) so --failover only ever
  // tries SideStore's own officially-run, validly-certified servers.
  appendJobLog(job, `\n[IPA Pocket] Anisette-каталог: ${SIDESIGN_ANISETTE_SOURCE}\n`);
  const login = await runSideSign(job, ['dev', 'login', '--apple-id', credentials.appleId, '--password', credentials.password, '--failover', '--source', SIDESIGN_ANISETTE_SOURCE], { stage: 'Входим в Apple Developer и ждём 2FA при необходимости' });
  credentials.password = '';
  if (login.code !== 0) {
    const detail = login.output.trim().slice(-1800) || 'Неизвестная ошибка входа.';
    throw new Error(`Не удалось войти в Apple ID. Проверь логин, пароль и пройди запрос подтверждения, если он появился.\n${detail}`);
  }
  job.stage = 'Apple ID принят';
  appendJobLog(job, '\n[IPA Pocket] Вход выполнен; запускаем подготовку подписи.\n');

  await signingStep(job, ['dev', 'devices', 'register', '-n', 'IPA Pocket iPhone', '-u', credentials.udid], 'Регистрация UDID устройства', true);
  await signingStep(job, ['dev', 'appids', 'register', '-n', item.metadata.displayName, '-b', item.metadata.bundleId], 'Регистрация Bundle ID', true);

  const certPath = path.join(job.signingHome, 'ipa-pocket-development.p12');
  const certPasswordPath = path.join(job.signingHome, 'ipa-pocket-development.p12pass');
  let p12Password = '';
  let hasCachedCert = await fsp.stat(certPath).then(s => s.isFile() && s.size > 100, () => false);
  if (hasCachedCert) {
    try { p12Password = decryptCachedPassword(await fsp.readFile(certPasswordPath, 'utf8'), accountHash); }
    catch (_) { hasCachedCert = false; }
  }
  if (!hasCachedCert) {
    await fsp.unlink(certPath).catch(() => {});
    await fsp.unlink(certPasswordPath).catch(() => {});
    p12Password = crypto.randomBytes(24).toString('hex');
    const certAttempts = [
      ['dev', 'certs', 'create', '--type', 'IOS_DEVELOPMENT', '--name', 'IPA Pocket Development', '--output', certPath, '--password', p12Password],
      ['dev', 'certs', 'create', '--type', 'iOSDevelopment', '--name', 'IPA Pocket Development', '--output', certPath, '--password', p12Password],
      ['dev', 'certs', 'create', '--type', 'development', '--name', 'IPA Pocket Development', '--output', certPath, '--password', p12Password]
    ];
    job.redactions.push(p12Password);
    const certResult = await runSideSignVariants(job, certAttempts, certPath);
    if (!(await fsp.stat(certPath).then(s => s.isFile() && s.size > 100, () => false))) {
      throw new Error(`Не удалось создать сертификат разработки. Проверь вывод SideSign ниже.\n${certResult.output.trim().slice(-1800)}`);
    }
    await fsp.writeFile(certPasswordPath, encryptCachedPassword(p12Password, accountHash), { mode: 0o600 });
    await fsp.chmod(certPath, 0o600).catch(() => {});
  }

  const profilePath = path.join(job.workDir, 'ipa-pocket.mobileprovision');
  // SideSign's documented dev command is `profiles download --bundle-id ... --output ...`.
  // It downloads/generates the profile for the registered App ID and current team.
  const profResult = await runSideSignVariants(job, [
    ['dev', 'profiles', 'download', '--bundle-id', item.metadata.bundleId, '--output', profilePath],
    ['dev', 'profiles', 'fetch', '--bundle-id', item.metadata.bundleId, '--output', profilePath]
  ], profilePath);
  let actualProfile = (await fsp.stat(profilePath).then(s => s.isFile() && s.size > 100, () => false)) ? profilePath : await findProvisioningFile(job.workDir);
  if (!actualProfile) {
    throw new Error(`Не удалось создать профиль для ${item.metadata.bundleId}. Это может быть ограничение бесплатной Personal Team или несовместимый тип профиля.\n${profResult.output.trim().slice(-1800)}`);
  }

  const signedPath = path.join(job.workDir, 'signed.ipa');
  const signResult = await runSideSign(job, ['sign', item.path, '--p12', certPath, '--password', p12Password, '--profile', actualProfile, '--bundle-id', item.metadata.bundleId, '--output', signedPath], { stage: 'Переподписываем IPA' });
  p12Password = '';
  if (signResult.code !== 0 && !(await fsp.stat(signedPath).then(s => s.isFile() && s.size > 100, () => false))) {
    throw new Error(`SideSign не смог переподписать этот IPA. Некоторые приложения требуют entitlements, которые бесплатный Apple ID не предоставляет.\n${signResult.output.trim().slice(-1800)}`);
  }
  const signedMeta = await inspectIpa(signedPath);
  if (!signedMeta.hasProvision || !signedMeta.hasCodeResources || !signedMeta.hasExecutable) {
    throw new Error('Выходной IPA не прошёл базовую проверку после подписи. Файл не будет опубликован для установки.');
  }

  const finalPath = path.join(UPLOAD_DIR, `${job.token}-signed.ipa`);
  await fsp.copyFile(signedPath, finalPath);
  await fsp.chmod(finalPath, 0o600).catch(() => {});
  const oldPath = item.path;
  item.path = finalPath;
  item.name = safeFileName(item.name.replace(/\.ipa$/i, '') + '-signed.ipa');
  item.metadata = signedMeta;
  item.signed = true;
  item.expiresAt = Date.now() + LINK_TTL_HOURS * 60 * 60 * 1000;
  await fsp.unlink(oldPath).catch(() => {});
  job.result = {
    name: item.name,
    metadata: signedMeta,
    expiresInHours: LINK_TTL_HOURS,
    installUrl: item.baseUrl ? `itms-services://?action=download-manifest&url=${encodeURIComponent(`${item.baseUrl}/ota/${item.token}/manifest.plist`)}` : '',
    downloadUrl: `${item.baseUrl || ''}/ota/${item.token}/app.ipa`,
    canOta: Boolean(item.baseUrl && /^https:\/\//i.test(item.baseUrl))
  };
  job.status = 'completed';
  job.stage = 'Подписание завершено';
  appendJobLog(job, '\n[IPA Pocket] Готово: подписанный IPA подготовлен.\n');
}
async function startSigningJob(item, requestData) {
  const id = crypto.randomUUID();
  const appleId = safeString(requestData.appleId, 254);
  const password = String(requestData.password || '');
  let udid = safeString(requestData.udid, 64).trim().toUpperCase().replace(/[–—−]/g, '-');
  // Newer iPhones use an 8-hex + hyphen + 16-hex UDID; older devices use 40 hex characters.
  // Some UDID pages omit the hyphen, so accept 24 hex characters and normalize them.
  const compactUdid = udid.replace(/-/g, '');
  if (/^[A-F0-9]{24}$/.test(compactUdid) && !udid.includes('-')) {
    udid = `${compactUdid.slice(0, 8)}-${compactUdid.slice(8)}`;
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(appleId)) throw new Error('Введи корректный Apple ID (электронную почту).');
  if (!password || password.length > 512) throw new Error('Введи пароль Apple ID.');
  if (!/^(?:[A-F0-9]{40}|[A-F0-9]{8}-[A-F0-9]{16})$/.test(udid)) throw new Error('Неподдерживаемый формат UDID. Принимаются старый формат из 40 шестнадцатеричных символов и новый формат XXXXXXXX-XXXXXXXXXXXXXXXX (8 символов, дефис, 16 символов). Вставь полный UDID из надёжного источника — не IMEI и не серийный номер.');
  if (signingBusy) throw new Error('Сервер уже выполняет подпись. Дождись окончания текущей операции.');
  const job = { id, token: item.token, status: 'queued', stage: 'Подготовка', logs: '', prompt: '', child: null, createdAt: Date.now(), result: null, error: '', redactions: [appleId, password], signingHome: '', workDir: '' };
  signJobs.set(id, job);
  signingBusy = true;
  // Password does not get written to disk or copied into the job object; only this local variable is passed to the login process.
  const credentials = { appleId, password, udid };
  setImmediate(async () => {
    try {
      await performSigning(job, item, credentials);
    } catch (error) {
      job.status = 'failed';
      job.stage = 'Подписание не завершено';
      job.error = redactForJob(job, safeString(error.message, 2500));
      appendJobLog(job, `\n[IPA Pocket] ОШИБКА: ${job.error}\n`);
    } finally {
      credentials.password = '';
      job.child = null;
      if (job.workDir) await fsp.rm(job.workDir, { recursive: true, force: true }).catch(() => {});
      job.redactions = job.redactions.filter(secret => secret === appleId);
      signingBusy = false;
      job.finishedAt = Date.now();
    }
  });
  return job;
}

function safeEqual(a, b) {
  const aa = Buffer.from(String(a || ''), 'utf8');
  const bb = Buffer.from(String(b || ''), 'utf8');
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
function parseCookies(header) {
  const output = Object.create(null);
  for (const part of String(header || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) {
      try { output[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim()); } catch (_) {}
    }
  }
  return output;
}
function requireSession(req, res, next) {
  const token = parseCookies(req.headers.cookie)[COOKIE_NAME];
  if (!token || !safeEqual(token, SESSION_TOKEN)) {
    return res.status(401).json({ ok: false, error: 'Сессия завершилась. Введи ключ доступа снова.' });
  }
  next();
}
function safeFileName(name) {
  const base = path.basename(String(name || 'application.ipa')).replace(/[^a-zA-Z0-9._-]+/g, '_').slice(0, 120);
  return base.toLowerCase().endsWith('.ipa') ? base : `${base || 'application'}.ipa`;
}
function xmlEscape(value) {
  return String(value ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&apos;');
}
function getPublicBaseUrl(req) {
  const configured = String(process.env.PUBLIC_BASE_URL || '').trim().replace(/\/+$/, '');
  if (configured) return /^https:\/\//i.test(configured) ? configured : '';
  const forwarded = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim().toLowerCase();
  const secure = req.secure || forwarded === 'https';
  if (!secure) return '';
  return `https://${req.get('host')}`;
}
function normaliseName(value, fallback) {
  const s = String(value || '').replace(/[\u0000-\u001f\u007f]/g, '').trim();
  return (s || fallback).slice(0, 120);
}
async function readEntryBuffer(entry, maxBytes = 4 * 1024 * 1024) {
  const size = Number(entry.uncompressedSize || 0);
  if (size > maxBytes) throw new Error('Info.plist необычно большой; анализ остановлен для безопасности.');
  const chunks = [];
  let total = 0;
  return await new Promise((resolve, reject) => {
    const stream = entry.stream();
    stream.on('data', chunk => {
      total += chunk.length;
      if (total > maxBytes) {
        stream.destroy(new Error('Info.plist превышает допустимый размер.'));
        return;
      }
      chunks.push(chunk);
    });
    stream.on('error', reject);
    stream.on('end', () => resolve(Buffer.concat(chunks)));
  });
}
function parseInfoPlist(buffer) {
  if (buffer.subarray(0, 8).toString('ascii') === 'bplist00') {
    const parsed = bplistParser.parseBuffer(buffer);
    if (!Array.isArray(parsed) || !parsed[0] || typeof parsed[0] !== 'object') throw new Error('Не удалось прочитать бинарный Info.plist.');
    return parsed[0];
  }
  const text = buffer.toString('utf8');
  if (!text.includes('<plist')) throw new Error('Info.plist имеет неизвестный формат.');
  return plist.parse(text);
}
async function inspectIpa(filePath) {
  let directory;
  try { directory = await unzipper.Open.file(filePath); }
  catch (_) { throw new Error('Файл не является корректным ZIP/IPA-архивом или он повреждён.'); }

  const entries = directory.files || [];
  const infoEntry = entries.find(entry => /^Payload\/[^/]+\.app\/Info\.plist$/.test(entry.path));
  if (!infoEntry) throw new Error('В архиве не найден Payload/*.app/Info.plist. Это не похоже на обычный iOS IPA.');
  const appPrefix = infoEntry.path.slice(0, -'Info.plist'.length);
  const buffer = await readEntryBuffer(infoEntry);
  const info = parseInfoPlist(buffer);
  const bundleId = String(info.CFBundleIdentifier || '').trim();
  if (!bundleId || !/^[A-Za-z0-9.-]+$/.test(bundleId)) throw new Error('В Info.plist отсутствует корректный CFBundleIdentifier.');

  const displayName = normaliseName(info.CFBundleDisplayName || info.CFBundleName, path.basename(appPrefix.replace(/\/$/, '')) .replace(/\.app$/i, ''));
  const version = normaliseName(info.CFBundleShortVersionString || info.CFBundleVersion, '1.0');
  const build = normaliseName(info.CFBundleVersion, version);
  const minimumOS = normaliseName(info.MinimumOSVersion, 'Не указан');
  const hasProvision = entries.some(entry => entry.path === `${appPrefix}embedded.mobileprovision`);
  const hasCodeResources = entries.some(entry => entry.path === `${appPrefix}_CodeSignature/CodeResources`);
  const hasExecutable = entries.some(entry => entry.path === `${appPrefix}${String(info.CFBundleExecutable || '')}`);
  const stats = await fsp.stat(filePath);
  return {
    bundleId,
    displayName,
    version,
    build,
    minimumOS,
    fileSize: stats.size,
    hasProvision,
    hasCodeResources,
    hasExecutable,
    signatureClues: hasProvision && hasCodeResources,
    archiveEntries: entries.length
  };
}
async function ensureDirs() {
  await fsp.mkdir(UPLOAD_DIR, { recursive: true });
  await fsp.mkdir(SIGNING_CACHE_DIR, { recursive: true, mode: 0o700 });
  await fsp.chmod(SIGNING_CACHE_DIR, 0o700).catch(() => {});
  await fsp.mkdir(path.join(DATA_DIR, 'jobs'), { recursive: true, mode: 0o700 });
  // Remove files left by an earlier process; installation links are intentionally short-lived.
  const names = await fsp.readdir(UPLOAD_DIR).catch(() => []);
  await Promise.all(names.map(name => fsp.unlink(path.join(UPLOAD_DIR, name)).catch(() => {})));
}
async function removePackage(token, item) {
  packages.delete(token);
  await fsp.unlink(item.path).catch(() => {});
}
async function cleanupExpired() {
  const now = Date.now();
  for (const [token, item] of packages.entries()) if (item.expiresAt <= now) await removePackage(token, item);
}

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({
  contentSecurityPolicy: { directives: {
    defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'"], imgSrc: ["'self'", 'data:'],
    connectSrc: ["'self'"], objectSrc: ["'none'"], baseUri: ["'self'"], frameAncestors: ["'none'"]
  } },
  crossOriginEmbedderPolicy: false
}));
app.use(express.json({ limit: '16kb' }));
app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html', etag: true, maxAge: '1h' }));
app.get('/health', (_req, res) => res.status(200).json({ ok: true, service: 'ipa-pocket-ota' }));
// Local anisette catalog for SideSign's --source/--failover (see ANISETTE_CATALOG above). Only ever
// fetched over loopback by the sidesign child process, never exposed as a link in the UI.
app.get('/internal/anisette-catalog.json', (_req, res) => res.type('application/json').send(ANISETTE_CATALOG_JSON));
app.get('/internal/anisette-catalog.json.hash', (_req, res) => res.type('text/plain').send(ANISETTE_CATALOG_HASH));

app.post('/api/auth', (req, res) => {
  if (!safeEqual(req.body && req.body.accessKey, ACCESS_KEY)) return res.status(401).json({ ok: false, error: 'Неверный ключ доступа.' });
  const forwarded = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim().toLowerCase();
  const secure = req.secure || forwarded === 'https';
  res.cookie(COOKIE_NAME, SESSION_TOKEN, { httpOnly: true, sameSite: 'strict', secure, path: '/', maxAge: 4 * 60 * 60 * 1000 });
  res.json({ ok: true });
});
app.post('/api/logout', (_req, res) => {
  res.clearCookie(COOKIE_NAME, { httpOnly: true, sameSite: 'strict', path: '/' });
  res.json({ ok: true });
});
app.get('/api/status', requireSession, (req, res) => {
  const signingReady = fs.existsSync(SIDESIGN_BIN);
  res.json({ ok: true, httpsReady: Boolean(getPublicBaseUrl(req)), maxFileSize: MAX_FILE_SIZE, linkTtlHours: LINK_TTL_HOURS, signingReady, mode: signingReady ? 'experimental-apple-id-signing' : 'ota-existing-signature' });
});

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
  filename: (_req, _file, cb) => cb(null, `${crypto.randomUUID()}.ipa`)
});
const upload = multer({
  storage,
  limits: { fileSize: MAX_FILE_SIZE, files: 1, fields: 0 },
  fileFilter: (_req, file, cb) => {
    if (path.extname(file.originalname).toLowerCase() !== '.ipa') return cb(new Error('Выбери файл с расширением .ipa.'));
    cb(null, true);
  }
});

app.post('/api/inspect', requireSession, (req, res) => {
  upload.single('ipa')(req, res, async error => {
    if (error) {
      const status = error instanceof multer.MulterError && error.code === 'LIMIT_FILE_SIZE' ? 413 : 400;
      return res.status(status).json({ ok: false, error: error.message || 'Не удалось загрузить IPA.' });
    }
    const file = req.file;
    if (!file) return res.status(400).json({ ok: false, error: 'Сначала выбери IPA-файл.' });
    try {
      const metadata = await inspectIpa(file.path);
      const token = crypto.randomBytes(32).toString('hex');
      const baseUrl = getPublicBaseUrl(req);
      const expiresAt = Date.now() + LINK_TTL_HOURS * 60 * 60 * 1000;
      const item = { token, path: file.path, name: safeFileName(file.originalname), metadata, baseUrl, expiresAt };
      packages.set(token, item);
      const root = baseUrl || `${req.protocol}://${req.get('host')}`;
      const canOta = Boolean(baseUrl);
      const installReady = Boolean(canOta && metadata.signatureClues);
      const manifestUrl = installReady ? `${root}/ota/${token}/manifest.plist` : '';
      const installUrl = installReady ? `itms-services://?action=download-manifest&url=${encodeURIComponent(manifestUrl)}` : '';
      res.json({
        ok: true,
        token,
        name: item.name,
        metadata,
        expiresAt,
        expiresInHours: LINK_TTL_HOURS,
        canOta: installReady,
        httpsReady: Boolean(baseUrl),
        manifestUrl,
        installUrl,
        downloadUrl: `${root}/ota/${token}/app.ipa`,
        warnings: [
          !metadata.hasProvision ? 'Внутри IPA не найден embedded.mobileprovision. iOS, скорее всего, отклонит OTA-установку.' : '',
          !metadata.hasCodeResources ? 'Не найден файл _CodeSignature/CodeResources. Наличие рабочей подписи не подтверждено.' : '',
          !metadata.hasExecutable ? 'Не найден основной исполняемый файл из Info.plist; IPA может быть неполным.' : '',
          !canOta ? 'Сайт сейчас доступен без HTTPS. Для установки через itms-services нужен публичный HTTPS-адрес.' : '',
          'Проверены только структура архива и наличие характерных файлов подписи. Криптографическая подпись, доверие сертификату и соответствие UDID не проверены.'
        ].filter(Boolean)
      });
    } catch (inspectionError) {
      await fsp.unlink(file.path).catch(() => {});
      res.status(400).json({ ok: false, error: String(inspectionError.message || 'Не удалось проанализировать IPA.').slice(0, 1200) });
    }
  });
});

app.post('/api/sign/start', requireSession, async (req, res) => {
  try {
    const token = safeString(req.body && req.body.token, 128);
    const item = packages.get(token);
    if (!/^[a-f0-9]{64}$/.test(token) || !item || item.expiresAt <= Date.now() || !fs.existsSync(item.path)) {
      return res.status(404).json({ ok: false, error: 'Загруженный IPA уже истёк. Загрузи его заново.' });
    }
    if (!req.body || req.body.confirmCredentialHandling !== true) {
      return res.status(400).json({ ok: false, error: 'Подтверди предупреждение о передаче данных Apple ID этому серверу.' });
    }
    const job = await startSigningJob(item, req.body);
    res.json({ ok: true, jobId: job.id, status: job.status });
  } catch (error) {
    res.status(400).json({ ok: false, error: safeString(error.message || 'Не удалось начать подпись.', 2000) });
  }
});
app.get('/api/sign/:id', requireSession, (req, res) => {
  const job = signJobs.get(String(req.params.id || ''));
  if (!job) return res.status(404).json({ ok: false, error: 'Задание подписи не найдено или сервер перезапускался.' });
  res.json({
    ok: true,
    id: job.id,
    status: job.status,
    stage: job.stage,
    prompt: job.prompt,
    logs: job.logs,
    error: job.error,
    result: job.result,
    createdAt: job.createdAt,
    finishedAt: job.finishedAt || null
  });
});
app.post('/api/sign/:id/input', requireSession, (req, res) => {
  const job = signJobs.get(String(req.params.id || ''));
  if (!job || !job.child || job.status !== 'awaiting_input') return res.status(409).json({ ok: false, error: 'Сейчас сервер не ожидает код подтверждения.' });
  const value = safeString(req.body && req.body.value, 80);
  if (!value || /[\r\n]/.test(value)) return res.status(400).json({ ok: false, error: 'Введи ответ одной строкой.' });
  if (/^\d{4,8}$/.test(value)) job.redactions.push(value);
  job.child.stdin.write(`${value}\n`);
  job.status = 'running';
  job.prompt = '';
  res.json({ ok: true });
});
app.post('/api/sign/:id/cancel', requireSession, (req, res) => {
  const job = signJobs.get(String(req.params.id || ''));
  if (!job) return res.status(404).json({ ok: false, error: 'Задание не найдено.' });
  if (job.child) job.child.kill('SIGTERM');
  job.status = 'cancelled';
  job.stage = 'Отменено пользователем';
  res.json({ ok: true });
});

function getOtaItem(req, res) {
  const token = String(req.params.token || '');
  if (!/^[a-f0-9]{64}$/.test(token)) { res.status(404).send('Ссылка недействительна.'); return null; }
  const item = packages.get(token);
  if (!item || item.expiresAt <= Date.now() || !fs.existsSync(item.path)) {
    if (item) removePackage(token, item).catch(() => {});
    res.status(404).send('Файл удалён или ссылка установки истекла. Загрузи IPA заново.');
    return null;
  }
  return item;
}
app.get('/ota/:token/manifest.plist', (req, res) => {
  const item = getOtaItem(req, res);
  if (!item) return;
  if (!item.baseUrl || !/^https:\/\//i.test(item.baseUrl)) return res.status(400).send('Для OTA-установки требуется HTTPS.');
  if (!item.signed && !item.metadata.signatureClues) return res.status(409).send('IPA ещё не прошёл базовую проверку подписи. Вернись в IPA Pocket и выполни подписание.');
  const m = item.metadata;
  const ipaUrl = `${item.baseUrl}/ota/${item.token}/app.ipa`;
  const document = `<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict><key>items</key><array><dict><key>assets</key><array><dict><key>kind</key><string>software-package</string><key>url</key><string>${xmlEscape(ipaUrl)}</string></dict></array><key>metadata</key><dict><key>bundle-identifier</key><string>${xmlEscape(m.bundleId)}</string><key>bundle-version</key><string>${xmlEscape(m.build || m.version)}</string><key>kind</key><string>software</string><key>title</key><string>${xmlEscape(m.displayName)}</string></dict></dict></array></dict></plist>`;
  res.setHeader('Content-Type', 'application/x-plist; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.send(document);
});
app.get('/ota/:token/app.ipa', (req, res) => {
  const item = getOtaItem(req, res);
  if (!item) return;
  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Content-Length', String(fs.statSync(item.path).size));
  res.setHeader('Content-Disposition', `inline; filename="${item.name.replace(/"/g, '')}"`);
  res.setHeader('Cache-Control', 'no-store, private');
  fs.createReadStream(item.path).on('error', () => { if (!res.headersSent) res.status(500).end('Не удалось прочитать IPA.'); else res.destroy(); }).pipe(res);
});

app.use((error, _req, res, _next) => {
  console.error('[IPA Pocket] request error:', error && error.message ? error.message : error);
  if (res.headersSent) return;
  res.status(500).json({ ok: false, error: 'Внутренняя ошибка сервера.' });
});

ensureDirs().then(() => {
  setInterval(() => cleanupExpired().catch(() => {}), 5 * 60 * 1000).unref();
  setInterval(async () => {
    const cutoff = Date.now() - 30 * 60 * 1000;
    for (const [id, job] of signJobs.entries()) {
      if (job.createdAt < cutoff && !job.child) signJobs.delete(id);
    }
  }, 5 * 60 * 1000).unref();
  app.listen(PORT, HOST, () => console.log(`[IPA Pocket] Listening on ${HOST}:${PORT}; OTA link lifetime: ${LINK_TTL_HOURS}h`));
}).catch(error => {
  console.error('[IPA Pocket] Could not initialise storage:', error.message);
  process.exit(1);
});
