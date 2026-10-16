'use strict';

require('dotenv').config();
const crypto = require('node:crypto');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
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
  res.json({ ok: true, httpsReady: Boolean(getPublicBaseUrl(req)), maxFileSize: MAX_FILE_SIZE, linkTtlHours: LINK_TTL_HOURS, mode: 'ota-existing-signature' });
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
      const manifestUrl = canOta ? `${root}/ota/${token}/manifest.plist` : '';
      const installUrl = canOta ? `itms-services://?action=download-manifest&url=${encodeURIComponent(manifestUrl)}` : '';
      res.json({
        ok: true,
        token,
        name: item.name,
        metadata,
        expiresAt,
        expiresInHours: LINK_TTL_HOURS,
        canOta,
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
  app.listen(PORT, HOST, () => console.log(`[IPA Pocket] Listening on ${HOST}:${PORT}; OTA link lifetime: ${LINK_TTL_HOURS}h`));
}).catch(error => {
  console.error('[IPA Pocket] Could not initialise storage:', error.message);
  process.exit(1);
});
