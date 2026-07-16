/**
 * LIBERTY OPERATIONS CENTER — SYSTEM RP
 * Jeden plik: backend + Discord OAuth2 + baza JSON + cały frontend.
 *
 * Wymagania:
 *   Node.js 20+
 *   npm init -y
 *   npm i express
 *
 * Uruchomienie (PowerShell):
 *   $env:DISCORD_CLIENT_SECRET="TU_WKLEJ_SECRET_Z_DISCORD_DEVELOPER_PORTAL"
 *   $env:BASE_URL="http://localhost:3000"
 *   $env:SESSION_SECRET="LOSOWY_DLUGI_TEKST_MIN_32_ZNAKI"
 *   node server.js
 *
 * Uruchomienie (Linux / macOS):
 *   DISCORD_CLIENT_SECRET="..." BASE_URL="http://localhost:3000" SESSION_SECRET="..." node server.js
 *
 * W Discord Developer Portal dodaj Redirect URI:
 *   http://localhost:3000/auth/callback
 *
 * Na hostingu ustaw BASE_URL na pełną domenę HTTPS, np.:
 *   https://mdt.twojadomena.pl
 * i dodaj:
 *   https://mdt.twojadomena.pl/auth/callback
 *
 * WAŻNE:
 * - Client Secret i SESSION_SECRET przechowuj w zmiennych środowiskowych, nigdy w publicznym kodzie.
 * - Domyślna baza zapisuje się do pliku ksp_mdt_data.json obok tego skryptu.
 * - System jest nieoficjalnym projektem roleplay inspirowanym polską Policją.
 */

'use strict';

const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.set('trust proxy', 1);

const PORT = Number(process.env.PORT || 3000);
const BASE_URL = String(process.env.BASE_URL || process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`).replace(/\/+$/, '');
const DISCORD_CLIENT_ID = String(process.env.DISCORD_CLIENT_ID || '1526962966975610991');
const DISCORD_CLIENT_SECRET = String(process.env.DISCORD_CLIENT_SECRET || '');
const DISCORD_GUILD_ID = String(process.env.DISCORD_GUILD_ID || '1527014315381751928');
const DISCORD_ROLE_ID = String(process.env.DISCORD_ROLE_ID || '1527014315411116062');
const DISCORD_ADMIN_ROLE_ID = String(process.env.DISCORD_ADMIN_ROLE_ID || '');
const DISCORD_REQUIRE_ROLE = process.env.DISCORD_REQUIRE_ROLE === 'true';
const DISCORD_BOT_TOKEN = String(process.env.DISCORD_BOT_TOKEN || '');
const DISCORD_ON_DUTY_ROLE_ID = String(process.env.DISCORD_ON_DUTY_ROLE_ID || '');
const DISCORD_LOG_WEBHOOK_URL = String(process.env.DISCORD_LOG_WEBHOOK_URL || '');
const ERLC_SERVER_KEY = String(process.env.ERLC_SERVER_KEY || '');
const ERLC_WEBHOOK_PUBLIC_KEY = String(process.env.ERLC_WEBHOOK_PUBLIC_KEY || '');
const SESSION_SECRET = String(process.env.SESSION_SECRET || 'CHANGE-ME-IN-PRODUCTION-AT-LEAST-32-CHARS');
const DB_FILE_SETTING = String(process.env.DB_FILE || 'ksp_mdt_data.json');
const DB_FILE = path.isAbsolute(DB_FILE_SETTING) ? DB_FILE_SETTING : path.join(__dirname, DB_FILE_SETTING);
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const OAUTH_STATE_TTL_MS = 10 * 60 * 1000;
const MAX_AUDIT = 3000;
const MAX_DUTY_SHIFTS_PER_USER = 100;
const PATROL_STATUSES = ['Dostępny', 'Przydzielony', 'W drodze', 'Na miejscu', 'Transport', 'Pościg', 'Przerwa'];
const DISPATCH_STATUSES = ['Nowe', 'Przyjęte', 'Jednostka w drodze', 'Na miejscu', 'Zamknięte', 'Anulowane'];
const DEV_LOGIN_ENABLED = process.env.DEV_LOGIN_ENABLED === 'true' && /^http:\/\/(?:localhost|127\.0\.0\.1)(?::\d+)?$/i.test(BASE_URL);
const PREVIEW_LOGIN_ENABLED = process.env.PREVIEW_LOGIN_ENABLED !== 'false';

if (!DISCORD_CLIENT_SECRET) {
  console.warn('\n[UWAGA] Brak DISCORD_CLIENT_SECRET. Logowanie Discord nie zadziała do czasu ustawienia sekretu.\n');
}
if (SESSION_SECRET.startsWith('CHANGE-ME')) {
  console.warn('[UWAGA] Ustaw własny SESSION_SECRET przed publikacją strony.');
}

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: false, limit: '2mb' }));

/* -------------------------------------------------------------------------- */
/*                                  SECURITY                                  */
/* -------------------------------------------------------------------------- */

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; img-src 'self' data: https://cdn.discordapp.com; " +
      "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; " +
      "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self' https://discord.com"
  );
  next();
});

const rateBuckets = new Map();

function rateLimit(key, max, windowMs) {
  const now = Date.now();
  let bucket = rateBuckets.get(key);
  if (!bucket || now > bucket.resetAt) {
    bucket = { count: 0, resetAt: now + windowMs };
    rateBuckets.set(key, bucket);
  }
  bucket.count += 1;
  return bucket.count <= max;
}

app.use('/auth', (req, res, next) => {
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  if (!rateLimit(`auth:${ip}`, 60, 10 * 60 * 1000)) {
    return res.status(429).send('Zbyt wiele prób. Spróbuj ponownie za kilka minut.');
  }
  next();
});

app.use('/api', (req, res, next) => {
  if (req.method !== 'GET') {
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    if (!rateLimit(`api-write:${ip}`, 240, 10 * 60 * 1000)) {
      return res.status(429).json({ error: 'Zbyt wiele operacji. Odczekaj chwilę.' });
    }
  }
  next();
});

/* -------------------------------------------------------------------------- */
/*                                  DATABASE                                  */
/* -------------------------------------------------------------------------- */

const COLLECTIONS = {
  citizens: { prefix: 'OSO', label: 'Osoby' },
  vehicles: { prefix: 'POJ', label: 'Pojazdy' },
  tickets: { prefix: 'MAN', label: 'Mandaty' },
  arrests: { prefix: 'ZAT', label: 'Zatrzymania' },
  reports: { prefix: 'RAP', label: 'Raporty' },
  wanted: { prefix: 'POS', label: 'Poszukiwani' },
  evidence: { prefix: 'DOW', label: 'Dowody' },
  dispatch: { prefix: 'ZGL', label: 'Zgłoszenia' }
};

function emptyDatabase() {
  return {
    meta: {
      version: 2,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    },
    counters: {},
    citizens: [],
    vehicles: [],
    tickets: [],
    arrests: [],
    reports: [],
    wanted: [],
    evidence: [],
    dispatch: [],
    duty: [],
    audit: []
  };
}

function loadDatabase() {
  try {
    if (!fs.existsSync(DB_FILE)) {
      const initial = emptyDatabase();
      saveDatabase(initial);
      return initial;
    }
    const parsed = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    const legacyWantedKey = ['bo', 'los'].join('');
    if (!Array.isArray(parsed.wanted) && Array.isArray(parsed[legacyWantedKey])) {
      parsed.wanted = parsed[legacyWantedKey];
    }
    delete parsed[legacyWantedKey];

    const base = emptyDatabase();

    for (const key of Object.keys(base)) {
      if (parsed[key] !== undefined) base[key] = parsed[key];
    }
    for (const key of Object.keys(COLLECTIONS)) {
      if (!Array.isArray(base[key])) base[key] = [];
    }
    if (!Array.isArray(base.audit)) base.audit = [];
    if (!Array.isArray(base.duty)) base.duty = [];
    if (!base.counters || typeof base.counters !== 'object') base.counters = {};
    return base;
  } catch (error) {
    console.error('[DB] Nie udało się wczytać bazy:', error);
    const backupName = `${DB_FILE}.broken-${Date.now()}`;
    try {
      if (fs.existsSync(DB_FILE)) fs.copyFileSync(DB_FILE, backupName);
    } catch {}
    const initial = emptyDatabase();
    saveDatabase(initial);
    return initial;
  }
}

function saveDatabase(database) {
  database.meta.updatedAt = new Date().toISOString();
  fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
  const temp = `${DB_FILE}.tmp`;
  fs.writeFileSync(temp, JSON.stringify(database, null, 2), 'utf8');
  fs.renameSync(temp, DB_FILE);
}

let db = loadDatabase();

function nextRecordId(collection) {
  const cfg = COLLECTIONS[collection];
  const year = new Date().getFullYear();
  const key = `${collection}:${year}`;
  db.counters[key] = Number(db.counters[key] || 0) + 1;
  return `${cfg.prefix}-${year}-${String(db.counters[key]).padStart(5, '0')}`;
}

function cleanText(value, max = 5000) {
  if (value === null || value === undefined) return '';
  return String(value).replace(/\u0000/g, '').trim().slice(0, max);
}

function cleanPayload(payload) {
  const result = {};
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return result;

  for (const [key, value] of Object.entries(payload)) {
    if (!/^[a-zA-Z0-9_]+$/.test(key)) continue;

    if (typeof value === 'string') {
      result[key] = cleanText(value);
    } else if (typeof value === 'number' && Number.isFinite(value)) {
      result[key] = value;
    } else if (typeof value === 'boolean') {
      result[key] = value;
    } else if (Array.isArray(value)) {
      result[key] = value.slice(0, 100).map(item => cleanText(item, 500));
    } else if (value === null) {
      result[key] = null;
    }
  }
  return result;
}

function addAudit(req, action, collection, recordId, details = '') {
  const user = req.authUser || {};
  db.audit.unshift({
    id: `AUD-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`,
    action,
    collection,
    recordId,
    details: cleanText(details, 1000),
    actorId: user.id || '',
    actorName: user.displayName || user.username || 'System',
    timestamp: new Date().toISOString(),
    ip: req.ip || ''
  });

  if (db.audit.length > MAX_AUDIT) db.audit.length = MAX_AUDIT;
}

function findById(collection, id) {
  return db[collection].find(item => item.id === id);
}

function deleteRelations(collection, id) {
  if (collection === 'citizens') {
    for (const vehicle of db.vehicles) {
      if (vehicle.ownerId === id) vehicle.ownerId = '';
    }
    for (const key of ['tickets', 'arrests', 'reports']) {
      for (const item of db[key]) {
        if (item.citizenId === id) item.citizenId = '';
      }
    }
  }

  if (collection === 'vehicles') {
    for (const ticket of db.tickets) {
      if (ticket.vehicleId === id) ticket.vehicleId = '';
    }
  }
}

function ensureDutyRecord(user) {
  let record = db.duty.find(item => String(item.userId) === String(user.id));
  let changed = false;

  if (!record) {
    record = {
      userId: String(user.id),
      displayName: cleanText(user.displayName || user.username || `Użytkownik ${user.id}`, 100),
      avatar: cleanText(user.avatar, 500),
      totalMs: 0,
      activeSince: null,
      lastStartedAt: null,
      lastEndedAt: null,
      shifts: [],
      callSign: '',
      unitType: '',
      vehicle: '',
      partner: '',
      radioChannel: '',
      patrolStatus: 'Poza służbą',
      statusUpdatedAt: null,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    db.duty.push(record);
    changed = true;
  }

  const currentName = cleanText(user.displayName || user.username || record.displayName, 100);
  const currentAvatar = cleanText(user.avatar, 500);
  if (record.displayName !== currentName) {
    record.displayName = currentName;
    changed = true;
  }
  if (record.avatar !== currentAvatar) {
    record.avatar = currentAvatar;
    changed = true;
  }
  if (!Array.isArray(record.shifts)) {
    record.shifts = [];
    changed = true;
  }
  if (record.activeSince && !Number.isFinite(new Date(record.activeSince).getTime())) {
    record.activeSince = null;
    changed = true;
  }
  if (!Number.isFinite(Number(record.totalMs)) || Number(record.totalMs) < 0) {
    record.totalMs = 0;
    changed = true;
  } else {
    record.totalMs = Number(record.totalMs);
  }

  const dutyDefaults = {
    callSign: '',
    unitType: '',
    vehicle: '',
    partner: '',
    radioChannel: '',
    patrolStatus: record.activeSince ? 'Dostępny' : 'Poza służbą',
    statusUpdatedAt: null
  };
  for (const [key, value] of Object.entries(dutyDefaults)) {
    if (record[key] === undefined || record[key] === null) {
      record[key] = value;
      changed = true;
    }
  }

  return { record, changed };
}

function dutySnapshot(record, nowMs = Date.now()) {
  const activeStartMs = record.activeSince ? new Date(record.activeSince).getTime() : NaN;
  const active = Number.isFinite(activeStartMs);
  const currentSessionMs = active ? Math.max(0, nowMs - activeStartMs) : 0;

  return {
    userId: String(record.userId),
    displayName: cleanText(record.displayName || 'Funkcjonariusz', 100),
    avatar: cleanText(record.avatar, 500),
    active,
    activeSince: active ? record.activeSince : null,
    currentSessionMs,
    totalMs: Math.max(0, Number(record.totalMs || 0)) + currentSessionMs,
    lastStartedAt: record.lastStartedAt || null,
    lastEndedAt: record.lastEndedAt || null,
    shiftCount: Array.isArray(record.shifts) ? record.shifts.length : 0,
    callSign: cleanText(record.callSign, 32),
    unitType: cleanText(record.unitType, 80),
    vehicle: cleanText(record.vehicle, 120),
    partner: cleanText(record.partner, 120),
    radioChannel: cleanText(record.radioChannel, 40),
    patrolStatus: active ? cleanText(record.patrolStatus || 'Dostępny', 40) : 'Poza służbą',
    statusUpdatedAt: record.statusUpdatedAt || null
  };
}

function getDutyLeaderboard(nowMs = Date.now()) {
  return db.duty
    .map(record => dutySnapshot(record, nowMs))
    .sort((a, b) => {
      if (b.totalMs !== a.totalMs) return b.totalMs - a.totalMs;
      if (a.active !== b.active) return a.active ? -1 : 1;
      return a.displayName.localeCompare(b.displayName, 'pl');
    });
}


function activeDutySnapshots(nowMs = Date.now()) {
  return getDutyLeaderboard(nowMs)
    .filter(item => item.active)
    .sort((a, b) => {
      const aKey = a.callSign || a.displayName;
      const bKey = b.callSign || b.displayName;
      return aKey.localeCompare(bKey, 'pl', { numeric: true });
    });
}

async function sendDiscordWebhook(title, description, color = 3100927, fields = []) {
  if (!DISCORD_LOG_WEBHOOK_URL || !/^https:\/\/(?:canary\.|ptb\.)?(?:discord(?:app)?\.com)\/api\/webhooks\//i.test(DISCORD_LOG_WEBHOOK_URL)) return;
  try {
    const response = await fetch(DISCORD_LOG_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'KSP • CAD/MDT',
        embeds: [{
          title: cleanText(title, 256),
          description: cleanText(description, 4000),
          color,
          fields: fields.slice(0, 20).map(field => ({
            name: cleanText(field.name, 256),
            value: cleanText(field.value, 1024) || '—',
            inline: Boolean(field.inline)
          })),
          timestamp: new Date().toISOString(),
          footer: { text: 'System wewnętrzny RP' }
        }]
      })
    });
    if (!response.ok) console.warn('[DISCORD] Webhook:', response.status, await response.text());
  } catch (error) {
    console.warn('[DISCORD] Nie udało się wysłać webhooka:', error.message);
  }
}

async function syncDiscordDutyRole(userId, shouldAdd) {
  if (!DISCORD_BOT_TOKEN || !DISCORD_ON_DUTY_ROLE_ID || !userId) return;
  const url = `https://discord.com/api/v10/guilds/${encodeURIComponent(DISCORD_GUILD_ID)}/members/${encodeURIComponent(userId)}/roles/${encodeURIComponent(DISCORD_ON_DUTY_ROLE_ID)}`;
  try {
    const response = await fetch(url, {
      method: shouldAdd ? 'PUT' : 'DELETE',
      headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` }
    });
    if (!response.ok && response.status !== 204) {
      console.warn('[DISCORD] Synchronizacja roli:', response.status, await response.text());
    }
  } catch (error) {
    console.warn('[DISCORD] Nie udało się zsynchronizować roli:', error.message);
  }
}

function appendDispatchHistory(record, req, action, details = '') {
  if (!Array.isArray(record.history)) record.history = [];
  record.history.unshift({
    action: cleanText(action, 100),
    details: cleanText(details, 500),
    actorId: req.authUser.id,
    actorName: req.authUser.displayName || req.authUser.username,
    timestamp: new Date().toISOString()
  });
  if (record.history.length > 100) record.history.length = 100;
}

/* -------------------------------------------------------------------------- */
/*                               COOKIE / SESSION                             */
/* -------------------------------------------------------------------------- */

const sessions = new Map();
const oauthStates = new Map();

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  header.split(';').forEach(part => {
    const index = part.indexOf('=');
    if (index < 0) return;
    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    try {
      out[key] = decodeURIComponent(value);
    } catch {
      out[key] = value;
    }
  });
  return out;
}

function hmac(value) {
  return crypto.createHmac('sha256', SESSION_SECRET).update(value).digest('base64url');
}

function signCookie(value) {
  return `${value}.${hmac(value)}`;
}

function verifySignedCookie(signed) {
  if (!signed || !signed.includes('.')) return null;
  const index = signed.lastIndexOf('.');
  const value = signed.slice(0, index);
  const signature = signed.slice(index + 1);
  const expected = hmac(value);

  try {
    if (
      signature.length === expected.length &&
      crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))
    ) {
      return value;
    }
  } catch {}
  return null;
}

function setCookie(res, name, value, options = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  parts.push(`Path=${options.path || '/'}`);
  parts.push(`SameSite=${options.sameSite || 'Lax'}`);

  if (options.httpOnly !== false) parts.push('HttpOnly');
  if (options.secure ?? BASE_URL.startsWith('https://')) parts.push('Secure');
  if (options.maxAge !== undefined) parts.push(`Max-Age=${Math.floor(options.maxAge / 1000)}`);
  if (options.expires) parts.push(`Expires=${options.expires.toUTCString()}`);

  res.append('Set-Cookie', parts.join('; '));
}

function clearCookie(res, name) {
  setCookie(res, name, '', { maxAge: 0, expires: new Date(0) });
}

function createSession(user) {
  const token = crypto.randomBytes(32).toString('base64url');
  sessions.set(token, {
    user,
    createdAt: Date.now(),
    expiresAt: Date.now() + SESSION_TTL_MS
  });
  return token;
}

function getSession(req) {
  const cookies = parseCookies(req);
  const token = verifySignedCookie(cookies.ksp_session);
  if (!token) return null;

  const session = sessions.get(token);
  if (!session) return null;

  if (Date.now() > session.expiresAt) {
    sessions.delete(token);
    return null;
  }

  session.expiresAt = Date.now() + SESSION_TTL_MS;
  return { token, ...session };
}

function requireAuth(req, res, next) {
  const session = getSession(req);
  if (!session) {
    return res.status(401).json({ error: 'AUTH_REQUIRED', loginUrl: '/auth/login' });
  }
  req.authUser = session.user;
  req.authSessionToken = session.token;

  if (
    session.user &&
    session.user.isPreview &&
    !['GET', 'HEAD', 'OPTIONS'].includes(String(req.method || '').toUpperCase())
  ) {
    return res.status(403).json({
      error: 'Tryb podglądu działa tylko do odczytu. Zaloguj się przez Discord, aby zapisywać zmiany.'
    });
  }

  next();
}

setInterval(() => {
  const now = Date.now();
  for (const [key, session] of sessions) {
    if (now > session.expiresAt) sessions.delete(key);
  }
  for (const [key, state] of oauthStates) {
    if (now > state.expiresAt) oauthStates.delete(key);
  }
  for (const [key, bucket] of rateBuckets) {
    if (now > bucket.resetAt) rateBuckets.delete(key);
  }
}, 5 * 60 * 1000).unref();

/* -------------------------------------------------------------------------- */
/*                               DISCORD OAUTH2                               */
/* -------------------------------------------------------------------------- */

function discordAvatarUrl(user) {
  if (!user || !user.id || !user.avatar) return '';
  const extension = user.avatar.startsWith('a_') ? 'gif' : 'png';
  return `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.${extension}?size=128`;
}

async function discordApi(endpoint, accessToken) {
  const response = await fetch(`https://discord.com/api/v10${endpoint}`, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'User-Agent': 'Liberty-Operations-Center/3.0'
    }
  });

  if (!response.ok) {
    const body = await response.text();
    const error = new Error(`Discord API ${response.status}: ${body.slice(0, 300)}`);
    error.status = response.status;
    throw error;
  }

  return response.json();
}

app.get('/auth/login', (req, res) => {
  if (!DISCORD_CLIENT_SECRET) {
    return res
      .status(500)
      .send('Administrator nie ustawił DISCORD_CLIENT_SECRET na serwerze.');
  }

  const state = crypto.randomBytes(24).toString('base64url');
  oauthStates.set(state, { expiresAt: Date.now() + OAUTH_STATE_TTL_MS });

  setCookie(res, 'ksp_oauth_state', signCookie(state), {
    maxAge: OAUTH_STATE_TTL_MS,
    sameSite: 'Lax'
  });

  const redirectUri = `${BASE_URL}/auth/callback`;
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: DISCORD_CLIENT_ID,
    scope: 'identify guilds.members.read',
    state,
    redirect_uri: redirectUri,
    prompt: 'consent'
  });

  res.redirect(`https://discord.com/oauth2/authorize?${params.toString()}`);
});

app.get('/auth/callback', async (req, res) => {
  try {
    const code = cleanText(req.query.code, 500);
    const returnedState = cleanText(req.query.state, 500);
    const cookies = parseCookies(req);
    const cookieState = verifySignedCookie(cookies.ksp_oauth_state);

    clearCookie(res, 'ksp_oauth_state');

    if (
      !code ||
      !returnedState ||
      !cookieState ||
      returnedState !== cookieState ||
      !oauthStates.has(returnedState)
    ) {
      return res.redirect('/?authError=Nieprawidlowy_stan_OAuth');
    }

    oauthStates.delete(returnedState);

    const redirectUri = `${BASE_URL}/auth/callback`;
    const tokenBody = new URLSearchParams({
      client_id: DISCORD_CLIENT_ID,
      client_secret: DISCORD_CLIENT_SECRET,
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri
    });

    const tokenResponse = await fetch('https://discord.com/api/v10/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: tokenBody.toString()
    });

    if (!tokenResponse.ok) {
      const text = await tokenResponse.text();
      console.error('[OAuth] Token exchange:', tokenResponse.status, text);
      if (tokenResponse.status === 429) {
        return res.redirect('/?authError=Discord_tymczasowo_ograniczyl_logowanie_sprobuj_ponownie_pozniej');
      }
      return res.redirect('/?authError=Nie_udalo_sie_pobrac_tokenu');
    }

    const tokenData = await tokenResponse.json();
    const accessToken = tokenData.access_token;

    const [discordUser, member] = await Promise.all([
      discordApi('/users/@me', accessToken),
      discordApi(`/users/@me/guilds/${DISCORD_GUILD_ID}/member`, accessToken)
    ]);

    const roles = Array.isArray(member.roles) ? member.roles.map(String) : [];
    const hasAccess = !DISCORD_REQUIRE_ROLE || roles.includes(DISCORD_ROLE_ID);
    const isAdmin = DISCORD_ADMIN_ROLE_ID ? roles.includes(DISCORD_ADMIN_ROLE_ID) : false;

    if (!hasAccess) {
      return res.redirect('/?authError=Brak_wymaganej_roli_na_serwerze');
    }

    const displayName =
      member.nick ||
      discordUser.global_name ||
      discordUser.username ||
      `Użytkownik ${discordUser.id}`;

    const sessionToken = createSession({
      id: String(discordUser.id),
      username: cleanText(discordUser.username, 64),
      displayName: cleanText(displayName, 64),
      avatar: discordAvatarUrl(discordUser),
      roles,
      isAdmin
    });

    setCookie(res, 'ksp_session', signCookie(sessionToken), {
      maxAge: SESSION_TTL_MS,
      sameSite: 'Lax'
    });

    res.redirect('/');
  } catch (error) {
    console.error('[OAuth] Callback error:', error);
    if (error.status === 404) {
      return res.redirect('/?authError=Nie_jestes_czlonkiem_wymaganego_serwera');
    }
    res.redirect('/?authError=Blad_logowania_Discord');
  }
});

app.get('/auth/logout', (req, res) => {
  const session = getSession(req);
  if (session) sessions.delete(session.token);
  clearCookie(res, 'ksp_session');
  res.redirect('/');
});

app.get('/auth/preview', (req, res) => {
  if (!PREVIEW_LOGIN_ENABLED) {
    return res.status(404).send('Tryb podglądu jest wyłączony.');
  }

  const token = createSession({
    id: 'preview-readonly',
    username: 'podglad',
    displayName: 'Gość podglądu',
    avatar: '',
    roles: [],
    isAdmin: false,
    isPreview: true
  });

  setCookie(res, 'ksp_session', signCookie(token), {
    maxAge: 60 * 60 * 1000,
    sameSite: 'Lax'
  });

  res.redirect('/');
});


app.get('/auth/dev', (req, res) => {
  if (!DEV_LOGIN_ENABLED) return res.status(404).send('Tryb lokalny jest wyłączony.');
  const token = createSession({
    id: '100000000000000001',
    username: 'tester',
    displayName: 'Tester lokalny',
    avatar: '',
    roles: [DISCORD_ROLE_ID, DISCORD_ADMIN_ROLE_ID].filter(Boolean),
    isAdmin: true
  });
  setCookie(res, 'ksp_session', signCookie(token), { maxAge: SESSION_TTL_MS, sameSite: 'Lax', secure: false });
  res.redirect('/');
});

/* -------------------------------------------------------------------------- */
/*                                    API                                     */
/* -------------------------------------------------------------------------- */

app.get('/api/me', requireAuth, (req, res) => {
  res.json({
    user: req.authUser,
    guildId: DISCORD_GUILD_ID,
    roleId: DISCORD_ROLE_ID,
    requireRole: DISCORD_REQUIRE_ROLE,
    serverTime: new Date().toISOString()
  });
});

app.get('/api/integrations/status', requireAuth, (req, res) => {
  res.json({
    discord: {
      oauth: Boolean(DISCORD_CLIENT_ID && DISCORD_CLIENT_SECRET && DISCORD_GUILD_ID),
      guildVerification: Boolean(DISCORD_GUILD_ID),
      roleGate: DISCORD_REQUIRE_ROLE,
      bot: Boolean(DISCORD_BOT_TOKEN),
      webhook: Boolean(DISCORD_LOG_WEBHOOK_URL)
    },
    erlc: {
      api: Boolean(ERLC_SERVER_KEY),
      webhookVerification: Boolean(ERLC_WEBHOOK_PUBLIC_KEY)
    },
    storage: {
      engine: 'JSON',
      persistentPath: path.isAbsolute(DB_FILE_SETTING),
      file: path.basename(DB_FILE)
    },
    version: '3.0-preview'
  });
});

app.get('/api/duty', requireAuth, (req, res) => {
  const nowMs = Date.now();

  if (req.authUser && req.authUser.isPreview) {
    return res.json({
      serverTime: new Date(nowMs).toISOString(),
      current: {
        userId: req.authUser.id,
        displayName: req.authUser.displayName,
        avatar: '',
        active: false,
        activeSince: '',
        totalMs: 0,
        shiftCount: 0,
        callSign: '',
        patrolStatus: 'Poza służbą',
        unitType: '',
        vehicle: '',
        partner: '',
        radioChannel: ''
      },
      leaderboard: getDutyLeaderboard(nowMs)
    });
  }

  const ensured = ensureDutyRecord(req.authUser);
  if (ensured.changed) saveDatabase(db);

  res.json({
    serverTime: new Date(nowMs).toISOString(),
    current: dutySnapshot(ensured.record, nowMs),
    leaderboard: getDutyLeaderboard(nowMs)
  });
});

app.post('/api/duty/start', requireAuth, (req, res) => {
  const ensured = ensureDutyRecord(req.authUser);
  const record = ensured.record;

  if (record.activeSince) {
    return res.status(409).json({ error: 'Służba jest już rozpoczęta.' });
  }

  const payload = cleanPayload(req.body);
  const callSign = cleanText(payload.callSign, 32).toUpperCase();
  if (!callSign) {
    return res.status(400).json({ error: 'Wpisz callsign patrolu przed rozpoczęciem służby.' });
  }
  const duplicateCallSign = db.duty.find(item =>
    item.activeSince && String(item.userId) !== String(record.userId) && String(item.callSign || '').toUpperCase() === callSign
  );
  if (duplicateCallSign) {
    return res.status(409).json({ error: 'Ten callsign jest już używany przez aktywny patrol.' });
  }

  const now = new Date().toISOString();
  record.activeSince = now;
  record.lastStartedAt = now;
  record.updatedAt = now;
  record.callSign = callSign;
  record.unitType = cleanText(payload.unitType || 'Patrol', 80);
  record.vehicle = cleanText(payload.vehicle, 120);
  record.partner = cleanText(payload.partner, 120);
  record.radioChannel = cleanText(payload.radioChannel, 40);
  record.patrolStatus = 'Dostępny';
  record.statusUpdatedAt = now;

  addAudit(req, 'DUTY_START', 'duty', record.userId, `Rozpoczęto służbę jako ${record.callSign}`);
  saveDatabase(db);

  void syncDiscordDutyRole(record.userId, true);
  void sendDiscordWebhook(
    'Rozpoczęcie służby',
    `**${record.displayName}** rozpoczął służbę jako **${record.callSign}**.`,
    3920785,
    [
      { name: 'Rodzaj patrolu', value: record.unitType || 'Patrol', inline: true },
      { name: 'Radiowóz', value: record.vehicle || 'Nie przypisano', inline: true },
      { name: 'Kanał', value: record.radioChannel || 'Nie przypisano', inline: true },
      { name: 'Partner', value: record.partner || 'Patrol jednoosobowy', inline: true }
    ]
  );

  const nowMs = Date.now();
  res.json({
    current: dutySnapshot(record, nowMs),
    leaderboard: getDutyLeaderboard(nowMs)
  });
});

app.post('/api/duty/stop', requireAuth, (req, res) => {
  const ensured = ensureDutyRecord(req.authUser);
  const record = ensured.record;

  if (!record.activeSince) {
    return res.status(409).json({ error: 'Służba nie jest obecnie aktywna.' });
  }

  const endedAt = new Date();
  const startedAt = new Date(record.activeSince);
  const durationMs = Math.max(0, endedAt.getTime() - startedAt.getTime());
  const dutyDetails = {
    callSign: record.callSign,
    unitType: record.unitType,
    vehicle: record.vehicle,
    partner: record.partner,
    radioChannel: record.radioChannel
  };

  record.totalMs = Math.max(0, Number(record.totalMs || 0)) + durationMs;
  record.shifts.unshift({
    startedAt: record.activeSince,
    endedAt: endedAt.toISOString(),
    durationMs,
    ...dutyDetails
  });
  if (record.shifts.length > MAX_DUTY_SHIFTS_PER_USER) {
    record.shifts.length = MAX_DUTY_SHIFTS_PER_USER;
  }
  record.activeSince = null;
  record.lastEndedAt = endedAt.toISOString();
  record.updatedAt = endedAt.toISOString();
  record.patrolStatus = 'Poza służbą';
  record.statusUpdatedAt = endedAt.toISOString();

  for (const dispatch of db.dispatch) {
    if (!Array.isArray(dispatch.assignedUnitIds) || !dispatch.assignedUnitIds.includes(record.userId)) continue;
    if (['Zamknięte', 'Anulowane'].includes(dispatch.status)) continue;
    dispatch.assignedUnitIds = dispatch.assignedUnitIds.filter(id => String(id) !== String(record.userId));
    const assigned = dispatch.assignedUnitIds
      .map(id => db.duty.find(item => String(item.userId) === String(id)))
      .filter(Boolean);
    dispatch.units = assigned.map(item => item.callSign || item.displayName).join(', ');
    dispatch.updatedAt = endedAt.toISOString();
    appendDispatchHistory(dispatch, req, 'UNIT_REMOVED', `${dutyDetails.callSign || record.displayName} zakończył służbę`);
  }

  addAudit(req, 'DUTY_STOP', 'duty', record.userId, `Zakończono służbę ${dutyDetails.callSign || ''} (${Math.round(durationMs / 60000)} min)`);
  saveDatabase(db);

  void syncDiscordDutyRole(record.userId, false);
  void sendDiscordWebhook(
    'Zakończenie służby',
    `**${record.displayName}** zakończył służbę **${dutyDetails.callSign || ''}**.`,
    16007990,
    [{ name: 'Czas zmiany', value: `${Math.floor(durationMs / 3600000)} godz. ${String(Math.floor((durationMs % 3600000) / 60000)).padStart(2, '0')} min`, inline: true }]
  );

  const nowMs = Date.now();
  res.json({
    current: dutySnapshot(record, nowMs),
    leaderboard: getDutyLeaderboard(nowMs)
  });
});

app.patch('/api/duty/status', requireAuth, (req, res) => {
  const ensured = ensureDutyRecord(req.authUser);
  const record = ensured.record;
  if (!record.activeSince) {
    return res.status(409).json({ error: 'Najpierw rozpocznij służbę.' });
  }

  const status = cleanText(req.body && req.body.status, 40);
  if (!PATROL_STATUSES.includes(status)) {
    return res.status(400).json({ error: 'Nieprawidłowy status patrolu.' });
  }
  const assignedOpenCall = db.dispatch.find(item =>
    !['Zamknięte', 'Anulowane'].includes(item.status) &&
    Array.isArray(item.assignedUnitIds) &&
    item.assignedUnitIds.map(String).includes(String(record.userId))
  );
  if (status === 'Dostępny' && assignedOpenCall) {
    return res.status(409).json({ error: `Najpierw zamknij lub odłącz patrol od zgłoszenia ${assignedOpenCall.callNo || assignedOpenCall.id}.` });
  }

  record.patrolStatus = status;
  record.statusUpdatedAt = new Date().toISOString();
  record.updatedAt = record.statusUpdatedAt;
  addAudit(req, 'PATROL_STATUS', 'duty', record.userId, `${record.callSign}: ${status}`);
  saveDatabase(db);

  res.json({ current: dutySnapshot(record), leaderboard: getDutyLeaderboard() });
});

app.get('/api/cad', requireAuth, (req, res) => {
  const ensured = ensureDutyRecord(req.authUser);
  if (ensured.changed) saveDatabase(db);

  const units = activeDutySnapshots();
  const priorityOrder = { P1: 1, P2: 2, P3: 3, P4: 4 };
  const calls = db.dispatch
    .filter(item => !['Zamknięte', 'Anulowane'].includes(item.status))
    .map(item => ({
      ...item,
      assignedUnitIds: Array.isArray(item.assignedUnitIds) ? item.assignedUnitIds.map(String) : []
    }))
    .sort((a, b) => {
      const pa = priorityOrder[String(a.priority || '').slice(0, 2)] || 9;
      const pb = priorityOrder[String(b.priority || '').slice(0, 2)] || 9;
      if (pa !== pb) return pa - pb;
      return new Date(a.createdAtCustom || a.createdAt || 0) - new Date(b.createdAtCustom || b.createdAt || 0);
    });

  res.json({
    serverTime: new Date().toISOString(),
    current: dutySnapshot(ensured.record),
    units,
    calls,
    stats: {
      activeUnits: units.length,
      availableUnits: units.filter(item => item.patrolStatus === 'Dostępny').length,
      urgentCalls: calls.filter(item => String(item.priority || '').startsWith('P1')).length,
      openCalls: calls.length
    }
  });
});

app.post('/api/dispatch/:id/assign', requireAuth, (req, res) => {
  const dispatch = findById('dispatch', req.params.id);
  if (!dispatch) return res.status(404).json({ error: 'Nie znaleziono zgłoszenia.' });

  const userId = cleanText(req.body && req.body.userId, 40);
  const unit = db.duty.find(item => String(item.userId) === userId && item.activeSince);
  if (!unit) return res.status(400).json({ error: 'Wybrana jednostka nie jest aktywna.' });
  const otherAssignment = db.dispatch.find(item =>
    item.id !== dispatch.id &&
    !['Zamknięte', 'Anulowane'].includes(item.status) &&
    Array.isArray(item.assignedUnitIds) &&
    item.assignedUnitIds.map(String).includes(userId)
  );
  if (otherAssignment) {
    return res.status(409).json({ error: `Jednostka jest już przydzielona do ${otherAssignment.callNo || otherAssignment.id}.` });
  }

  if (!Array.isArray(dispatch.assignedUnitIds)) dispatch.assignedUnitIds = [];
  if (!dispatch.assignedUnitIds.map(String).includes(userId)) dispatch.assignedUnitIds.push(userId);

  const assigned = dispatch.assignedUnitIds
    .map(id => db.duty.find(item => String(item.userId) === String(id)))
    .filter(Boolean);
  dispatch.units = assigned.map(item => item.callSign || item.displayName).join(', ');
  if (!dispatch.status || dispatch.status === 'Nowe') dispatch.status = 'Przyjęte';
  dispatch.updatedAt = new Date().toISOString();
  unit.patrolStatus = 'Przydzielony';
  unit.statusUpdatedAt = dispatch.updatedAt;
  appendDispatchHistory(dispatch, req, 'UNIT_ASSIGNED', `${unit.callSign || unit.displayName} przydzielony do zgłoszenia`);
  addAudit(req, 'DISPATCH_ASSIGN', 'dispatch', dispatch.id, `${unit.callSign || unit.displayName}`);
  saveDatabase(db);

  void sendDiscordWebhook(
    `Przydział do ${dispatch.callNo || dispatch.id}`,
    `Jednostka **${unit.callSign || unit.displayName}** została przydzielona do zgłoszenia.`,
    16762967,
    [
      { name: 'Kategoria', value: dispatch.category || 'Zdarzenie', inline: true },
      { name: 'Priorytet', value: dispatch.priority || 'Standard', inline: true },
      { name: 'Lokalizacja', value: dispatch.location || 'Nie podano', inline: false }
    ]
  );

  res.json({ item: dispatch, unit: dutySnapshot(unit) });
});

app.post('/api/dispatch/:id/unassign', requireAuth, (req, res) => {
  const dispatch = findById('dispatch', req.params.id);
  if (!dispatch) return res.status(404).json({ error: 'Nie znaleziono zgłoszenia.' });

  const userId = cleanText(req.body && req.body.userId, 40);
  if (!Array.isArray(dispatch.assignedUnitIds)) dispatch.assignedUnitIds = [];
  dispatch.assignedUnitIds = dispatch.assignedUnitIds.filter(id => String(id) !== userId);
  const unit = db.duty.find(item => String(item.userId) === userId);
  const assigned = dispatch.assignedUnitIds
    .map(id => db.duty.find(item => String(item.userId) === String(id)))
    .filter(Boolean);
  dispatch.units = assigned.map(item => item.callSign || item.displayName).join(', ');
  dispatch.updatedAt = new Date().toISOString();
  if (unit && unit.activeSince) {
    unit.patrolStatus = 'Dostępny';
    unit.statusUpdatedAt = dispatch.updatedAt;
  }
  appendDispatchHistory(dispatch, req, 'UNIT_REMOVED', `${unit ? (unit.callSign || unit.displayName) : userId} odłączony od zgłoszenia`);
  addAudit(req, 'DISPATCH_UNASSIGN', 'dispatch', dispatch.id, `${unit ? (unit.callSign || unit.displayName) : userId}`);
  saveDatabase(db);
  res.json({ item: dispatch });
});

app.post('/api/dispatch/:id/status', requireAuth, (req, res) => {
  const dispatch = findById('dispatch', req.params.id);
  if (!dispatch) return res.status(404).json({ error: 'Nie znaleziono zgłoszenia.' });

  const status = cleanText(req.body && req.body.status, 60);
  if (!DISPATCH_STATUSES.includes(status)) {
    return res.status(400).json({ error: 'Nieprawidłowy status zgłoszenia.' });
  }

  dispatch.status = status;
  dispatch.updatedAt = new Date().toISOString();
  if (['Zamknięte', 'Anulowane'].includes(status)) dispatch.closedAt = dispatch.updatedAt;
  appendDispatchHistory(dispatch, req, 'STATUS_CHANGED', status);

  const unitStatusMap = {
    'Przyjęte': 'Przydzielony',
    'Jednostka w drodze': 'W drodze',
    'Na miejscu': 'Na miejscu'
  };
  for (const userId of Array.isArray(dispatch.assignedUnitIds) ? dispatch.assignedUnitIds : []) {
    const unit = db.duty.find(item => String(item.userId) === String(userId));
    if (!unit || !unit.activeSince) continue;
    unit.patrolStatus = unitStatusMap[status] || (['Zamknięte', 'Anulowane'].includes(status) ? 'Dostępny' : unit.patrolStatus);
    unit.statusUpdatedAt = dispatch.updatedAt;
  }

  addAudit(req, 'DISPATCH_STATUS', 'dispatch', dispatch.id, status);
  saveDatabase(db);
  res.json({ item: dispatch });
});

app.get('/api/dashboard', requireAuth, (req, res) => {
  const activeWanted = db.wanted.filter(item => item.status !== 'Zamknięte');
  const openDispatch = db.dispatch.filter(item => !['Zamknięte', 'Anulowane'].includes(item.status));
  const activeArrests = db.arrests.filter(item => item.status === 'Aktywne');
  const unpaidTickets = db.tickets.filter(item => item.status === 'Nieopłacony');
  const activeUnits = activeDutySnapshots();

  res.json({
    stats: {
      citizens: db.citizens.length,
      vehicles: db.vehicles.length,
      tickets: db.tickets.length,
      arrests: db.arrests.length,
      reports: db.reports.length,
      activeWanted: activeWanted.length,
      openDispatch: openDispatch.length,
      unpaidTickets: unpaidTickets.length,
      activeDuty: activeUnits.length,
      availableDuty: activeUnits.filter(item => item.patrolStatus === 'Dostępny').length,
      urgentDispatch: openDispatch.filter(item => String(item.priority || '').startsWith('P1')).length
    },
    activeUnits: activeUnits.slice(0, 12),
    activeWanted: activeWanted.slice(0, 8),
    openDispatch: openDispatch.slice(0, 8),
    activeArrests: activeArrests.slice(0, 8),
    recentAudit: db.audit.slice(0, 12)
  });
});

app.get('/api/search', requireAuth, (req, res) => {
  const query = cleanText(req.query.q, 200).toLowerCase();
  if (query.length < 2) return res.json({ results: [] });

  const results = [];
  for (const [collection, cfg] of Object.entries(COLLECTIONS)) {
    for (const item of db[collection]) {
      const haystack = Object.values(item)
        .filter(value => ['string', 'number'].includes(typeof value))
        .join(' ')
        .toLowerCase();

      if (haystack.includes(query)) {
        results.push({
          collection,
          collectionLabel: cfg.label,
          id: item.id,
          title:
            item.fullName ||
            item.title ||
            item.plate ||
            item.caseNo ||
            item.callNo ||
            item.name ||
            item.id,
          subtitle:
            item.description ||
            item.reason ||
            item.summary ||
            item.address ||
            item.status ||
            ''
        });
      }
    }
  }

  res.json({ results: results.slice(0, 60) });
});

app.get('/api/export', requireAuth, (req, res) => {
  addAudit(req, 'EXPORT', 'database', 'ALL', 'Eksport pełnej bazy JSON');
  saveDatabase(db);

  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader(
    'Content-Disposition',
    `attachment; filename="ksp-mdt-backup-${new Date().toISOString().slice(0, 10)}.json"`
  );
  res.send(JSON.stringify(db, null, 2));
});

app.get('/api/audit', requireAuth, (req, res) => {
  const limit = Math.min(Math.max(Number(req.query.limit || 200), 1), 1000);
  res.json({ items: db.audit.slice(0, limit) });
});

app.get('/api/:collection', requireAuth, (req, res, next) => {
  const collection = req.params.collection;
  if (!COLLECTIONS[collection]) return next();

  const query = cleanText(req.query.q, 200).toLowerCase();
  const status = cleanText(req.query.status, 100);
  let items = [...db[collection]];

  if (query) {
    items = items.filter(item =>
      Object.values(item)
        .filter(value => ['string', 'number'].includes(typeof value))
        .join(' ')
        .toLowerCase()
        .includes(query)
    );
  }

  if (status) items = items.filter(item => String(item.status || '') === status);

  items.sort((a, b) => {
    const da = new Date(a.updatedAt || a.createdAt || 0).getTime();
    const dbb = new Date(b.updatedAt || b.createdAt || 0).getTime();
    return dbb - da;
  });

  res.json({ items });
});

app.get('/api/:collection/:id', requireAuth, (req, res, next) => {
  const collection = req.params.collection;
  if (!COLLECTIONS[collection]) return next();

  const item = findById(collection, req.params.id);
  if (!item) return res.status(404).json({ error: 'Nie znaleziono rekordu.' });

  res.json({ item });
});

app.post('/api/:collection', requireAuth, (req, res, next) => {
  const collection = req.params.collection;
  if (!COLLECTIONS[collection]) return next();

  const payload = cleanPayload(req.body);
  const now = new Date().toISOString();
  const id = nextRecordId(collection);

  const record = {
    ...payload,
    id,
    createdAt: now,
    updatedAt: now,
    createdBy: req.authUser.displayName,
    createdById: req.authUser.id
  };

  if (collection === 'citizens') {
    record.fullName = cleanText(
      `${record.firstName || ''} ${record.lastName || ''}`.trim(),
      150
    );
  }

  if (['tickets', 'arrests', 'reports'].includes(collection) && !record.caseNo) {
    record.caseNo = id;
  }

  if (collection === 'dispatch' && !record.callNo) {
    record.callNo = id;
  }
  if (collection === 'dispatch') {
    record.assignedUnitIds = [];
    record.history = [];
    record.status = record.status || 'Nowe';
    record.createdAtCustom = record.createdAtCustom || now;
    appendDispatchHistory(record, req, 'CREATED', 'Przyjęto nowe zgłoszenie');
  }

  db[collection].unshift(record);
  addAudit(req, 'CREATE', collection, id, 'Utworzono rekord');
  saveDatabase(db);
  if (collection === 'dispatch') {
    void sendDiscordWebhook(
      `Nowe zgłoszenie ${record.callNo || record.id}`,
      `**${record.category || 'Zdarzenie'}** · ${record.location || 'Lokalizacja niepodana'}`,
      String(record.priority || '').startsWith('P1') ? 16733013 : 16762967,
      [
        { name: 'Priorytet', value: record.priority || 'Standard', inline: true },
        { name: 'Status', value: record.status || 'Nowe', inline: true },
        { name: 'Opis', value: record.description || 'Nie wpisano opisu', inline: false }
      ]
    );
  }
  res.status(201).json({ item: record });
});

app.put('/api/:collection/:id', requireAuth, (req, res, next) => {
  const collection = req.params.collection;
  if (!COLLECTIONS[collection]) return next();

  const index = db[collection].findIndex(item => item.id === req.params.id);
  if (index < 0) return res.status(404).json({ error: 'Nie znaleziono rekordu.' });

  const payload = cleanPayload(req.body);
  delete payload.id;
  delete payload.createdAt;
  delete payload.createdBy;
  delete payload.createdById;

  const old = db[collection][index];
  const updated = {
    ...old,
    ...payload,
    id: old.id,
    createdAt: old.createdAt,
    createdBy: old.createdBy,
    createdById: old.createdById,
    updatedAt: new Date().toISOString(),
    updatedBy: req.authUser.displayName,
    updatedById: req.authUser.id
  };

  if (collection === 'citizens') {
    updated.fullName = cleanText(
      `${updated.firstName || ''} ${updated.lastName || ''}`.trim(),
      150
    );
  }
  if (collection === 'dispatch') {
    if (!Array.isArray(updated.assignedUnitIds)) updated.assignedUnitIds = [];
    if (!Array.isArray(updated.history)) updated.history = [];
    if (old.status !== updated.status) {
      appendDispatchHistory(updated, req, 'STATUS_CHANGED', updated.status || 'Zmieniono status');
      if (['Zamknięte', 'Anulowane'].includes(updated.status)) updated.closedAt = updated.closedAt || updated.updatedAt;
      const unitStatusMap = {
        'Przyjęte': 'Przydzielony',
        'Jednostka w drodze': 'W drodze',
        'Na miejscu': 'Na miejscu'
      };
      for (const userId of updated.assignedUnitIds) {
        const unit = db.duty.find(item => String(item.userId) === String(userId));
        if (!unit || !unit.activeSince) continue;
        unit.patrolStatus = unitStatusMap[updated.status] || (['Zamknięte', 'Anulowane'].includes(updated.status) ? 'Dostępny' : unit.patrolStatus);
        unit.statusUpdatedAt = updated.updatedAt;
      }
    } else {
      appendDispatchHistory(updated, req, 'UPDATED', 'Zaktualizowano dane zgłoszenia');
    }
  }

  db[collection][index] = updated;
  addAudit(req, 'UPDATE', collection, old.id, 'Zaktualizowano rekord');
  saveDatabase(db);
  res.json({ item: updated });
});

app.delete('/api/:collection/:id', requireAuth, (req, res, next) => {
  const collection = req.params.collection;
  if (!COLLECTIONS[collection]) return next();

  if (!req.authUser.isAdmin) {
    return res.status(403).json({ error: 'Tylko administrator może usuwać rekordy.' });
  }

  const index = db[collection].findIndex(item => item.id === req.params.id);
  if (index < 0) return res.status(404).json({ error: 'Nie znaleziono rekordu.' });

  const [removed] = db[collection].splice(index, 1);
  if (collection === 'dispatch' && Array.isArray(removed.assignedUnitIds)) {
    for (const userId of removed.assignedUnitIds) {
      const unit = db.duty.find(item => String(item.userId) === String(userId));
      if (unit && unit.activeSince) {
        unit.patrolStatus = 'Dostępny';
        unit.statusUpdatedAt = new Date().toISOString();
      }
    }
  }
  deleteRelations(collection, removed.id);
  addAudit(req, 'DELETE', collection, removed.id, 'Usunięto rekord');
  saveDatabase(db);
  res.json({ ok: true });
});

app.use('/api', (req, res) => {
  res.status(404).json({ error: 'Nieznany endpoint API.' });
});

/* -------------------------------------------------------------------------- */
/*                                  FRONTEND                                  */
/* -------------------------------------------------------------------------- */

const HTML = String.raw`<!DOCTYPE html>
<html lang="pl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
  <meta name="theme-color" content="#07101d">
  <title>Liberty Operations Center | ER:LC RP</title>
  <style>
    :root {
      --bg-0: #050a12;
      --bg-1: #08111e;
      --bg-2: #0c1726;
      --panel: rgba(14, 27, 45, 0.92);
      --panel-2: rgba(20, 37, 59, 0.88);
      --panel-3: #172a42;
      --line: rgba(136, 177, 222, 0.16);
      --line-strong: rgba(136, 177, 222, 0.32);
      --text: #eef6ff;
      --muted: #91a7c0;
      --blue: #2f8cff;
      --blue-2: #67b2ff;
      --cyan: #55e7ff;
      --green: #3bd391;
      --yellow: #ffc857;
      --orange: #ff8a4c;
      --red: #ff5364;
      --purple: #a582ff;
      --shadow: 0 18px 60px rgba(0, 0, 0, 0.34);
      --radius: 16px;
      --radius-sm: 10px;
      --sidebar-width: 258px;
      --topbar-height: 72px;
      --font: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }

    * {
      box-sizing: border-box;
      scrollbar-color: rgba(103, 178, 255, 0.45) rgba(255, 255, 255, 0.03);
      scrollbar-width: thin;
    }

    html,
    body {
      margin: 0;
      min-height: 100%;
      background: var(--bg-0);
      color: var(--text);
      font-family: var(--font);
    }

    body {
      overflow-x: hidden;
      background:
        radial-gradient(circle at 15% -5%, rgba(47, 140, 255, 0.17), transparent 34%),
        radial-gradient(circle at 100% 12%, rgba(85, 231, 255, 0.08), transparent 25%),
        linear-gradient(145deg, var(--bg-0), var(--bg-1) 48%, #071321);
    }

    body::before {
      content: "";
      position: fixed;
      inset: 0;
      pointer-events: none;
      opacity: 0.025;
      background-image:
        linear-gradient(rgba(255,255,255,.6) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255,255,255,.6) 1px, transparent 1px);
      background-size: 32px 32px;
      z-index: 0;
    }

    button,
    input,
    textarea,
    select {
      font: inherit;
    }

    button {
      cursor: pointer;
    }

    a {
      color: inherit;
    }

    .hidden {
      display: none !important;
    }

    .app {
      min-height: 100vh;
      position: relative;
      z-index: 1;
    }

    .sidebar {
      position: fixed;
      inset: 0 auto 0 0;
      width: var(--sidebar-width);
      padding: 18px 14px;
      border-right: 1px solid var(--line);
      background:
        linear-gradient(180deg, rgba(8, 17, 30, 0.98), rgba(5, 11, 20, 0.97)),
        radial-gradient(circle at 50% 0, rgba(47, 140, 255, 0.2), transparent 38%);
      backdrop-filter: blur(20px);
      z-index: 20;
      display: flex;
      flex-direction: column;
      gap: 14px;
      transition: transform 0.25s ease;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 6px 8px 16px;
      border-bottom: 1px solid var(--line);
    }

    .brand-badge {
      width: 46px;
      height: 46px;
      border-radius: 14px;
      display: grid;
      place-items: center;
      position: relative;
      background: linear-gradient(145deg, rgba(47, 140, 255, 0.28), rgba(85, 231, 255, 0.08));
      border: 1px solid rgba(103, 178, 255, 0.4);
      box-shadow: inset 0 0 22px rgba(47, 140, 255, 0.15), 0 8px 26px rgba(0,0,0,.3);
    }

    .brand-badge svg {
      width: 28px;
      height: 28px;
      filter: drop-shadow(0 0 8px rgba(85, 231, 255, 0.5));
    }

    .brand h1 {
      margin: 0;
      font-size: 17px;
      letter-spacing: 0.8px;
      line-height: 1.1;
    }

    .brand p {
      margin: 5px 0 0;
      font-size: 11px;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 1.5px;
    }

    .system-status {
      margin: 0 4px;
      padding: 10px 11px;
      border: 1px solid rgba(59, 211, 145, 0.22);
      background: rgba(59, 211, 145, 0.07);
      border-radius: 12px;
      display: flex;
      gap: 9px;
      align-items: center;
      color: #baf3d9;
      font-size: 12px;
    }

    .pulse-dot {
      width: 8px;
      height: 8px;
      border-radius: 999px;
      background: var(--green);
      box-shadow: 0 0 0 0 rgba(59, 211, 145, 0.7);
      animation: pulse 2s infinite;
    }

    @keyframes pulse {
      0% { box-shadow: 0 0 0 0 rgba(59, 211, 145, 0.65); }
      70% { box-shadow: 0 0 0 8px rgba(59, 211, 145, 0); }
      100% { box-shadow: 0 0 0 0 rgba(59, 211, 145, 0); }
    }

    .nav {
      display: flex;
      flex-direction: column;
      gap: 5px;
      overflow-y: auto;
      padding-right: 2px;
    }

    .nav-title {
      color: #607892;
      font-size: 10px;
      font-weight: 800;
      letter-spacing: 1.6px;
      text-transform: uppercase;
      margin: 12px 10px 5px;
    }

    .nav-button {
      border: 1px solid transparent;
      color: #a9bad0;
      background: transparent;
      border-radius: 11px;
      min-height: 42px;
      padding: 8px 11px;
      display: flex;
      align-items: center;
      gap: 11px;
      text-align: left;
      transition: 0.18s ease;
    }

    .nav-button:hover {
      color: var(--text);
      background: rgba(103, 178, 255, 0.08);
      border-color: rgba(103, 178, 255, 0.11);
    }

    .nav-button.active {
      color: #fff;
      background: linear-gradient(90deg, rgba(47, 140, 255, 0.25), rgba(47, 140, 255, 0.08));
      border-color: rgba(103, 178, 255, 0.26);
      box-shadow: inset 3px 0 0 var(--blue-2);
    }

    .nav-icon {
      width: 22px;
      height: 22px;
      border-radius: 7px;
      display: grid;
      place-items: center;
      background: rgba(255,255,255,.04);
      font-size: 14px;
      flex: 0 0 auto;
    }

    .nav-button.active .nav-icon {
      background: rgba(47, 140, 255, 0.24);
      color: var(--cyan);
    }

    .sidebar-user {
      margin-top: auto;
      padding: 12px;
      border: 1px solid var(--line);
      border-radius: 14px;
      background: rgba(255,255,255,.025);
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .avatar {
      width: 38px;
      height: 38px;
      border-radius: 12px;
      object-fit: cover;
      background: var(--panel-3);
      border: 1px solid var(--line-strong);
      display: grid;
      place-items: center;
      font-weight: 800;
      color: var(--blue-2);
    }

    .sidebar-user-info {
      min-width: 0;
      flex: 1;
    }

    .sidebar-user-info strong,
    .sidebar-user-info span {
      display: block;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .sidebar-user-info strong {
      font-size: 13px;
    }

    .sidebar-user-info span {
      color: var(--muted);
      font-size: 11px;
      margin-top: 3px;
    }

    .logout-button {
      border: 0;
      background: rgba(255, 83, 100, 0.1);
      color: #ff8896;
      border-radius: 9px;
      width: 32px;
      height: 32px;
      font-size: 15px;
    }

    .main {
      margin-left: var(--sidebar-width);
      min-height: 100vh;
    }

    .topbar {
      position: sticky;
      top: 0;
      z-index: 15;
      height: var(--topbar-height);
      padding: 12px 22px;
      border-bottom: 1px solid var(--line);
      background: rgba(6, 13, 23, 0.82);
      backdrop-filter: blur(18px);
      display: flex;
      align-items: center;
      gap: 16px;
    }

    .mobile-menu {
      display: none;
      border: 1px solid var(--line);
      color: var(--text);
      background: var(--panel);
      width: 42px;
      height: 42px;
      border-radius: 11px;
    }

    .global-search-wrap {
      flex: 1;
      max-width: 760px;
      position: relative;
    }

    .global-search {
      width: 100%;
      min-height: 44px;
      border-radius: 13px;
      border: 1px solid var(--line);
      background: rgba(255,255,255,.035);
      color: var(--text);
      outline: none;
      padding: 0 45px 0 42px;
      transition: 0.18s ease;
    }

    .global-search:focus {
      border-color: rgba(103, 178, 255, 0.55);
      background: rgba(47, 140, 255, 0.07);
      box-shadow: 0 0 0 4px rgba(47, 140, 255, 0.08);
    }

    .search-symbol {
      position: absolute;
      left: 15px;
      top: 50%;
      transform: translateY(-50%);
      color: var(--muted);
    }

    .search-shortcut {
      position: absolute;
      right: 11px;
      top: 50%;
      transform: translateY(-50%);
      color: #6e839b;
      border: 1px solid var(--line);
      background: rgba(255,255,255,.03);
      padding: 3px 7px;
      border-radius: 6px;
      font-size: 10px;
    }

    .search-results {
      position: absolute;
      top: calc(100% + 9px);
      left: 0;
      right: 0;
      max-height: min(520px, 70vh);
      overflow-y: auto;
      background: rgba(9, 19, 32, 0.98);
      border: 1px solid var(--line-strong);
      border-radius: 14px;
      box-shadow: var(--shadow);
      padding: 7px;
      display: none;
    }

    .search-results.open {
      display: block;
    }

    .search-result {
      width: 100%;
      border: 0;
      background: transparent;
      color: var(--text);
      text-align: left;
      padding: 10px;
      border-radius: 10px;
      display: grid;
      grid-template-columns: auto 1fr;
      gap: 10px;
    }

    .search-result:hover {
      background: rgba(47, 140, 255, 0.1);
    }

    .search-result-tag {
      color: var(--blue-2);
      font-size: 10px;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: 1px;
      padding-top: 2px;
    }

    .search-result strong,
    .search-result span {
      display: block;
    }

    .search-result span {
      color: var(--muted);
      margin-top: 3px;
      font-size: 12px;
    }

    .topbar-clock {
      margin-left: auto;
      text-align: right;
      white-space: nowrap;
    }

    .topbar-clock strong {
      display: block;
      font-size: 15px;
    }

    .topbar-clock span {
      display: block;
      color: var(--muted);
      font-size: 11px;
      margin-top: 3px;
    }

    .content {
      padding: 24px;
      max-width: 1800px;
      margin: 0 auto;
    }

    .page-header {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 18px;
      margin-bottom: 22px;
    }

    .page-header h2 {
      margin: 0;
      font-size: clamp(24px, 3vw, 34px);
      letter-spacing: -0.7px;
    }

    .page-header p {
      margin: 7px 0 0;
      color: var(--muted);
      max-width: 760px;
      line-height: 1.55;
    }

    .header-actions {
      display: flex;
      flex-wrap: wrap;
      gap: 9px;
      justify-content: flex-end;
    }

    .button {
      border: 1px solid var(--line);
      background: rgba(255,255,255,.035);
      color: var(--text);
      min-height: 40px;
      border-radius: 10px;
      padding: 8px 13px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      font-weight: 700;
      font-size: 13px;
      transition: 0.18s ease;
      text-decoration: none;
    }

    .button:hover {
      transform: translateY(-1px);
      border-color: var(--line-strong);
      background: rgba(255,255,255,.06);
    }

    .button.primary {
      border-color: rgba(47, 140, 255, 0.65);
      background: linear-gradient(145deg, #2682ed, #166acb);
      box-shadow: 0 9px 28px rgba(47, 140, 255, 0.2);
    }

    .button.success {
      border-color: rgba(59, 211, 145, 0.4);
      background: rgba(59, 211, 145, 0.13);
      color: #b8f4d7;
    }

    .button.warning {
      border-color: rgba(255, 200, 87, 0.4);
      background: rgba(255, 200, 87, 0.12);
      color: #ffe0a0;
    }

    .button.danger {
      border-color: rgba(255, 83, 100, 0.42);
      background: rgba(255, 83, 100, 0.12);
      color: #ffadb6;
    }

    .button.ghost {
      background: transparent;
    }

    .button.small {
      min-height: 32px;
      padding: 5px 9px;
      font-size: 11px;
      border-radius: 8px;
    }

    .stats-grid {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 14px;
      margin-bottom: 20px;
    }

    .stat-card {
      border: 1px solid var(--line);
      border-radius: var(--radius);
      background:
        linear-gradient(145deg, rgba(18, 34, 55, 0.9), rgba(10, 22, 37, 0.88));
      padding: 17px;
      box-shadow: 0 10px 30px rgba(0,0,0,.13);
      position: relative;
      overflow: hidden;
    }

    .stat-card::after {
      content: "";
      position: absolute;
      right: -20px;
      top: -25px;
      width: 90px;
      height: 90px;
      border-radius: 999px;
      background: var(--accent, var(--blue));
      opacity: 0.07;
      filter: blur(1px);
    }

    .stat-top {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 1px;
      font-weight: 800;
    }

    .stat-icon {
      width: 34px;
      height: 34px;
      border-radius: 10px;
      display: grid;
      place-items: center;
      color: var(--accent, var(--blue-2));
      background: color-mix(in srgb, var(--accent, var(--blue)) 13%, transparent);
      font-size: 16px;
    }

    .stat-value {
      margin-top: 15px;
      font-size: 31px;
      font-weight: 850;
      letter-spacing: -1px;
    }

    .stat-foot {
      color: #6f879f;
      font-size: 11px;
      margin-top: 4px;
    }

    .dashboard-grid {
      display: grid;
      grid-template-columns: minmax(0, 1.5fr) minmax(320px, .8fr);
      gap: 16px;
    }

    .panel {
      border: 1px solid var(--line);
      border-radius: var(--radius);
      background: var(--panel);
      box-shadow: 0 12px 38px rgba(0,0,0,.15);
      overflow: hidden;
    }

    .panel-header {
      min-height: 56px;
      padding: 13px 16px;
      border-bottom: 1px solid var(--line);
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      background: rgba(255,255,255,.018);
    }

    .panel-header h3 {
      margin: 0;
      font-size: 15px;
    }

    .panel-header span {
      color: var(--muted);
      font-size: 11px;
    }

    .panel-body {
      padding: 14px;
    }

    .quick-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 10px;
    }

    .quick-action {
      min-height: 104px;
      border: 1px solid var(--line);
      border-radius: 13px;
      color: var(--text);
      background: rgba(255,255,255,.025);
      padding: 13px;
      text-align: left;
      transition: 0.18s ease;
    }

    .quick-action:hover {
      border-color: rgba(103, 178, 255, 0.4);
      background: rgba(47, 140, 255, 0.08);
      transform: translateY(-2px);
    }

    .quick-action b {
      display: block;
      margin: 10px 0 4px;
      font-size: 13px;
    }

    .quick-action span {
      display: block;
      color: var(--muted);
      font-size: 11px;
      line-height: 1.45;
    }

    .list {
      display: flex;
      flex-direction: column;
      gap: 8px;
    }

    .list-item {
      border: 1px solid var(--line);
      border-radius: 12px;
      background: rgba(255,255,255,.022);
      padding: 11px 12px;
      display: flex;
      align-items: center;
      gap: 10px;
      min-width: 0;
    }

    .list-item-main {
      flex: 1;
      min-width: 0;
    }

    .list-item-main strong,
    .list-item-main span {
      display: block;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .list-item-main strong {
      font-size: 13px;
    }

    .list-item-main span {
      color: var(--muted);
      font-size: 11px;
      margin-top: 4px;
    }

    .badge {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 24px;
      padding: 3px 8px;
      border: 1px solid var(--line);
      border-radius: 999px;
      font-size: 10px;
      font-weight: 800;
      white-space: nowrap;
      color: #c7d6e8;
      background: rgba(255,255,255,.035);
    }

    .badge.red {
      color: #ffadb6;
      border-color: rgba(255,83,100,.3);
      background: rgba(255,83,100,.1);
    }

    .badge.yellow {
      color: #ffe0a0;
      border-color: rgba(255,200,87,.3);
      background: rgba(255,200,87,.1);
    }

    .badge.green {
      color: #b8f4d7;
      border-color: rgba(59,211,145,.3);
      background: rgba(59,211,145,.1);
    }

    .badge.blue {
      color: #b8ddff;
      border-color: rgba(47,140,255,.34);
      background: rgba(47,140,255,.11);
    }

    .badge.purple {
      color: #d7c9ff;
      border-color: rgba(165,130,255,.34);
      background: rgba(165,130,255,.1);
    }

    .audit-item {
      position: relative;
      padding-left: 18px;
    }

    .audit-item::before {
      content: "";
      position: absolute;
      left: 2px;
      top: 16px;
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: var(--blue-2);
      box-shadow: 0 0 0 5px rgba(47,140,255,.1);
    }

    .table-toolbar {
      border: 1px solid var(--line);
      border-radius: 14px 14px 0 0;
      border-bottom: 0;
      background: rgba(14,27,45,.9);
      padding: 12px;
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 10px;
    }

    .table-search {
      min-width: 240px;
      flex: 1;
      max-width: 520px;
      min-height: 39px;
      border-radius: 10px;
      border: 1px solid var(--line);
      background: rgba(255,255,255,.03);
      color: var(--text);
      outline: none;
      padding: 0 12px;
    }

    .table-search:focus {
      border-color: rgba(103,178,255,.45);
    }

    .table-wrap {
      border: 1px solid var(--line);
      border-radius: 0 0 14px 14px;
      overflow: auto;
      background: rgba(8,17,30,.8);
    }

    table {
      width: 100%;
      border-collapse: collapse;
      min-width: 850px;
    }

    th,
    td {
      border-bottom: 1px solid var(--line);
      text-align: left;
      padding: 12px 13px;
      vertical-align: middle;
    }

    th {
      position: sticky;
      top: 0;
      z-index: 2;
      background: #101e30;
      color: #8fa8c2;
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 1px;
      font-weight: 850;
    }

    td {
      font-size: 12px;
      color: #dbe7f5;
    }

    tbody tr {
      transition: 0.15s ease;
    }

    tbody tr:hover {
      background: rgba(47,140,255,.055);
    }

    tbody tr:last-child td {
      border-bottom: 0;
    }

    .cell-main {
      font-weight: 760;
      color: #fff;
    }

    .cell-muted {
      color: var(--muted);
    }

    .actions-cell {
      display: flex;
      gap: 6px;
      justify-content: flex-end;
    }

    .icon-button {
      width: 32px;
      height: 32px;
      border-radius: 8px;
      border: 1px solid var(--line);
      color: #c9d8e8;
      background: rgba(255,255,255,.03);
      display: inline-grid;
      place-items: center;
    }

    .icon-button:hover {
      border-color: rgba(103,178,255,.42);
      color: #fff;
      background: rgba(47,140,255,.1);
    }

    .empty-state {
      padding: 58px 20px;
      text-align: center;
      color: var(--muted);
    }

    .empty-state-icon {
      width: 60px;
      height: 60px;
      margin: 0 auto 14px;
      border-radius: 18px;
      display: grid;
      place-items: center;
      background: rgba(47,140,255,.08);
      border: 1px solid rgba(47,140,255,.17);
      font-size: 25px;
      color: var(--blue-2);
    }

    .empty-state h3 {
      color: var(--text);
      margin: 0 0 8px;
    }

    .empty-state p {
      margin: 0;
      font-size: 13px;
    }

    .modal-backdrop {
      position: fixed;
      inset: 0;
      z-index: 100;
      padding: 28px;
      background: rgba(1, 5, 10, 0.76);
      backdrop-filter: blur(8px);
      display: grid;
      place-items: center;
      opacity: 0;
      visibility: hidden;
      transition: 0.18s ease;
    }

    .modal-backdrop.open {
      opacity: 1;
      visibility: visible;
    }

    .modal {
      width: min(980px, 100%);
      max-height: calc(100vh - 56px);
      overflow: auto;
      border: 1px solid var(--line-strong);
      background:
        radial-gradient(circle at 100% 0, rgba(47,140,255,.1), transparent 28%),
        #0a1524;
      border-radius: 18px;
      box-shadow: 0 30px 90px rgba(0,0,0,.6);
      transform: translateY(10px) scale(.99);
      transition: .18s ease;
    }

    .modal-backdrop.open .modal {
      transform: translateY(0) scale(1);
    }

    .modal-header {
      position: sticky;
      top: 0;
      z-index: 5;
      min-height: 64px;
      padding: 14px 18px;
      border-bottom: 1px solid var(--line);
      background: rgba(10,21,36,.95);
      backdrop-filter: blur(14px);
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
    }

    .modal-header h3 {
      margin: 0;
      font-size: 18px;
    }

    .modal-header p {
      margin: 4px 0 0;
      color: var(--muted);
      font-size: 11px;
    }

    .modal-close {
      border: 1px solid var(--line);
      color: var(--text);
      background: rgba(255,255,255,.03);
      width: 38px;
      height: 38px;
      border-radius: 10px;
      font-size: 18px;
    }

    .modal-body {
      padding: 18px;
    }

    .modal-footer {
      position: sticky;
      bottom: 0;
      z-index: 5;
      border-top: 1px solid var(--line);
      background: rgba(10,21,36,.95);
      backdrop-filter: blur(14px);
      padding: 13px 18px;
      display: flex;
      justify-content: flex-end;
      flex-wrap: wrap;
      gap: 9px;
    }

    .form-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 14px;
    }

    .form-group {
      min-width: 0;
    }

    .form-group.full {
      grid-column: 1 / -1;
    }

    .form-group label {
      display: block;
      color: #9fb3ca;
      font-size: 11px;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: .8px;
      margin: 0 0 7px;
    }

    .form-control {
      width: 100%;
      min-height: 42px;
      border-radius: 10px;
      border: 1px solid var(--line);
      background: rgba(255,255,255,.035);
      color: var(--text);
      padding: 9px 11px;
      outline: none;
      resize: vertical;
    }

    .form-control:focus {
      border-color: rgba(103,178,255,.5);
      box-shadow: 0 0 0 3px rgba(47,140,255,.07);
      background: rgba(47,140,255,.055);
    }

    select.form-control option {
      background: #101d2d;
    }

    textarea.form-control {
      min-height: 100px;
      line-height: 1.55;
    }

    .detail-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
    }

    .detail {
      border: 1px solid var(--line);
      border-radius: 11px;
      background: rgba(255,255,255,.025);
      padding: 11px;
      min-width: 0;
    }

    .detail.full {
      grid-column: 1 / -1;
    }

    .detail-label {
      display: block;
      color: #7790aa;
      font-size: 9px;
      text-transform: uppercase;
      letter-spacing: 1px;
      font-weight: 850;
      margin-bottom: 6px;
    }

    .detail-value {
      color: #edf6ff;
      font-size: 13px;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      line-height: 1.5;
    }

    .toast-container {
      position: fixed;
      right: 18px;
      bottom: 18px;
      z-index: 200;
      width: min(390px, calc(100vw - 36px));
      display: flex;
      flex-direction: column;
      gap: 9px;
      pointer-events: none;
    }

    .toast {
      border: 1px solid var(--line-strong);
      background: rgba(10,21,36,.97);
      border-radius: 12px;
      box-shadow: var(--shadow);
      padding: 12px 13px;
      display: flex;
      align-items: flex-start;
      gap: 10px;
      animation: toastIn .2s ease;
      pointer-events: auto;
    }

    @keyframes toastIn {
      from { opacity: 0; transform: translateY(9px); }
      to { opacity: 1; transform: translateY(0); }
    }

    .toast-mark {
      width: 28px;
      height: 28px;
      border-radius: 9px;
      display: grid;
      place-items: center;
      background: rgba(47,140,255,.12);
      color: var(--blue-2);
      flex: 0 0 auto;
    }

    .toast.success .toast-mark {
      background: rgba(59,211,145,.12);
      color: var(--green);
    }

    .toast.error .toast-mark {
      background: rgba(255,83,100,.12);
      color: var(--red);
    }

    .toast-content strong,
    .toast-content span {
      display: block;
    }

    .toast-content strong {
      font-size: 12px;
    }

    .toast-content span {
      color: var(--muted);
      font-size: 11px;
      margin-top: 4px;
      line-height: 1.45;
    }

    .login-screen {
      min-height: 100vh;
      display: grid;
      place-items: center;
      padding: 25px;
      position: relative;
      overflow: hidden;
    }

    .login-screen::before,
    .login-screen::after {
      content: "";
      position: absolute;
      border-radius: 999px;
      filter: blur(2px);
      opacity: .2;
      pointer-events: none;
    }

    .login-screen::before {
      width: 500px;
      height: 500px;
      left: -240px;
      top: -230px;
      background: radial-gradient(circle, var(--blue), transparent 65%);
    }

    .login-screen::after {
      width: 450px;
      height: 450px;
      right: -220px;
      bottom: -220px;
      background: radial-gradient(circle, var(--cyan), transparent 65%);
    }

    .login-card {
      width: min(520px, 100%);
      border: 1px solid var(--line-strong);
      border-radius: 22px;
      background:
        linear-gradient(150deg, rgba(18,34,55,.94), rgba(7,16,28,.94));
      box-shadow: 0 35px 120px rgba(0,0,0,.55);
      padding: 30px;
      text-align: center;
      position: relative;
      z-index: 2;
    }

    .login-logo {
      width: 82px;
      height: 82px;
      margin: 0 auto 20px;
      border-radius: 24px;
      display: grid;
      place-items: center;
      border: 1px solid rgba(103,178,255,.42);
      background: linear-gradient(145deg, rgba(47,140,255,.25), rgba(85,231,255,.06));
      box-shadow: inset 0 0 35px rgba(47,140,255,.13), 0 15px 45px rgba(0,0,0,.3);
    }

    .login-logo svg {
      width: 45px;
      height: 45px;
    }

    .login-card h1 {
      margin: 0;
      font-size: 27px;
      letter-spacing: -.5px;
    }

    .login-card .subtitle {
      margin: 9px auto 22px;
      max-width: 390px;
      color: var(--muted);
      line-height: 1.6;
      font-size: 13px;
    }

    .discord-button {
      min-height: 52px;
      width: 100%;
      border: 1px solid rgba(120,133,255,.55);
      border-radius: 13px;
      background: linear-gradient(145deg, #5865f2, #4651d4);
      color: #fff;
      font-weight: 850;
      letter-spacing: .2px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 11px;
      text-decoration: none;
      box-shadow: 0 12px 38px rgba(88,101,242,.24);
      transition: .18s ease;
    }

    .discord-button:hover {
      transform: translateY(-2px);
      box-shadow: 0 16px 45px rgba(88,101,242,.32);
    }

    .preview-login-button {
      min-height: 46px;
      width: 100%;
      margin-top: 10px;
      border: 1px solid rgba(103,178,255,.28);
      border-radius: 13px;
      background: rgba(47,140,255,.08);
      color: #b9d8f7;
      font-weight: 800;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 10px;
      text-decoration: none;
      transition: .18s ease;
    }

    .preview-login-button:hover {
      transform: translateY(-1px);
      border-color: rgba(103,178,255,.48);
      background: rgba(47,140,255,.13);
    }

    .preview-login-button small {
      color: #7f9bb7;
      font-size: 9px;
      letter-spacing: .8px;
      text-transform: uppercase;
    }

    .preview-mode-banner {
      margin-bottom: 14px;
      padding: 11px 14px;
      border: 1px solid rgba(255,190,74,.3);
      border-radius: 12px;
      background: rgba(255,190,74,.08);
      color: #ffd893;
      font-size: 11px;
      line-height: 1.55;
    }

    .login-features {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 9px;
      margin-top: 20px;
    }

    .login-feature {
      border: 1px solid var(--line);
      border-radius: 11px;
      background: rgba(255,255,255,.024);
      padding: 11px 8px;
      color: #abc0d6;
      font-size: 10px;
      line-height: 1.45;
    }

    .login-error {
      margin: 0 0 16px;
      border: 1px solid rgba(255,83,100,.36);
      border-radius: 11px;
      background: rgba(255,83,100,.1);
      color: #ffc0c7;
      padding: 11px;
      font-size: 12px;
    }

    .duty-grid {
      display: grid;
      grid-template-columns: minmax(300px, 360px) minmax(0, 1fr);
      gap: 16px;
      align-items: start;
    }

    .duty-summary {
      border: 1px solid var(--line);
      border-radius: var(--radius);
      background: linear-gradient(155deg, rgba(18,34,55,.96), rgba(8,17,30,.94));
      padding: 20px;
      box-shadow: 0 15px 45px rgba(0,0,0,.2);
      position: sticky;
      top: 90px;
    }

    .duty-summary.active {
      border-color: rgba(59,211,145,.42);
      box-shadow: 0 15px 45px rgba(0,0,0,.2), 0 0 0 1px rgba(59,211,145,.08) inset;
    }

    .duty-summary-head,
    .duty-person {
      display: flex;
      align-items: center;
      gap: 11px;
    }

    .duty-summary-head div,
    .duty-person div {
      min-width: 0;
      display: flex;
      flex-direction: column;
      gap: 3px;
    }

    .duty-summary-head span,
    .duty-person span {
      color: var(--muted);
      font-size: 10px;
      letter-spacing: .5px;
    }

    .duty-summary-head strong,
    .duty-person strong {
      color: #fff;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .duty-avatar {
      width: 42px;
      height: 42px;
      flex: 0 0 42px;
      border-radius: 12px;
      display: grid;
      place-items: center;
      overflow: hidden;
      background: linear-gradient(145deg, rgba(47,140,255,.25), rgba(85,231,255,.12));
      border: 1px solid rgba(103,178,255,.25);
      color: #dff3ff;
      font-weight: 850;
    }

    .duty-avatar img {
      width: 100%;
      height: 100%;
      object-fit: cover;
    }

    .duty-status-line {
      margin: 18px 0 22px;
      min-height: 38px;
      border-radius: 11px;
      border: 1px solid var(--line);
      background: rgba(255,255,255,.025);
      padding: 10px 12px;
      display: flex;
      align-items: center;
      gap: 10px;
      color: #b9cce0;
      font-size: 11px;
    }

    .duty-time-label {
      color: var(--muted);
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 1.3px;
      font-weight: 800;
    }

    .duty-time {
      margin: 6px 0 18px;
      font-size: clamp(34px, 4vw, 50px);
      line-height: 1;
      font-weight: 900;
      letter-spacing: -2px;
      color: #fff;
      font-variant-numeric: tabular-nums;
    }

    .duty-total-row {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      padding: 11px 0;
      border-top: 1px solid var(--line);
      color: var(--muted);
      font-size: 11px;
    }

    .duty-total-row strong {
      color: #fff;
      text-align: right;
      font-variant-numeric: tabular-nums;
    }

    .duty-main-button {
      width: 100%;
      margin-top: 15px;
      min-height: 46px;
    }

    .duty-table-wrap {
      border: 0;
      border-radius: 0;
    }

    .duty-table-wrap table {
      min-width: 880px;
    }

    .duty-rank {
      width: 52px;
      font-size: 16px;
      font-weight: 900;
      color: var(--blue-2);
    }

    .duty-session-value,
    .duty-total-value {
      font-variant-numeric: tabular-nums;
      white-space: nowrap;
    }

    .duty-meta-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 8px;
      margin: 0 0 14px;
    }

    .duty-meta {
      border: 1px solid var(--line);
      border-radius: 10px;
      background: rgba(255,255,255,.024);
      padding: 9px 10px;
      min-width: 0;
    }

    .duty-meta span {
      display: block;
      color: var(--muted);
      font-size: 9px;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: 1px;
      margin-bottom: 4px;
    }

    .duty-meta strong {
      display: block;
      color: #fff;
      font-size: 12px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .duty-status-control {
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 8px;
      margin: 12px 0 2px;
    }

    .cad-layout {
      display: grid;
      grid-template-columns: minmax(290px, 360px) minmax(0, 1fr);
      gap: 16px;
      align-items: start;
    }

    .cad-column {
      display: flex;
      flex-direction: column;
      gap: 12px;
      min-width: 0;
    }

    .cad-unit,
    .cad-call {
      border: 1px solid var(--line);
      border-radius: 14px;
      background: linear-gradient(155deg, rgba(20,37,59,.86), rgba(10,20,34,.9));
      padding: 13px;
      box-shadow: 0 12px 35px rgba(0,0,0,.14);
    }

    .cad-unit-head,
    .cad-call-head {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 10px;
    }

    .cad-unit-name,
    .cad-call-title {
      min-width: 0;
    }

    .cad-unit-name strong,
    .cad-call-title strong {
      display: block;
      color: #fff;
      font-size: 14px;
      line-height: 1.3;
    }

    .cad-unit-name span,
    .cad-call-title span {
      display: block;
      color: var(--muted);
      font-size: 10px;
      margin-top: 4px;
      line-height: 1.45;
    }

    .cad-unit-details,
    .cad-call-details {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 7px;
      margin-top: 11px;
    }

    .cad-detail {
      border-radius: 9px;
      background: rgba(255,255,255,.025);
      border: 1px solid rgba(136,177,222,.1);
      padding: 8px 9px;
      min-width: 0;
    }

    .cad-detail span {
      display: block;
      color: var(--muted);
      font-size: 8px;
      font-weight: 850;
      text-transform: uppercase;
      letter-spacing: .9px;
      margin-bottom: 4px;
    }

    .cad-detail strong {
      display: block;
      font-size: 11px;
      color: #dfefff;
      overflow-wrap: anywhere;
    }

    .cad-call {
      position: relative;
      overflow: hidden;
    }

    .cad-call::before {
      content: '';
      position: absolute;
      inset: 0 auto 0 0;
      width: 4px;
      background: var(--blue);
    }

    .cad-call.p1::before { background: var(--red); }
    .cad-call.p2::before { background: var(--orange); }
    .cad-call.p3::before { background: var(--yellow); }
    .cad-call.p4::before { background: var(--blue); }

    .cad-call-description {
      margin: 11px 0 0;
      color: #b9cce0;
      font-size: 11px;
      line-height: 1.55;
      white-space: pre-wrap;
    }

    .cad-actions {
      display: grid;
      grid-template-columns: minmax(150px, 1fr) auto auto;
      gap: 8px;
      margin-top: 12px;
      align-items: center;
    }

    .cad-status-buttons {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-top: 9px;
    }

    .cad-status-buttons .button {
      min-height: 31px;
      padding: 6px 9px;
      font-size: 9px;
    }

    .cad-current-banner {
      border: 1px solid rgba(59,211,145,.3);
      border-radius: 14px;
      background: linear-gradient(145deg, rgba(59,211,145,.1), rgba(47,140,255,.06));
      padding: 13px 14px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 15px;
    }

    .cad-current-banner strong { display:block; }
    .cad-current-banner span { display:block;color:var(--muted);font-size:10px;margin-top:4px; }

    .settings-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 15px;
    }

    .settings-card {
      border: 1px solid var(--line);
      border-radius: 14px;
      background: rgba(255,255,255,.024);
      padding: 16px;
    }

    .settings-card h3 {
      margin: 0 0 7px;
      font-size: 15px;
    }

    .settings-card p {
      color: var(--muted);
      font-size: 12px;
      line-height: 1.55;
      margin: 0 0 14px;
    }

    .loader {
      width: 38px;
      height: 38px;
      border-radius: 50%;
      border: 3px solid rgba(103,178,255,.15);
      border-top-color: var(--blue-2);
      animation: spin .7s linear infinite;
      margin: 30px auto;
    }

    @keyframes spin {
      to { transform: rotate(360deg); }
    }


    .city-hero {
      position: relative;
      overflow: hidden;
      min-height: 260px;
      padding: 32px;
      border: 1px solid rgba(103, 178, 255, 0.25);
      border-radius: 24px;
      background:
        linear-gradient(115deg, rgba(10, 26, 47, .98), rgba(8, 19, 34, .88)),
        radial-gradient(circle at 86% 20%, rgba(85, 231, 255, .22), transparent 34%);
      box-shadow: var(--shadow);
      display: grid;
      grid-template-columns: minmax(0, 1.35fr) minmax(280px, .65fr);
      gap: 26px;
      align-items: center;
    }

    .city-hero::after {
      content: "";
      position: absolute;
      inset: -20% -8% -20% 55%;
      opacity: .18;
      background-image:
        linear-gradient(30deg, transparent 48%, rgba(103,178,255,.45) 49%, transparent 51%),
        linear-gradient(150deg, transparent 48%, rgba(85,231,255,.28) 49%, transparent 51%);
      background-size: 62px 62px;
      transform: rotate(-5deg);
      pointer-events: none;
    }

    .city-kicker {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      color: #8bdfff;
      font-size: 11px;
      font-weight: 900;
      letter-spacing: 2px;
      text-transform: uppercase;
    }

    .city-hero h2 {
      position: relative;
      z-index: 1;
      margin: 13px 0 12px;
      max-width: 780px;
      font-size: clamp(30px, 4vw, 54px);
      line-height: 1.02;
      letter-spacing: -1.8px;
    }

    .city-hero p {
      position: relative;
      z-index: 1;
      max-width: 720px;
      margin: 0;
      color: #a8bdd3;
      font-size: 15px;
      line-height: 1.75;
    }

    .city-hero-actions {
      position: relative;
      z-index: 2;
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-top: 24px;
    }

    .city-radar {
      position: relative;
      z-index: 1;
      min-height: 205px;
      border-radius: 999px;
      border: 1px solid rgba(85,231,255,.24);
      background:
        radial-gradient(circle, rgba(85,231,255,.13) 0 2px, transparent 3px),
        repeating-radial-gradient(circle, transparent 0 31px, rgba(103,178,255,.14) 32px 33px),
        conic-gradient(from 225deg, transparent 0 72%, rgba(85,231,255,.22) 82%, transparent 92%);
      box-shadow: inset 0 0 55px rgba(47,140,255,.13), 0 0 50px rgba(47,140,255,.08);
      aspect-ratio: 1;
      max-width: 235px;
      justify-self: center;
    }

    .radar-node {
      position: absolute;
      width: 12px;
      height: 12px;
      border: 2px solid #07101d;
      border-radius: 50%;
      background: var(--green);
      box-shadow: 0 0 16px rgba(59,211,145,.8);
    }

    .radar-node:nth-child(1) { left: 31%; top: 28%; }
    .radar-node:nth-child(2) { left: 66%; top: 42%; background: var(--cyan); }
    .radar-node:nth-child(3) { left: 47%; top: 69%; background: var(--yellow); }
    .radar-node:nth-child(4) { left: 74%; top: 72%; background: var(--red); }

    .section-heading {
      display: flex;
      align-items: end;
      justify-content: space-between;
      gap: 18px;
      margin: 28px 2px 14px;
    }

    .section-heading h3 { margin: 0; font-size: 19px; }
    .section-heading p { margin: 6px 0 0; color: var(--muted); font-size: 13px; }

    .module-grid {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 14px;
    }

    .module-card {
      --module: var(--blue);
      position: relative;
      overflow: hidden;
      min-height: 205px;
      padding: 19px;
      border: 1px solid var(--line);
      border-radius: 18px;
      background: linear-gradient(145deg, rgba(18,34,55,.96), rgba(10,21,37,.92));
      color: var(--text);
      text-align: left;
      transition: transform .2s ease, border-color .2s ease, box-shadow .2s ease;
    }

    .module-card::before {
      content: "";
      position: absolute;
      inset: 0;
      background: radial-gradient(circle at 92% 0, color-mix(in srgb, var(--module) 23%, transparent), transparent 43%);
      pointer-events: none;
    }

    .module-card::after {
      content: "";
      position: absolute;
      left: 18px;
      right: 18px;
      bottom: 0;
      height: 2px;
      background: linear-gradient(90deg, transparent, var(--module), transparent);
      opacity: .75;
    }

    .module-card:hover {
      transform: translateY(-4px);
      border-color: color-mix(in srgb, var(--module) 48%, transparent);
      box-shadow: 0 18px 45px rgba(0,0,0,.28);
    }

    .module-head { position: relative; display:flex; justify-content:space-between; gap:12px; align-items:flex-start; }
    .module-icon { width:48px; height:48px; border-radius:14px; display:grid; place-items:center; font-size:22px; color:#fff; background:color-mix(in srgb, var(--module) 24%, transparent); border:1px solid color-mix(in srgb, var(--module) 45%, transparent); }
    .module-state { font-size:9px; font-weight:900; letter-spacing:1.2px; text-transform:uppercase; color:var(--module); border:1px solid color-mix(in srgb, var(--module) 35%, transparent); background:color-mix(in srgb, var(--module) 10%, transparent); padding:6px 8px; border-radius:999px; }
    .module-card h4 { position:relative; margin:18px 0 7px; font-size:17px; }
    .module-card p { position:relative; margin:0; color:var(--muted); font-size:12px; line-height:1.55; }
    .module-meta { position:absolute; left:19px; right:19px; bottom:18px; display:flex; justify-content:space-between; align-items:center; color:#8da4bd; font-size:11px; }

    .city-grid {
      display: grid;
      grid-template-columns: minmax(0, 1.35fr) minmax(320px, .65fr);
      gap: 16px;
      margin-top: 16px;
    }

    .pulse-list { display:flex; flex-direction:column; gap:10px; }
    .pulse-row { display:grid; grid-template-columns:12px 1fr auto; gap:12px; align-items:center; padding:13px; border:1px solid var(--line); border-radius:13px; background:rgba(255,255,255,.02); }
    .pulse-line { width:8px; height:8px; border-radius:50%; background:var(--cyan); box-shadow:0 0 12px rgba(85,231,255,.7); }
    .pulse-row strong { display:block; font-size:13px; }
    .pulse-row span { display:block; margin-top:3px; color:var(--muted); font-size:11px; }

    .mesh-grid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:10px; }
    .mesh-node { min-height:104px; padding:14px; border-radius:14px; border:1px solid var(--line); background:rgba(255,255,255,.025); }
    .mesh-node b { display:block; font-size:13px; }
    .mesh-node span { display:block; color:var(--muted); font-size:11px; margin-top:6px; line-height:1.45; }
    .mesh-status { display:inline-flex!important; width:auto; margin-top:11px!important; padding:5px 8px; border-radius:999px; font-size:9px!important; font-weight:900; letter-spacing:1px; text-transform:uppercase; color:#a7f0d0!important; background:rgba(59,211,145,.09); border:1px solid rgba(59,211,145,.22); }
    .mesh-status.wait { color:#ffe0a0!important; background:rgba(255,200,87,.08); border-color:rgba(255,200,87,.2); }

    .department-hero {
      --dept: var(--blue);
      position:relative;
      overflow:hidden;
      padding:26px;
      border:1px solid color-mix(in srgb, var(--dept) 36%, transparent);
      border-radius:22px;
      background:linear-gradient(120deg, color-mix(in srgb, var(--dept) 13%, #0a1525), #091321 66%);
      box-shadow:var(--shadow);
    }
    .department-hero::after { content:""; position:absolute; width:260px; height:260px; border-radius:50%; right:-70px; top:-120px; border:42px solid color-mix(in srgb, var(--dept) 10%, transparent); }
    .department-hero h2 { position:relative; margin:8px 0; font-size:32px; }
    .department-hero p { position:relative; max-width:760px; margin:0; color:#a8bdd3; line-height:1.65; }
    .department-mark { position:relative; color:var(--dept); font-size:11px; font-weight:900; letter-spacing:1.8px; text-transform:uppercase; }

    .preview-grid { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:14px; margin-top:16px; }
    .preview-card { min-height:176px; padding:18px; border-radius:16px; border:1px solid var(--line); background:var(--panel); }
    .preview-card h3 { margin:10px 0 8px; font-size:15px; }
    .preview-card p { margin:0; color:var(--muted); font-size:12px; line-height:1.6; }
    .preview-card .preview-icon { font-size:22px; color:var(--blue-2); }
    .preview-tag { display:inline-flex; padding:5px 8px; border-radius:999px; border:1px solid var(--line); color:#8fa8c2; font-size:9px; font-weight:850; letter-spacing:1px; text-transform:uppercase; }

    .operation-board { display:grid; grid-template-columns:minmax(0,.72fr) minmax(0,1.28fr); gap:16px; }
    .agency-lane { padding:13px; border-radius:13px; background:rgba(255,255,255,.025); border:1px solid var(--line); margin-bottom:9px; }
    .agency-lane strong { font-size:12px; }
    .agency-lane span { float:right; color:var(--muted); font-size:11px; }
    .incident-timeline { position:relative; padding-left:20px; display:flex; flex-direction:column; gap:14px; }
    .incident-timeline::before { content:""; position:absolute; left:5px; top:6px; bottom:6px; width:1px; background:linear-gradient(var(--cyan),rgba(103,178,255,.08)); }
    .timeline-event { position:relative; }
    .timeline-event::before { content:""; position:absolute; left:-19px; top:5px; width:9px; height:9px; border-radius:50%; background:var(--cyan); box-shadow:0 0 10px rgba(85,231,255,.7); }
    .timeline-event b { display:block; font-size:12px; }
    .timeline-event span { display:block; margin-top:4px; color:var(--muted); font-size:11px; }

    .server-console { font-family:"Cascadia Code",Consolas,monospace; padding:18px; border:1px solid rgba(59,211,145,.18); border-radius:15px; background:#050b10; color:#a9c7b8; font-size:12px; line-height:1.8; }
    .console-ok { color:#62e2a4; }
    .console-wait { color:#ffd276; }

    @media (max-width: 1250px) {
      .module-grid { grid-template-columns:repeat(2,minmax(0,1fr)); }
      .preview-grid { grid-template-columns:repeat(2,minmax(0,1fr)); }
    }

    @media (max-width: 840px) {
      .city-hero { grid-template-columns:1fr; padding:24px; }
      .city-radar { display:none; }
      .city-grid, .operation-board { grid-template-columns:1fr; }
    }

    @media (max-width: 560px) {
      .module-grid, .preview-grid, .mesh-grid { grid-template-columns:1fr; }
      .city-hero h2 { font-size:34px; }
    }

    @media (max-width: 1180px) {
      .stats-grid {
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }

      .dashboard-grid {
        grid-template-columns: 1fr;
      }

      .quick-grid {
        grid-template-columns: repeat(2, 1fr);
      }
    }

    @media (max-width: 840px) {
      :root {
        --sidebar-width: 270px;
      }

      .sidebar {
        transform: translateX(-105%);
        box-shadow: 20px 0 60px rgba(0,0,0,.5);
      }

      .sidebar.open {
        transform: translateX(0);
      }

      .main {
        margin-left: 0;
      }

      .mobile-menu {
        display: grid;
        place-items: center;
      }

      .topbar-clock {
        display: none;
      }

      .content {
        padding: 17px;
      }

      .form-grid,
      .detail-grid,
      .settings-grid,
      .duty-grid,
      .cad-layout {
        grid-template-columns: 1fr;
      }

      .cad-actions {
        grid-template-columns: 1fr;
      }

      .duty-summary {
        position: static;
      }

      .form-group.full,
      .detail.full {
        grid-column: auto;
      }
    }

    @media (max-width: 560px) {
      .topbar {
        padding: 10px 12px;
      }

      .search-shortcut {
        display: none;
      }

      .global-search {
        padding-right: 12px;
      }

      .page-header {
        display: block;
      }

      .header-actions {
        justify-content: flex-start;
        margin-top: 14px;
      }

      .stats-grid {
        grid-template-columns: 1fr;
      }

      .quick-grid,
      .login-features {
        grid-template-columns: 1fr;
      }

      .modal-backdrop {
        padding: 0;
        align-items: end;
      }

      .modal {
        max-height: 94vh;
        border-radius: 18px 18px 0 0;
      }
    }

    @media print {
      .sidebar,
      .topbar,
      .header-actions,
      .table-toolbar,
      .modal-footer,
      .modal-close {
        display: none !important;
      }

      .main {
        margin-left: 0;
      }

      body,
      .panel,
      .modal,
      .modal-backdrop {
        background: #fff !important;
        color: #000 !important;
        box-shadow: none !important;
      }
    }
  </style>
</head>
<body>
  <div id="loginScreen" class="login-screen">
    <div class="login-card">
      <div class="login-logo">
        <svg viewBox="0 0 64 64" fill="none" aria-hidden="true">
          <path d="M32 5 53 13v15c0 14-8.4 24.3-21 31C19.4 52.3 11 42 11 28V13L32 5Z" stroke="#67b2ff" stroke-width="3"/>
          <path d="M20 28h24M32 16v24M23 43c6-5 12-5 18 0" stroke="#55e7ff" stroke-width="3" stroke-linecap="round"/>
        </svg>
      </div>
      <h1>LIBERTY • OPERATIONS</h1>
      <p class="subtitle">
        Niezależne centrum operacyjne całego serwera ER:LC. Jeden profil Discord, wszystkie frakcje, postacie i systemy RP w jednym miejscu.
      </p>
      <div id="loginError" class="login-error hidden"></div>
      <a class="discord-button" href="/auth/login">
        <span style="font-size:20px">◉</span>
        Zaloguj przez Discord
      </a>
      <a class="preview-login-button" href="/auth/preview">
        <span style="font-size:18px">▦</span>
        Wejdź do podglądu
        <small>tylko odczyt</small>
      </a>
      <div class="login-features">
        <div class="login-feature">Weryfikacja członkostwa Discord</div>
        <div class="login-feature">Centrum wszystkich frakcji</div>
        <div class="login-feature">Gotowe pod API ER:LC</div>
      </div>
    </div>
  </div>

  <div id="app" class="app hidden">
    <aside id="sidebar" class="sidebar">
      <div class="brand">
        <div class="brand-badge">
          <svg viewBox="0 0 64 64" fill="none" aria-hidden="true">
            <path d="M32 5 53 13v15c0 14-8.4 24.3-21 31C19.4 52.3 11 42 11 28V13L32 5Z" stroke="#67b2ff" stroke-width="3"/>
            <path d="M20 28h24M32 16v24M23 43c6-5 12-5 18 0" stroke="#55e7ff" stroke-width="3" stroke-linecap="round"/>
          </svg>
        </div>
        <div>
          <h1>LIBERTY • OPS</h1>
          <p>Centrum operacyjne RP</p>
        </div>
      </div>

      <div class="system-status">
        <span class="pulse-dot"></span>
        System online · połączenie bezpieczne
      </div>
      <div style="margin:0 4px;padding:9px 11px;border-radius:10px;background:rgba(47,140,255,.07);border:1px solid rgba(103,178,255,.16);font-size:10px;font-weight:850;letter-spacing:1.4px;color:#9bcfff;text-align:center">ER:LC • CITY OS • V3 PREVIEW</div>

      <nav class="nav" id="navigation">
        <div class="nav-title">Miasto</div>
        <button class="nav-button active" data-page="dashboard">
          <span class="nav-icon">⌂</span> Centrum miasta
        </button>
        <button class="nav-button" data-page="operations">
          <span class="nav-icon">◈</span> Wspólne zdarzenia
        </button>
        <button class="nav-button" data-page="sessions">
          <span class="nav-icon">◷</span> Sesje RP
        </button>
        <button class="nav-button" data-page="serverlive">
          <span class="nav-icon">⌁</span> Serwer ER:LC
        </button>

        <div class="nav-title">Frakcje</div>
        <button class="nav-button" data-page="police">
          <span class="nav-icon">★</span> KSP · Policja
        </button>
        <button class="nav-button" data-page="ems">
          <span class="nav-icon">✚</span> PRM · Ratownictwo
        </button>
        <button class="nav-button" data-page="fire">
          <span class="nav-icon">▲</span> PSP · Straż pożarna
        </button>
        <button class="nav-button" data-page="dot">
          <span class="nav-icon">◆</span> PD · Drogi i transport
        </button>
        <button class="nav-button" data-page="cad">
          <span class="nav-icon">⌖</span> Dyspozytornia CAD
        </button>
        <button class="nav-button" data-page="duty">
          <span class="nav-icon">◉</span> Aktywna służba
        </button>

        <div class="nav-title">KSP · Baza policyjna</div>
        <button class="nav-button" data-page="dispatch">
          <span class="nav-icon">☎</span> Rejestr zgłoszeń
        </button>
        <button class="nav-button" data-page="citizens">
          <span class="nav-icon">◎</span> Osoby
        </button>
        <button class="nav-button" data-page="vehicles">
          <span class="nav-icon">▰</span> Pojazdy
        </button>
        <button class="nav-button" data-page="tickets">
          <span class="nav-icon">₿</span> Mandaty
        </button>
        <button class="nav-button" data-page="arrests">
          <span class="nav-icon">⌁</span> Zatrzymania
        </button>
        <button class="nav-button" data-page="reports">
          <span class="nav-icon">▤</span> Raporty
        </button>
        <button class="nav-button" data-page="wanted">
          <span class="nav-icon">⚠</span> Poszukiwani
        </button>
        <button class="nav-button" data-page="evidence">
          <span class="nav-icon">◇</span> Dowody
        </button>

        <div class="nav-title">Społeczność</div>
        <button class="nav-button" data-page="civilian">
          <span class="nav-icon">◉</span> Profil cywila
        </button>
        <button class="nav-button" data-page="economy">
          <span class="nav-icon">▦</span> Firmy i urzędy
        </button>
        <button class="nav-button" data-page="discordhub">
          <span class="nav-icon">◌</span> Discord Hub
        </button>

        <div class="nav-title">System</div>
        <button class="nav-button" data-page="lab">
          <span class="nav-icon">✦</span> Innovation Lab
        </button>
        <button class="nav-button" data-page="audit">
          <span class="nav-icon">◷</span> Dziennik operacji
        </button>
        <button class="nav-button" data-page="settings">
          <span class="nav-icon">⚙</span> Ustawienia
        </button>
      </nav>

      <div class="sidebar-user">
        <div id="sidebarAvatar" class="avatar">K</div>
        <div class="sidebar-user-info">
          <strong id="sidebarUserName">Ładowanie...</strong>
          <span id="sidebarUserRole">Funkcjonariusz</span>
        </div>
        <a class="logout-button" href="/auth/logout" title="Wyloguj">↪</a>
      </div>
    </aside>

    <main class="main">
      <header class="topbar">
        <button id="mobileMenu" class="mobile-menu" aria-label="Menu">☰</button>
        <div class="global-search-wrap">
          <span class="search-symbol">⌕</span>
          <input id="globalSearch" class="global-search" placeholder="Szukaj w całym mieście: osoba, pojazd, sprawa, moduł...">
          <span class="search-shortcut">Ctrl K</span>
          <div id="searchResults" class="search-results"></div>
        </div>
        <div class="topbar-clock">
          <strong id="clockTime">--:--:--</strong>
          <span id="clockDate">--</span>
        </div>
      </header>

      <section id="content" class="content"></section>
    </main>
  </div>

  <div id="modalBackdrop" class="modal-backdrop">
    <div class="modal">
      <div class="modal-header">
        <div>
          <h3 id="modalTitle">Rekord</h3>
          <p id="modalSubtitle">KSP • SYSTEM INFORMACYJNY</p>
        </div>
        <button id="modalClose" class="modal-close">×</button>
      </div>
      <div id="modalBody" class="modal-body"></div>
      <div id="modalFooter" class="modal-footer"></div>
    </div>
  </div>

  <div id="toastContainer" class="toast-container"></div>

  <script>
    'use strict';

    var state = {
      user: null,
      currentPage: 'dashboard',
      currentItems: [],
      currentRecord: null,
      modalMode: null,
      citizens: [],
      vehicles: [],
      searchTimer: null,
      dutyData: null,
      dutyFetchedAt: 0,
      dutyTimer: null,
      dutyTick: 0,
      cadData: null,
      cadTimer: null
    };

    var pageConfig = {
      citizens: {
        title: 'Kartoteka osób',
        description: 'Dane identyfikacyjne, statusy, uprawnienia i notatki operacyjne.',
        icon: '◎',
        primary: 'fullName',
        secondary: 'documentNo',
        columns: [
          ['id', 'ID'],
          ['fullName', 'Imię i nazwisko'],
          ['birthDate', 'Data ur.'],
          ['documentNo', 'Dokument'],
          ['licenseStatus', 'Prawo jazdy'],
          ['status', 'Status']
        ],
        fields: [
          { key: 'firstName', label: 'Imię', required: true },
          { key: 'lastName', label: 'Nazwisko', required: true },
          { key: 'birthDate', label: 'Data urodzenia', type: 'date' },
          { key: 'gender', label: 'Płeć', placeholder: 'Wpisz płeć' },
          { key: 'documentNo', label: 'Numer dokumentu' },
          { key: 'phone', label: 'Telefon' },
          { key: 'address', label: 'Adres', full: true },
          { key: 'licenseNo', label: 'Numer prawa jazdy' },
          { key: 'licenseStatus', label: 'Status prawa jazdy', required: true, placeholder: 'Wpisz status prawa jazdy' },
          { key: 'status', label: 'Status osoby', required: true, placeholder: 'Wpisz status osoby' },
          { key: 'tags', label: 'Tagi / oznaczenia', placeholder: 'np. agresywny, broń, recydywa', full: true },
          { key: 'notes', label: 'Notatki operacyjne', type: 'textarea', full: true }
        ]
      },

      vehicles: {
        title: 'Ewidencja pojazdów',
        description: 'Rejestr pojazdów, właścicieli, ubezpieczeń oraz statusów operacyjnych.',
        icon: '▰',
        primary: 'plate',
        secondary: 'make',
        columns: [
          ['id', 'ID'],
          ['plate', 'Rejestracja'],
          ['make', 'Marka'],
          ['model', 'Model'],
          ['ownerId', 'Właściciel'],
          ['status', 'Status']
        ],
        fields: [
          { key: 'plate', label: 'Numer rejestracyjny', required: true },
          { key: 'vin', label: 'VIN' },
          { key: 'make', label: 'Marka' },
          { key: 'model', label: 'Model' },
          { key: 'year', label: 'Rok produkcji', type: 'number' },
          { key: 'color', label: 'Kolor' },
          { key: 'ownerId', label: 'Właściciel', type: 'citizen' },
          { key: 'insurance', label: 'Ubezpieczenie', required: true, placeholder: 'Wpisz status ubezpieczenia' },
          { key: 'inspection', label: 'Badanie techniczne', required: true, placeholder: 'Wpisz status badania technicznego' },
          { key: 'status', label: 'Status pojazdu', type: 'select', options: ['Czysty', 'Obserwowany', 'Poszukiwany', 'Skradziony', 'Zabezpieczony'] },
          { key: 'notes', label: 'Notatki', type: 'textarea', full: true }
        ]
      },

      tickets: {
        title: 'Mandaty i wykroczenia',
        description: 'Rejestr wystawionych mandatów, punktów i statusów płatności.',
        icon: '₿',
        primary: 'caseNo',
        secondary: 'article',
        columns: [
          ['caseNo', 'Numer sprawy'],
          ['citizenId', 'Osoba'],
          ['article', 'Podstawa'],
          ['amount', 'Kwota'],
          ['points', 'Punkty'],
          ['status', 'Status'],
          ['date', 'Data']
        ],
        fields: [
          { key: 'citizenId', label: 'Ukarana osoba', type: 'citizen', required: true },
          { key: 'vehicleId', label: 'Pojazd', type: 'vehicle' },
          { key: 'officer', label: 'Funkcjonariusz' },
          { key: 'date', label: 'Data i czas', type: 'datetime-local' },
          { key: 'location', label: 'Miejsce', full: true },
          { key: 'article', label: 'Artykuł / podstawa prawna', required: true, full: true },
          { key: 'description', label: 'Opis wykroczenia', type: 'textarea', full: true },
          { key: 'amount', label: 'Kwota mandatu', type: 'number' },
          { key: 'points', label: 'Punkty karne', type: 'number' },
          { key: 'status', label: 'Status', type: 'select', options: ['Nieopłacony', 'Opłacony', 'Anulowany', 'Odmowa przyjęcia'] }
        ]
      },

      arrests: {
        title: 'Zatrzymania',
        description: 'Dokumentacja zatrzymań, podstaw, zabezpieczonych przedmiotów i zwolnień.',
        icon: '⌁',
        primary: 'caseNo',
        secondary: 'reason',
        columns: [
          ['caseNo', 'Numer sprawy'],
          ['citizenId', 'Zatrzymany'],
          ['reason', 'Powód'],
          ['startDate', 'Od'],
          ['status', 'Status'],
          ['officer', 'Funkcjonariusz']
        ],
        fields: [
          { key: 'citizenId', label: 'Zatrzymana osoba', type: 'citizen', required: true },
          { key: 'officer', label: 'Funkcjonariusz prowadzący' },
          { key: 'startDate', label: 'Data zatrzymania', type: 'datetime-local' },
          { key: 'endDate', label: 'Data zwolnienia', type: 'datetime-local' },
          { key: 'location', label: 'Miejsce zatrzymania', full: true },
          { key: 'reason', label: 'Powód zatrzymania', required: true, full: true },
          { key: 'articles', label: 'Zarzuty / artykuły', type: 'textarea', full: true },
          { key: 'items', label: 'Zabezpieczone przedmioty', type: 'textarea', full: true },
          { key: 'status', label: 'Status', type: 'select', options: ['Aktywne', 'Zwolniony', 'Przekazany', 'Aresztowany'] },
          { key: 'notes', label: 'Uwagi', type: 'textarea', full: true }
        ]
      },

      reports: {
        title: 'Raporty służbowe',
        description: 'Notatki urzędowe, raporty interwencji, zdarzeń drogowych i czynności.',
        icon: '▤',
        primary: 'title',
        secondary: 'caseNo',
        columns: [
          ['caseNo', 'Numer sprawy'],
          ['title', 'Tytuł'],
          ['type', 'Typ'],
          ['citizenId', 'Osoba'],
          ['officer', 'Autor'],
          ['status', 'Status'],
          ['date', 'Data']
        ],
        fields: [
          { key: 'title', label: 'Tytuł raportu', required: true, full: true },
          { key: 'type', label: 'Typ', type: 'select', options: ['Interwencja', 'Wypadek', 'Kontrola drogowa', 'Przeszukanie', 'Pościg', 'Użycie siły', 'Inne'] },
          { key: 'citizenId', label: 'Osoba powiązana', type: 'citizen' },
          { key: 'officer', label: 'Autor raportu' },
          { key: 'date', label: 'Data zdarzenia', type: 'datetime-local' },
          { key: 'location', label: 'Miejsce zdarzenia', full: true },
          { key: 'status', label: 'Status', type: 'select', options: ['Szkic', 'W toku', 'Zatwierdzony', 'Zamknięty'] },
          { key: 'summary', label: 'Krótkie podsumowanie', type: 'textarea', full: true },
          { key: 'details', label: 'Pełny opis zdarzenia', type: 'textarea', full: true },
          { key: 'witnesses', label: 'Świadkowie / inne osoby', type: 'textarea', full: true }
        ]
      },

      wanted: {
        title: 'Poszukiwani',
        description: 'Aktywne komunikaty o osobach, pojazdach i przedmiotach wymagających uwagi.',
        icon: '⚠',
        primary: 'title',
        secondary: 'target',
        columns: [
          ['id', 'ID'],
          ['title', 'Komunikat'],
          ['type', 'Typ'],
          ['target', 'Cel'],
          ['priority', 'Priorytet'],
          ['status', 'Status'],
          ['expiresAt', 'Wygasa']
        ],
        fields: [
          { key: 'title', label: 'Tytuł komunikatu', required: true, full: true },
          { key: 'type', label: 'Typ', type: 'select', options: ['Osoba', 'Pojazd', 'Przedmiot', 'Miejsce'] },
          { key: 'target', label: 'Cel / dane identyfikacyjne', required: true, full: true },
          { key: 'priority', label: 'Priorytet', type: 'select', options: ['Niski', 'Średni', 'Wysoki', 'Krytyczny'] },
          { key: 'status', label: 'Status', type: 'select', options: ['Aktywne', 'Wstrzymane', 'Zamknięte'] },
          { key: 'createdAtCustom', label: 'Data publikacji', type: 'datetime-local' },
          { key: 'expiresAt', label: 'Data wygaśnięcia', type: 'datetime-local' },
          { key: 'officer', label: 'Funkcjonariusz prowadzący' },
          { key: 'description', label: 'Opis i instrukcje', type: 'textarea', full: true }
        ]
      },

      evidence: {
        title: 'Magazyn dowodów',
        description: 'Łańcuch zabezpieczenia, opis, lokalizacja i status materiałów dowodowych.',
        icon: '◇',
        primary: 'name',
        secondary: 'caseNo',
        columns: [
          ['id', 'ID dowodu'],
          ['caseNo', 'Sprawa'],
          ['name', 'Nazwa'],
          ['type', 'Typ'],
          ['storage', 'Magazyn'],
          ['collector', 'Zabezpieczył'],
          ['status', 'Status']
        ],
        fields: [
          { key: 'caseNo', label: 'Numer sprawy', required: true },
          { key: 'name', label: 'Nazwa dowodu', required: true },
          { key: 'type', label: 'Typ', type: 'select', options: ['Przedmiot', 'Broń', 'Substancja', 'Dokument', 'Zdjęcie', 'Nagranie', 'Elektronika', 'Inne'] },
          { key: 'date', label: 'Data zabezpieczenia', type: 'datetime-local' },
          { key: 'collector', label: 'Zabezpieczył' },
          { key: 'storage', label: 'Miejsce przechowywania' },
          { key: 'status', label: 'Status', type: 'select', options: ['Zabezpieczony', 'W badaniu', 'Wydany', 'Zniszczony', 'Zwrócony'] },
          { key: 'hash', label: 'Hash / plomba / numer zabezpieczenia', full: true },
          { key: 'description', label: 'Opis dowodu', type: 'textarea', full: true }
        ]
      },

      dispatch: {
        title: 'Dyspozytornia i zgłoszenia',
        description: 'Przyjmowanie zgłoszeń, priorytety, przydzielone jednostki i aktualny status.',
        icon: '☎',
        primary: 'callNo',
        secondary: 'category',
        columns: [
          ['callNo', 'Numer'],
          ['category', 'Kategoria'],
          ['priority', 'Priorytet'],
          ['location', 'Lokalizacja'],
          ['units', 'Jednostki'],
          ['status', 'Status'],
          ['createdAtCustom', 'Przyjęto']
        ],
        fields: [
          { key: 'category', label: 'Kategoria', type: 'select', options: ['Alarmowe', 'Przemoc', 'Ruch drogowy', 'Kradzież', 'Zakłócanie porządku', 'Medyczne', 'Pożar', 'Inne'] },
          { key: 'priority', label: 'Priorytet', type: 'select', options: ['P1 — natychmiast', 'P2 — pilne', 'P3 — standard', 'P4 — niskie'] },
          { key: 'caller', label: 'Zgłaszający' },
          { key: 'phone', label: 'Telefon zgłaszającego' },
          { key: 'location', label: 'Lokalizacja', required: true, full: true },
          { key: 'units', label: 'Przydzielone jednostki', placeholder: 'np. KSP-21, KSP-34', full: true },
          { key: 'status', label: 'Status', type: 'select', options: ['Nowe', 'Przyjęte', 'Jednostka w drodze', 'Na miejscu', 'Zamknięte', 'Anulowane'] },
          { key: 'createdAtCustom', label: 'Data zgłoszenia', type: 'datetime-local' },
          { key: 'closedAt', label: 'Data zamknięcia', type: 'datetime-local' },
          { key: 'description', label: 'Opis zgłoszenia', type: 'textarea', full: true }
        ]
      }
    };

    var collectionLabels = {
      citizens: 'Osoby',
      vehicles: 'Pojazdy',
      tickets: 'Mandaty',
      arrests: 'Zatrzymania',
      reports: 'Raporty',
      wanted: 'Poszukiwani',
      evidence: 'Dowody',
      dispatch: 'Zgłoszenia',
      duty: 'Służba'
    };

    var fieldLabels = {};
    Object.keys(pageConfig).forEach(function (name) {
      fieldLabels[name] = {};
      pageConfig[name].fields.forEach(function (field) {
        fieldLabels[name][field.key] = field.label;
      });
      fieldLabels[name].id = 'ID rekordu';
      fieldLabels[name].caseNo = fieldLabels[name].caseNo || 'Numer sprawy';
      fieldLabels[name].callNo = fieldLabels[name].callNo || 'Numer zgłoszenia';
      fieldLabels[name].createdAt = 'Utworzono';
      fieldLabels[name].updatedAt = 'Zaktualizowano';
      fieldLabels[name].createdBy = 'Utworzył';
      fieldLabels[name].updatedBy = 'Zaktualizował';
    });

    function escapeHtml(value) {
      return String(value === null || value === undefined ? '' : value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }

    function api(url, options) {
      options = options || {};
      options.headers = Object.assign(
        { 'Content-Type': 'application/json' },
        options.headers || {}
      );

      return fetch(url, options).then(async function (response) {
        if (response.status === 401) {
          showLogin();
          throw new Error('Sesja wygasła. Zaloguj się ponownie.');
        }

        var type = response.headers.get('content-type') || '';
        var body = type.includes('application/json') ? await response.json() : await response.text();

        if (!response.ok) {
          throw new Error((body && body.error) || body || 'Błąd połączenia z serwerem.');
        }
        return body;
      });
    }

    function toast(title, message, type) {
      type = type || 'info';
      var container = document.getElementById('toastContainer');
      var item = document.createElement('div');
      item.className = 'toast ' + type;
      item.innerHTML =
        '<div class="toast-mark">' + (type === 'success' ? '✓' : type === 'error' ? '!' : 'i') + '</div>' +
        '<div class="toast-content"><strong>' + escapeHtml(title) + '</strong><span>' +
        escapeHtml(message) + '</span></div>';

      container.appendChild(item);
      setTimeout(function () {
        item.style.opacity = '0';
        item.style.transform = 'translateY(8px)';
        setTimeout(function () { item.remove(); }, 220);
      }, 3800);
    }

    function showLogin() {
      document.getElementById('loginScreen').classList.remove('hidden');
      document.getElementById('app').classList.add('hidden');
    }

    function showApp() {
      document.getElementById('loginScreen').classList.add('hidden');
      document.getElementById('app').classList.remove('hidden');
    }

    function formatDate(value, includeTime) {
      if (!value) return '—';
      var date = new Date(value);
      if (Number.isNaN(date.getTime())) return String(value);
      var options = includeTime
        ? { dateStyle: 'short', timeStyle: 'short' }
        : { dateStyle: 'short' };
      return new Intl.DateTimeFormat('pl-PL', options).format(date);
    }

    function toLocalInputDate(value) {
      if (!value) return '';
      var date = new Date(value);
      if (Number.isNaN(date.getTime())) return value;
      var local = new Date(date.getTime() - date.getTimezoneOffset() * 60000);
      return local.toISOString().slice(0, 16);
    }

    function statusBadge(value) {
      var text = String(value || 'Brak');
      var low = text.toLowerCase();
      var color = 'blue';

      if (
        low.startsWith('p1') ||
        low.includes('pościg') ||
        low.includes('poszuk') ||
        low.includes('kryty') ||
        low.includes('skradz') ||
        low.includes('cofnię') ||
        low.includes('nieważ') ||
        low.includes('brak') ||
        low.includes('aktywn')
      ) color = 'red';
      else if (
        low.startsWith('p2') ||
        low.startsWith('p3') ||
        low.includes('przerwa') ||
        low.includes('w toku') ||
        low.includes('w drodze') ||
        low.includes('wysoki') ||
        low.includes('nieopłac') ||
        low.includes('obserw')
      ) color = 'yellow';
      else if (
        low.includes('dostęp') ||
        low.includes('opłac') ||
        low.includes('ważne') ||
        low.includes('czysty') ||
        low.includes('zatwier') ||
        low.includes('zamknię') ||
        low.includes('zwoln')
      ) color = 'green';
      else if (low.includes('transport') || low.includes('przydziel') || low.includes('średni') || low.includes('przyję')) color = 'purple';

      return '<span class="badge ' + color + '">' + escapeHtml(text) + '</span>';
    }

    function findCitizenName(id) {
      if (!id) return '—';
      var item = state.citizens.find(function (person) { return person.id === id; });
      return item ? (item.fullName || item.id) : id;
    }

    function findVehicleName(id) {
      if (!id) return '—';
      var item = state.vehicles.find(function (vehicle) { return vehicle.id === id; });
      return item ? ((vehicle.plate || item.id) + ' · ' + (item.make || '') + ' ' + (item.model || '')) : id;
    }

    function formatCell(collection, key, value) {
      if (key === 'citizenId' || key === 'ownerId') return escapeHtml(findCitizenName(value));
      if (key === 'vehicleId') return escapeHtml(findVehicleName(value));
      if (key === 'status' || key === 'priority' || key === 'licenseStatus') return statusBadge(value);
      if (/date|At$/i.test(key) && value) return escapeHtml(formatDate(value, true));
      if (key === 'amount' && value !== '' && value !== undefined) return escapeHtml(value) + ' zł';
      if (value === null || value === undefined || value === '') return '<span class="cell-muted">—</span>';
      return escapeHtml(value);
    }

    function getRecordTitle(collection, record) {
      var cfg = pageConfig[collection];
      return (
        record[cfg.primary] ||
        record.fullName ||
        record.caseNo ||
        record.callNo ||
        record.plate ||
        record.id
      );
    }

    function setClock() {
      var now = new Date();
      document.getElementById('clockTime').textContent =
        new Intl.DateTimeFormat('pl-PL', {
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit'
        }).format(now);
      document.getElementById('clockDate').textContent =
        new Intl.DateTimeFormat('pl-PL', {
          weekday: 'short',
          day: '2-digit',
          month: 'long'
        }).format(now);
    }

    function setUser(user) {
      state.user = user;
      document.getElementById('sidebarUserName').textContent = user.displayName || user.username;
      document.getElementById('sidebarUserRole').textContent = user.isPreview
        ? 'Tryb podglądu · tylko odczyt'
        : (user.isAdmin ? 'Użytkownik · administrator' : 'Użytkownik Discord');

      var avatar = document.getElementById('sidebarAvatar');
      if (user.avatar) {
        avatar.innerHTML = '<img src="' + escapeHtml(user.avatar) + '" alt="" style="width:100%;height:100%;object-fit:cover;border-radius:inherit">';
      } else {
        avatar.textContent = (user.displayName || user.username || 'K').slice(0, 1).toUpperCase();
      }
    }

    async function loadLookups() {
      try {
        var responses = await Promise.all([
          api('/api/citizens'),
          api('/api/vehicles')
        ]);
        state.citizens = responses[0].items || [];
        state.vehicles = responses[1].items || [];
      } catch (error) {
        console.error(error);
      }
    }

    function pageHeader(title, description, actions) {
      var previewNotice = state.user && state.user.isPreview
        ? '<div class="preview-mode-banner"><strong>TRYB PODGLĄDU</strong> — możesz obejrzeć cały system, ale zapisywanie, edycja, służba i operacje administracyjne są zablokowane. Pełny dostęp wymaga logowania Discord.</div>'
        : '';

      return (
        previewNotice +
        '<div class="page-header">' +
          '<div><h2>' + escapeHtml(title) + '</h2><p>' + escapeHtml(description) + '</p></div>' +
          '<div class="header-actions">' + (actions || '') + '</div>' +
        '</div>'
      );
    }

    async function navigate(page) {
      if (state.dutyTimer) {
        clearInterval(state.dutyTimer);
        state.dutyTimer = null;
      }
      if (state.cadTimer) {
        clearInterval(state.cadTimer);
        state.cadTimer = null;
      }
      state.currentPage = page;
      state.currentItems = [];
      state.currentRecord = null;

      document.querySelectorAll('.nav-button').forEach(function (button) {
        button.classList.toggle('active', button.dataset.page === page);
      });

      document.getElementById('sidebar').classList.remove('open');
      document.getElementById('content').innerHTML = '<div class="loader"></div>';

      try {
        if (page === 'dashboard') await renderDashboard();
        else if (page === 'police') await renderPoliceDashboard();
        else if (page === 'operations') await renderOperations();
        else if (page === 'sessions') renderSessions();
        else if (page === 'serverlive') await renderServerLive();
        else if (page === 'ems' || page === 'fire' || page === 'dot') renderDepartmentPreview(page);
        else if (page === 'civilian') renderCivilian();
        else if (page === 'economy') renderEconomy();
        else if (page === 'discordhub') await renderDiscordHub();
        else if (page === 'lab') renderLab();
        else if (page === 'duty') await renderDuty();
        else if (page === 'cad') await renderCad();
        else if (page === 'audit') await renderAudit();
        else if (page === 'settings') renderSettings();
        else await renderCollection(page);
      } catch (error) {
        document.getElementById('content').innerHTML =
          pageHeader('Błąd', 'Nie udało się załadować danych.') +
          '<div class="panel"><div class="empty-state"><div class="empty-state-icon">!</div>' +
          '<h3>Wystąpił problem</h3><p>' + escapeHtml(error.message) + '</p></div></div>';
        toast('Błąd', error.message, 'error');
      }
    }


    function moduleCard(icon, title, description, page, color, stateLabel, meta) {
      return '<button class="module-card" style="--module:' + color + '" onclick="navigate(\'' + page + '\')">' +
        '<div class="module-head"><span class="module-icon">' + icon + '</span><span class="module-state">' + escapeHtml(stateLabel) + '</span></div>' +
        '<h4>' + escapeHtml(title) + '</h4><p>' + escapeHtml(description) + '</p>' +
        '<div class="module-meta"><span>' + escapeHtml(meta) + '</span><b>Otwórz →</b></div></button>';
    }

    function previewCard(icon, title, description, tag) {
      return '<div class="preview-card"><span class="preview-tag">' + escapeHtml(tag || 'Podgląd V3') + '</span>' +
        '<div class="preview-icon" style="margin-top:13px">' + icon + '</div><h3>' + escapeHtml(title) + '</h3><p>' + escapeHtml(description) + '</p></div>';
    }

    function integrationNode(title, description, active, waitingText) {
      return '<div class="mesh-node"><b>' + escapeHtml(title) + '</b><span>' + escapeHtml(description) + '</span>' +
        '<span class="mesh-status ' + (active ? '' : 'wait') + '">' + escapeHtml(active ? 'Połączono' : (waitingText || 'Oczekuje')) + '</span></div>';
    }

    async function renderDashboard() {
      var responses = await Promise.all([api('/api/dashboard'), api('/api/integrations/status')]);
      var data = responses[0];
      var integrations = responses[1];
      var stats = data.stats || {};
      var currentUser = state.user && (state.user.displayName || state.user.username) || 'Użytkowniku';

      var html = '<div class="city-hero"><div><span class="city-kicker"><span class="pulse-dot"></span> City Operations Network · V3 Preview</span>' +
        '<h2>Jedno centrum. Całe miasto. Pełna niezależność RP.</h2>' +
        '<p>Witaj, ' + escapeHtml(currentUser) + '. KSP jest teraz jednym z elementów większego ekosystemu. Docelowo ta sama operacja połączy policję, PRM, PSP, drogi, dyspozytornię, cywilów, Discord i serwer ER:LC.</p>' +
        '<div class="city-hero-actions"><button class="button primary" onclick="navigate(\'operations\')">◈ Otwórz centrum zdarzeń</button>' +
        '<button class="button" onclick="navigate(\'serverlive\')">⌁ Integracja ER:LC</button><button class="button ghost" onclick="navigate(\'lab\')">✦ Zobacz Innovation Lab</button></div></div>' +
        '<div class="city-radar"><span class="radar-node"></span><span class="radar-node"></span><span class="radar-node"></span><span class="radar-node"></span></div></div>';

      html += '<div class="section-heading"><div><h3>Centrum usług miasta</h3><p>Każdy kafel to osobny „budynek”, ale wszystkie korzystają ze wspólnego konta i wspólnego rdzenia zdarzeń.</p></div><span class="badge blue">BEZ BLOKAD RÓL · PODGLĄD</span></div>';
      html += '<div class="module-grid">' +
        moduleCard('★','KSP · Policja','Działający CAD/MDT, kartoteki, mandaty, zatrzymania, raporty i dowody.','police','#4da3ff','Działa','moduł operacyjny') +
        moduleCard('✚','PRM · Ratownictwo','Karty pacjenta RP, zespoły, transport, triage i wspólne zdarzenia.','ems','#36d79b','Podgląd','moduł medyczny') +
        moduleCard('▲','PSP · Straż pożarna','Zastępy, dowodzenie akcją, strefy zagrożenia i raport końcowy.','fire','#ff625f','Podgląd','moduł ratowniczy') +
        moduleCard('◆','PD · Drogi i transport','Lawety, blokady, utrzymanie dróg, depozyt i obsługa infrastruktury.','dot','#ffc857','Podgląd','moduł techniczny') +
        moduleCard('⌖','Dyspozytornia 112','Jedno zdarzenie, wiele frakcji, przydziały, priorytety i chronologia.','cad','#a582ff','Działa','wspólny CAD') +
        moduleCard('◉','Profil cywila','Postacie RP, pojazdy, dokumenty, licencje, firmy i wnioski.','civilian','#55e7ff','Podgląd','portal mieszkańca') +
        moduleCard('◌','Discord Hub','Role, kanały, służby, powiadomienia, formularze i komendy bota.','discordhub','#7289da','Podgląd','warstwa społeczności') +
        moduleCard('⌁','ER:LC Live','Gracze, drużyny, pojazdy, callsigny, zgłoszenia i webhooki z gry.','serverlive','#3bd391','Gotowy rdzeń','integracja API') +
      '</div>';

      html += '<div class="city-grid"><div class="panel"><div class="panel-header"><div><h3>Puls miasta</h3><span>Dane już działające w obecnym rdzeniu</span></div><span class="badge green">LIVE Z BAZY</span></div><div class="panel-body"><div class="pulse-list">' +
        '<div class="pulse-row"><i class="pulse-line"></i><div><strong>' + Number(stats.activeDuty || 0) + ' osób na służbie</strong><span>Aktywne zmiany i patrole widoczne w CAD</span></div><b>LIVE</b></div>' +
        '<div class="pulse-row"><i class="pulse-line" style="background:var(--yellow)"></i><div><strong>' + Number(stats.openDispatch || 0) + ' otwartych zdarzeń</strong><span>Wspólny rdzeń może później obsługiwać wszystkie frakcje</span></div><b>' + Number(stats.urgentDispatch || 0) + ' P1</b></div>' +
        '<div class="pulse-row"><i class="pulse-line" style="background:var(--blue)"></i><div><strong>' + Number(stats.citizens || 0) + ' profili osób i ' + Number(stats.vehicles || 0) + ' pojazdów</strong><span>Obecna policyjna baza stanie się miejskim rejestrem RP</span></div><b>BAZA</b></div>' +
        '<div class="pulse-row"><i class="pulse-line" style="background:var(--purple)"></i><div><strong>' + Number(stats.reports || 0) + ' raportów operacyjnych</strong><span>W przyszłości spięte z uniwersalnym numerem zdarzenia</span></div><b>HISTORIA</b></div>' +
      '</div></div></div>' +
      '<div class="panel"><div class="panel-header"><div><h3>Siatka integracji</h3><span>Co jest już podłączone, a co czeka na sekret w Renderze</span></div></div><div class="panel-body"><div class="mesh-grid">' +
        integrationNode('Discord OAuth','Logowanie i potwierdzenie członkostwa na serwerze.', integrations.discord.oauth, 'Konfiguracja') +
        integrationNode('Bot Discord','Komendy, role służbowe i automatyczne wiadomości.', integrations.discord.bot, 'Token bota') +
        integrationNode('ER:LC API','Dane serwera, graczy, pojazdów i komendy.', integrations.erlc.api, 'Klucz API') +
        integrationNode('Webhooki ER:LC','Zdarzenia z gry dostarczane w czasie rzeczywistym.', integrations.erlc.webhookVerification, 'Klucz publiczny') +
      '</div></div></div></div>';

      document.getElementById('content').innerHTML = html;
    }

    async function renderOperations() {
      var data = await api('/api/dashboard');
      var calls = data.openDispatch || [];
      var call = calls[0];
      var title = call ? (call.callNo || call.id) + ' · ' + (call.category || 'Zdarzenie') : 'INC-2026-DEMO · Wypadek wielopojazdowy';
      var location = call ? (call.location || 'Lokalizacja niepodana') : 'Postal 204 · Liberty County';
      var priority = call ? (call.priority || 'P2') : 'P1';

      var html = pageHeader('Wspólne centrum zdarzeń','Najważniejszy element V3: jeden incydent łączy wszystkie służby, osoby, pojazdy, raporty i pełną chronologię.','<button class="button primary" onclick="openCreate(\'dispatch\')">＋ Utwórz zdarzenie</button><button class="button" onclick="navigate(\'cad\')">⌖ Otwórz CAD</button>');
      html += '<div class="department-hero" style="--dept:#a582ff"><span class="department-mark">Universal Incident Core</span><h2>' + escapeHtml(title) + '</h2><p>' + escapeHtml(location) + ' · Priorytet ' + escapeHtml(priority) + '. Każda frakcja pracuje na tej samej osi czasu, ale widzi własne formularze i zadania.</p></div>';
      html += '<div class="operation-board" style="margin-top:16px"><div class="panel"><div class="panel-header"><div><h3>Warstwy operacji</h3><span>Jedno zdarzenie, wiele zespołów</span></div></div><div class="panel-body">' +
        '<div class="agency-lane"><strong>KSP · zabezpieczenie i ruch</strong><span>2 jednostki</span></div>' +
        '<div class="agency-lane"><strong>PRM · poszkodowani</strong><span>1 zespół</span></div>' +
        '<div class="agency-lane"><strong>PSP · ratownictwo techniczne</strong><span>1 zastęp</span></div>' +
        '<div class="agency-lane"><strong>PD · usunięcie pojazdów</strong><span>oczekuje</span></div>' +
        '<div class="agency-lane"><strong>Dyspozytor · koordynacja</strong><span>aktywny</span></div>' +
      '</div></div><div class="panel"><div class="panel-header"><div><h3>Oś czasu operacji</h3><span>Podgląd przyszłego rejestru zdarzeń</span></div><span class="badge purple">REPLAY READY</span></div><div class="panel-body"><div class="incident-timeline">' +
        '<div class="timeline-event"><b>20:14 · zgłoszenie przyjęte</b><span>Automatyczne utworzenie wspólnego numeru incydentu.</span></div>' +
        '<div class="timeline-event"><b>20:15 · KSP 2A-21 przydzielony</b><span>Status jednostki zmieniony na „W drodze”.</span></div>' +
        '<div class="timeline-event"><b>20:16 · PRM M-02 zadysponowany</b><span>Moduł medyczny otrzymał kartę pacjenta do uzupełnienia.</span></div>' +
        '<div class="timeline-event"><b>20:18 · aktualizacja z ER:LC</b><span>Ostatni znany postal oraz pojazdy połączone ze zdarzeniem.</span></div>' +
        '<div class="timeline-event"><b>Po zakończeniu · raport AAR</b><span>System odtworzy całą sesję i wygeneruje podsumowanie.</span></div>' +
      '</div></div></div></div>';
      html += '<div class="preview-grid">' +
        previewCard('⛓','Event Graph','Osoba, pojazd, zgłoszenie, mandat, transport i dowód będą połączone relacjami zamiast żyć jako osobne rekordy.','Unikalny rdzeń') +
        previewCard('▶','After Action Replay','Dowódca przewinie zdarzenie minuta po minucie i sprawdzi czasy reakcji oraz decyzje jednostek.','Planowane') +
        previewCard('⚡','Cross-service Panic','Alarm jednej jednostki natychmiast uruchomi wspólną procedurę policji, PRM, PSP i Discorda.','Planowane') +
      '</div>';
      document.getElementById('content').innerHTML = html;
    }

    function renderDepartmentPreview(type) {
      var departments = {
        ems: { mark:'Państwowe Ratownictwo Medyczne', title:'PRM · Medyczny system operacyjny', color:'#36d79b', description:'Zespoły ratownictwa, fikcyjne karty pacjentów RP, triage, transporty i współpraca ze szpitalem.', cards:[['✚','Karta pacjenta RP','Stan postaci, obrażenia RP, wykonane czynności i wynik transportu.'],['▤','Transport medyczny','Jedna karta od wezwania, przez działania na miejscu, aż po przekazanie.'],['⌁','Triage zdarzenia','Wspólny obraz wielu poszkodowanych dla PRM, PSP i dyspozytora.'],['◷','Czasy reakcji','Automatyczne mierzenie zadysponowania, dojazdu i zakończenia.'],['◉','Obsada zespołu','Kierownik, ratownik, ambulans, kanał i bieżący status.'],['◈','Szpital RP','Przekazanie postaci, miejsce docelowe i zamknięcie dokumentacji.']]},
        fire: { mark:'Państwowa Straż Pożarna', title:'PSP · Dowodzenie działaniami', color:'#ff625f', description:'Zastępy, pojazdy, strefy działań, dowódca akcji i pełny raport ratowniczy.', cards:[['▲','Karta zdarzenia','Pożary, wypadki, zagrożenia techniczne i inne działania.'],['⌖','Strefy operacyjne','Sektor bojowy, bezpieczny, medyczny i punkt dowodzenia.'],['◆','Zasoby i pojazdy','Zastępy, sprzęt specjalistyczny i gotowość jednostek.'],['◉','Dowódca akcji','Przekazywanie dowodzenia i chronologia decyzji.'],['✚','Współpraca z PRM','Poszkodowani trafiają do wspólnego incydentu bez przepisywania danych.'],['▤','Raport końcowy','Automatyczny skład jednostek, czas działań i użyte zasoby.']]},
        dot: { mark:'Public Department / DOT', title:'PD · Infrastruktura i transport', color:'#ffc857', description:'Drogi, lawety, pojazdy techniczne, depozyt, blokady oraz obsługa infrastruktury miasta.', cards:[['◆','Zlecenia holowania','Od wezwania przez przyjazd po przekazanie pojazdu na depozyt.'],['▰','Depozyt pojazdów','Powód, właściciel, rejestracja, opłaty RP i status wydania.'],['⌁','Blokady dróg','Odcinki zamknięte, objazdy i informacja dla wszystkich służb.'],['⚙','Awarie infrastruktury','Sygnalizacja, bariery, uszkodzenia i planowane naprawy.'],['◷','Kolejka zleceń','Priorytety i automatyczny wybór najbliższej dostępnej jednostki.'],['◈','Wspólny incydent','Zlecenie techniczne podpięte bezpośrednio do zdarzenia 112.']]}
      };
      var d = departments[type];
      var html = '<div class="department-hero" style="--dept:' + d.color + '"><span class="department-mark">' + escapeHtml(d.mark) + ' · Wersja podglądowa</span><h2>' + escapeHtml(d.title) + '</h2><p>' + escapeHtml(d.description) + '</p><div class="city-hero-actions"><button class="button ghost" onclick="navigate(\'operations\')">◈ Zobacz wspólne zdarzenia</button><span class="badge yellow">FUNKCJE NIE ZAPISUJĄ JESZCZE DANYCH</span></div></div>';
      html += '<div class="preview-grid">' + d.cards.map(function(card){ return previewCard(card[0],card[1],card[2],'Podgląd modułu'); }).join('') + '</div>';
      document.getElementById('content').innerHTML = html;
    }

    async function renderServerLive() {
      var integrations = await api('/api/integrations/status');
      var apiReady = integrations.erlc.api;
      var webhookReady = integrations.erlc.webhookVerification;
      var html = pageHeader('ER:LC Live Gateway','Warstwa łącząca stronę, Discord i prywatny serwer gry. Sekrety pozostają wyłącznie po stronie backendu.','');
      html += '<div class="department-hero" style="--dept:#3bd391"><span class="department-mark">Game Integration Layer</span><h2>' + (apiReady ? 'Klucz API wykryty' : 'Integracja gotowa do konfiguracji') + '</h2><p>Po podaniu klucza w Renderze ten moduł będzie pobierał stan serwera, graczy, drużyny, callsigny, pojazdy i zgłoszenia. Webhooki dostarczą wybrane zdarzenia bez ciągłego odpytywania.</p></div>';
      html += '<div class="preview-grid">' +
        previewCard('◉','Gracze i drużyny','Lista obecnych graczy, ich zespół, callsign i powiązane konto Discord.','API v2') +
        previewCard('▰','Pojazdy na serwerze','Właściciel, tablica i kontekst zdarzenia bez ręcznego przepisywania.','API v2') +
        previewCard('☎','Zgłoszenia z gry','Wybrane połączenia i zdarzenia trafią bezpośrednio do wspólnego CAD.','Webhook') +
        previewCard('⌖','Pozycja operacyjna','Ostatnia dostępna lokalizacja lub postal jednostki w zdarzeniu.','API v2') +
        previewCard('⚡','Komendy systemowe','Bezpieczna lista dozwolonych operacji wykonywanych z panelu administracyjnego.','Backend only') +
        previewCard('◷','Synchronizacja sesji','Automatyczne wykrywanie wejść, wyjść i niespójności służby.','Planowane') +
      '</div>';
      html += '<div class="panel" style="margin-top:16px"><div class="panel-header"><div><h3>Konsola gotowości</h3><span>Żaden sekret nie jest pokazywany w przeglądarce</span></div></div><div class="panel-body"><div class="server-console">' +
        '<span class="console-ok">[OK]</span> Discord OAuth: aktywny<br>' +
        '<span class="' + (apiReady ? 'console-ok' : 'console-wait') + '">[' + (apiReady ? 'OK' : 'WAIT') + ']</span> ERLC_SERVER_KEY: ' + (apiReady ? 'wykryty po stronie serwera' : 'oczekuje na ustawienie w Renderze') + '<br>' +
        '<span class="' + (webhookReady ? 'console-ok' : 'console-wait') + '">[' + (webhookReady ? 'OK' : 'WAIT') + ']</span> ERLC_WEBHOOK_PUBLIC_KEY: ' + (webhookReady ? 'wykryty po stronie serwera' : 'oczekuje na konfigurację') + '<br>' +
        '<span class="console-ok">[READY]</span> Adapter danych: przygotowany do kolejnego etapu<br>' +
        '<span class="console-wait">[PREVIEW]</span> Żadne żądania do ER:LC nie są jeszcze wysyłane</div></div></div>';
      document.getElementById('content').innerHTML = html;
    }

    function renderSessions() {
      var html = pageHeader('Session Director','Planowanie, obsada, przebieg i automatyczne podsumowanie całej sesji RP.','<button class="button primary" onclick="toast(\'Wersja podglądowa\',\'Tworzenie sesji dodamy po zatwierdzeniu układu.\',\'info\')">＋ Zaplanuj sesję</button>');
      html += '<div class="department-hero" style="--dept:#55e7ff"><span class="department-mark">RP Session Control</span><h2>Operacja „Nocne Liberty”</h2><p>Przykładowa sala przygotowań: zapisy, minimalne obsady, scenariusze dynamiczne, cele frakcji i raport po zakończeniu.</p></div>';
      html += '<div class="preview-grid">' +
        previewCard('◷','Harmonogram sesji','Start, planowany koniec, lista zapisanych i automatyczne przypomnienia Discord.','Podgląd') +
        previewCard('▦','Macierz obsady','Minimalna i maksymalna liczba osób dla każdej frakcji oraz wolne stanowiska.','Podgląd') +
        previewCard('✦','Scenario Engine','Administrator uruchamia kontrolowane wydarzenia, cele i kolejne fazy scenariusza.','Unikalne') +
        previewCard('◈','Live Director','Widok sytuacyjny bez zdradzania graczom poufnych elementów scenariusza.','Unikalne') +
        previewCard('▶','Replay sesji','Odtworzenie najważniejszych zdarzeń, zmian statusów i reakcji jednostek.','Planowane') +
        previewCard('▤','Raport AAR','Frekwencja, czasy reakcji, zdarzenia i automatyczne podsumowanie na Discord.','Planowane') +
      '</div>';
      document.getElementById('content').innerHTML = html;
    }

    function renderCivilian() {
      var name = state.user && (state.user.displayName || state.user.username) || 'Użytkownik';
      var html = pageHeader('Portal mieszkańca','Cywil nie dostaje policyjnego formularza. Otrzymuje własne postacie, dokumenty, firmy i historię świata RP.','');
      html += '<div class="department-hero" style="--dept:#55e7ff"><span class="department-mark">Citizen Identity Layer</span><h2>Profil Discord: ' + escapeHtml(name) + '</h2><p>Jedno konto Discord może posiadać kilka oddzielnych postaci RP. Połączenie z Robloxem i zatwierdzanie postaci dodamy w warstwie danych.</p></div>';
      html += '<div class="preview-grid">' +
        previewCard('◉','Postacie RP','Osobne dane, pojazdy, licencje, mandaty i historia dla każdej fikcyjnej postaci.','Podgląd') +
        previewCard('▰','Garaż mieszkańca','Rejestracja pojazdów, dokumenty, ubezpieczenie RP i zgłoszenie sprzedaży.','Podgląd') +
        previewCard('▤','Dokumenty i wnioski','Prawo jazdy RP, pozwolenia, zgłoszenia oraz status sprawy bez pisania do administracji.','Podgląd') +
        previewCard('▦','Firma lub organizacja','Rejestr przedsiębiorstwa, pracownicy, pojazdy służbowe i licencje.','Planowane') +
        previewCard('⚖','Sprawy i należności','Mandaty, decyzje, odwołania i fikcyjne opłaty dostępne w jednym miejscu.','Planowane') +
        previewCard('⌁','Tożsamość Roblox','Kontrolowane połączenie Discord ↔ Roblox zatwierdzane przez administrację.','Fundament') +
      '</div>';
      document.getElementById('content').innerHTML = html;
    }

    function renderEconomy() {
      var html = pageHeader('Firmy, urzędy i świat cywilny','Warstwa administracyjna świata RP: organizacje, nieruchomości, licencje, wnioski i usługi miejskie.','');
      html += '<div class="department-hero" style="--dept:#ffc857"><span class="department-mark">Civic & Economy Layer</span><h2>Miasto działające również poza interwencjami</h2><p>Serwer nie musi opierać się wyłącznie na służbach. Ten moduł tworzy długoterminowy rozwój postaci i organizacji.</p></div>';
      html += '<div class="preview-grid">' +
        previewCard('▦','Rejestr firm','Właściciel, pracownicy, branża, flota i status działalności.','Podgląd') +
        previewCard('⌂','Nieruchomości RP','Przypisanie lokalu do postaci lub firmy i historia zmian właściciela.','Planowane') +
        previewCard('▤','Urząd cyfrowy','Wnioski, decyzje, kolejka spraw i automatyczne powiadomienia Discord.','Podgląd') +
        previewCard('⚖','Sąd i odwołania','Sprawy RP powiązane z incydentem, dowodami i kartoteką postaci.','Planowane') +
        previewCard('◈','Rynek zleceń','Legalne zadania dla firm transportowych, mechaników i ochrony.','Unikalne') +
        previewCard('✦','Reputacja świata','Historia postaci i organizacji bez prostego, sztucznego paska punktów.','Koncepcja') +
      '</div>';
      document.getElementById('content').innerHTML = html;
    }

    async function renderDiscordHub() {
      var integrations = await api('/api/integrations/status');
      var html = pageHeader('Discord Hub','Discord pozostaje głównym wejściem społeczności, ale przestaje być jedynym miejscem przechowywania informacji.','');
      html += '<div class="department-hero" style="--dept:#7289da"><span class="department-mark">Community Integration</span><h2>Jedno konto, wiele serwerów i modułów</h2><p>Obecna wersja wykorzystuje logowanie i członkostwo na Discordzie. Później bot połączy kanały, formularze, służby, alarmy i raporty z tą samą bazą.</p></div>';
      html += '<div class="preview-grid">' +
        previewCard('/','Komendy slash','Służba, status, profil, zgłoszenie, zapisy na sesję i raport bez opuszczania Discorda.','Bot') +
        previewCard('◌','Kanały statusowe','Jedna stale aktualizowana wiadomość zamiast dziesiątek spamujących webhooków.','Unikalne') +
        previewCard('⚡','Alarmy i eskalacja','Panic, P1, brak obsady i awarie integracji kierowane do właściwych osób.','Planowane') +
        previewCard('▤','Formularze Discord','Modal do prostych zgłoszeń, a pełna dokumentacja otwierana na stronie.','Planowane') +
        previewCard('⛓','Wiele serwerów Discord','Jedna instancja może łączyć główny Discord i osobne serwery frakcji.','Architektura') +
        previewCard('◉','Linked Roles','W przyszłości automatyczne potwierdzanie statusu postaci lub członkostwa.','Opcjonalne') +
      '</div>';
      html += '<div class="panel" style="margin-top:16px"><div class="panel-header"><div><h3>Stan integracji</h3><span>Bez ujawniania tokenów</span></div></div><div class="panel-body"><div class="mesh-grid">' +
        integrationNode('OAuth2', 'Logowanie użytkownika i identyfikacja konta.', integrations.discord.oauth, 'Konfiguracja') +
        integrationNode('Bot', 'Komendy, przyciski, role i automatyzacje.', integrations.discord.bot, 'Token bota') +
        integrationNode('Webhook logów', 'Proste komunikaty systemowe do kanału.', integrations.discord.webhook, 'Adres webhooka') +
        integrationNode('Brama ról', integrations.discord.roleGate ? 'Dostęp ograniczony rolą.' : 'Na etapie V3 role nie blokują modułów.', true, '') +
      '</div></div></div>';
      document.getElementById('content').innerHTML = html;
    }

    function renderLab() {
      var html = pageHeader('Innovation Lab','Pomysły, które mają odróżnić ten system od zwykłego CAD-u i gotowych paneli dla wielu serwerów.','');
      html += '<div class="department-hero" style="--dept:#a582ff"><span class="department-mark">Experimental Layer</span><h2>Nie kopiujemy panelu. Budujemy cyfrowego bliźniaka sesji RP.</h2><p>Każdy rekord, gracz, postać, pojazd, jednostka i zdarzenie tworzy jeden spójny model świata. To pozwala później analizować, odtwarzać i automatyzować sesję.</p></div>';
      html += '<div class="preview-grid">' +
        previewCard('⛓','RP Event Graph','Graf relacji pokaże, dlaczego dana osoba, pojazd lub raport jest powiązany ze sprawą.','Flagship') +
        previewCard('▶','Session Time Machine','Przewijanie sesji minuta po minucie: wejścia, zgłoszenia, statusy, pojazdy i decyzje.','Flagship') +
        previewCard('◎','Digital Twin','Aktualny stan świata RP odwzorowany w jednym modelu niezależnym od pojedynczej sesji gry.','Flagship') +
        previewCard('✦','Scenario Orchestrator','Kontrolowane wydarzenia i fazy scenariusza uruchamiane przez dyrektora sesji.','Unikalne') +
        previewCard('⚡','Smart Dispatch Suggestions','System sugeruje właściwy typ jednostki na podstawie kategorii, statusu i obciążenia.','Później') +
        previewCard('▤','Automatic AAR','Raport po sesji z frekwencją, zdarzeniami i czasami reakcji bez ręcznego zbierania.','Później') +
        previewCard('◈','World Continuity','Konsekwencje zdarzeń przechodzą na kolejne sesje zamiast resetować się po wyjściu z gry.','Unikalne') +
        previewCard('⌁','Integration Health','Panel sam wykrywa awarię Discorda, ER:LC, bazy lub webhooków i pokazuje wpływ na system.','Techniczne') +
        previewCard('◆','Privacy Modes','Inny poziom szczegółów dla gracza, frakcji, dyspozytora i administracji bez duplikowania danych.','Docelowo') +
      '</div>';
      document.getElementById('content').innerHTML = html;
    }

    async function renderPoliceDashboard() {
      var data = await api('/api/dashboard');
      var stats = data.stats;

      var cards = [
        ['Osoby w bazie', stats.citizens, '◎', '#2f8cff', 'Pełna kartoteka obywateli'],
        ['Pojazdy', stats.vehicles, '▰', '#55e7ff', 'Zarejestrowane pojazdy'],
        ['Na służbie', stats.activeDuty, '◉', '#3bd391', 'Aktualnie aktywni funkcjonariusze'],
        ['Dostępne patrole', stats.availableDuty, '⌖', '#55e7ff', 'Gotowe do przyjęcia zgłoszenia'],
        ['Zgłoszenia P1', stats.urgentDispatch, '!', '#ff5364', 'Najwyższy priorytet'],
        ['Aktywne poszukiwania', stats.activeWanted, '⚠', '#ff5364', 'Wymagają natychmiastowej uwagi'],
        ['Otwarte zgłoszenia', stats.openDispatch, '☎', '#ffc857', 'W toku lub oczekujące'],
        ['Mandaty', stats.tickets, '₿', '#a582ff', 'Łączna liczba wystawionych'],
        ['Nieopłacone', stats.unpaidTickets, '!', '#ff8a4c', 'Mandaty oczekujące'],
        ['Zatrzymania', stats.arrests, '⌁', '#3bd391', 'Łączna liczba wpisów'],
        ['Raporty', stats.reports, '▤', '#67b2ff', 'Dokumentacja służbowa']
      ];

      var html = pageHeader(
        'Panel operacyjny',
        'Bieżący obraz sytuacji, szybki dostęp do najważniejszych modułów i ostatnich zdarzeń.',
        '<button class="button success" onclick="navigate(\'duty\')">◉ Aktywna służba</button>' +
        '<button class="button" onclick="navigate(\'cad\')">⌖ Otwórz CAD</button>' +
        '<button class="button primary" onclick="openCreate(\'dispatch\')">＋ Nowe zgłoszenie</button>' +
        '<button class="button" onclick="openCreate(\'reports\')">＋ Nowy raport</button>'
      );

      html += '<div class="stats-grid">';
      cards.forEach(function (card) {
        html +=
          '<div class="stat-card" style="--accent:' + card[3] + '">' +
            '<div class="stat-top"><span>' + escapeHtml(card[0]) + '</span><span class="stat-icon">' + card[2] + '</span></div>' +
            '<div class="stat-value">' + Number(card[1] || 0) + '</div>' +
            '<div class="stat-foot">' + escapeHtml(card[4]) + '</div>' +
          '</div>';
      });
      html += '</div>';

      html +=
        '<div class="dashboard-grid">' +
          '<div style="display:flex;flex-direction:column;gap:16px">' +
            '<div class="panel">' +
              '<div class="panel-header"><div><h3>Szybkie czynności</h3><span>Najczęściej używane działania</span></div></div>' +
              '<div class="panel-body"><div class="quick-grid">' +
                quickAction('◎', 'Dodaj osobę', 'Nowy wpis w kartotece', 'citizens') +
                quickAction('▰', 'Dodaj pojazd', 'Rejestracja i właściciel', 'vehicles') +
                quickAction('₿', 'Wystaw mandat', 'Wykroczenie i należność', 'tickets') +
                quickAction('⌁', 'Zatrzymanie', 'Dokumentacja czynności', 'arrests') +
                quickAction('▤', 'Raport', 'Notatka lub interwencja', 'reports') +
                quickAction('⚠', 'Dodaj komunikat', 'Komunikat operacyjny', 'wanted') +
                quickAction('◇', 'Zabezpiecz dowód', 'Łańcuch przechowywania', 'evidence') +
                quickAction('☎', 'Przyjmij zgłoszenie', 'Nowe zdarzenie', 'dispatch') +
              '</div></div>' +
            '</div>' +
            dashboardListPanel('Aktywne poszukiwania', 'Najwyższy priorytet', data.activeWanted, 'wanted') +
            dashboardListPanel('Otwarte zgłoszenia', 'Dyspozytornia', data.openDispatch, 'dispatch') +
          '</div>' +
          '<div style="display:flex;flex-direction:column;gap:16px">' +
            dashboardUnitsPanel(data.activeUnits || []) +
            '<div class="panel">' +
              '<div class="panel-header"><div><h3>Ostatnia aktywność</h3><span>Dziennik systemowy</span></div>' +
              '<button class="button small ghost" onclick="navigate(\'audit\')">Pełny dziennik</button></div>' +
              '<div class="panel-body">' + auditList(data.recentAudit) + '</div>' +
            '</div>' +
            dashboardListPanel('Aktywne zatrzymania', 'Osoby pozostające w dyspozycji', data.activeArrests, 'arrests') +
          '</div>' +
        '</div>';

      document.getElementById('content').innerHTML = html;
    }

    function quickAction(icon, title, description, collection) {
      return (
        '<button class="quick-action" onclick="openCreate(\'' + collection + '\')">' +
          '<span style="font-size:20px;color:var(--blue-2)">' + icon + '</span>' +
          '<b>' + escapeHtml(title) + '</b>' +
          '<span>' + escapeHtml(description) + '</span>' +
        '</button>'
      );
    }

    function dashboardListPanel(title, subtitle, items, collection) {
      var body = '';
      if (!items || !items.length) {
        body = '<div class="empty-state" style="padding:28px 10px"><p>Brak aktywnych wpisów.</p></div>';
      } else {
        body = '<div class="list">';
        items.forEach(function (item) {
          var name = getRecordTitle(collection, item);
          var sub = item.location || item.target || item.reason || item.description || item.status || item.id;
          body +=
            '<div class="list-item">' +
              '<div class="list-item-main"><strong>' + escapeHtml(name) + '</strong><span>' + escapeHtml(sub) + '</span></div>' +
              statusBadge(item.priority || item.status) +
              '<button class="icon-button" onclick="openView(\'' + collection + '\',\'' + item.id + '\')">›</button>' +
            '</div>';
        });
        body += '</div>';
      }

      return (
        '<div class="panel">' +
          '<div class="panel-header"><div><h3>' + escapeHtml(title) + '</h3><span>' + escapeHtml(subtitle) + '</span></div>' +
          '<button class="button small ghost" onclick="navigate(\'' + collection + '\')">Zobacz wszystkie</button></div>' +
          '<div class="panel-body">' + body + '</div>' +
        '</div>'
      );
    }

    function dashboardUnitsPanel(units) {
      var body = '';
      if (!units.length) {
        body = '<div class="empty-state" style="padding:28px 10px"><p>Nikt nie rozpoczął służby.</p></div>';
      } else {
        body = '<div class="list">' + units.map(function (unit) {
          return '<div class="list-item">' +
            '<div class="list-item-main"><strong>' + escapeHtml(unit.callSign || unit.displayName) + '</strong>' +
            '<span>' + escapeHtml(unit.displayName) + ' · ' + escapeHtml(unit.vehicle || unit.unitType || 'Patrol') + '</span></div>' +
            statusBadge(unit.patrolStatus) +
          '</div>';
        }).join('') + '</div>';
      }
      return '<div class="panel">' +
        '<div class="panel-header"><div><h3>Patrole na służbie</h3><span>Aktualna obsada jednostek</span></div>' +
        '<button class="button small ghost" onclick="navigate(\'cad\')">Otwórz CAD</button></div>' +
        '<div class="panel-body">' + body + '</div></div>';
    }

    function auditList(items) {
      if (!items || !items.length) {
        return '<div class="empty-state" style="padding:28px 10px"><p>Brak operacji w dzienniku.</p></div>';
      }

      var html = '<div class="list">';
      items.forEach(function (item) {
        html +=
          '<div class="list-item audit-item">' +
            '<div class="list-item-main">' +
              '<strong>' + escapeHtml(item.actorName || 'System') + ' · ' + escapeHtml(item.action) + '</strong>' +
              '<span>' + escapeHtml(item.collection || '') + ' / ' + escapeHtml(item.recordId || '') +
              ' · ' + escapeHtml(formatDate(item.timestamp, true)) + '</span>' +
            '</div>' +
          '</div>';
      });
      return html + '</div>';
    }

    async function renderCollection(collection) {
      var cfg = pageConfig[collection];
      if (!cfg) throw new Error('Nieznany moduł.');

      await loadLookups();
      var response = await api('/api/' + collection);
      state.currentItems = response.items || [];

      var actions =
        '<button class="button" onclick="exportCsv(\'' + collection + '\')">⇩ CSV</button>' +
        '<button class="button primary" onclick="openCreate(\'' + collection + '\')">＋ Dodaj rekord</button>';

      var html = pageHeader(cfg.title, cfg.description, actions);
      html +=
        '<div class="table-toolbar">' +
          '<input id="tableSearch" class="table-search" placeholder="Filtruj bieżącą tabelę...">' +
          '<span class="badge blue">' + state.currentItems.length + ' rekordów</span>' +
        '</div>' +
        '<div class="table-wrap"><table><thead><tr>';

      cfg.columns.forEach(function (column) {
        html += '<th>' + escapeHtml(column[1]) + '</th>';
      });
      html += '<th style="text-align:right">Akcje</th></tr></thead><tbody id="tableBody"></tbody></table></div>';

      document.getElementById('content').innerHTML = html;
      renderRows(collection, state.currentItems);

      document.getElementById('tableSearch').addEventListener('input', function (event) {
        var query = event.target.value.toLowerCase().trim();
        var filtered = state.currentItems.filter(function (item) {
          return Object.values(item).join(' ').toLowerCase().includes(query);
        });
        renderRows(collection, filtered);
      });
    }

    function renderRows(collection, items) {
      var cfg = pageConfig[collection];
      var body = document.getElementById('tableBody');
      if (!body) return;

      if (!items.length) {
        body.innerHTML =
          '<tr><td colspan="' + (cfg.columns.length + 1) + '">' +
            '<div class="empty-state">' +
              '<div class="empty-state-icon">' + cfg.icon + '</div>' +
              '<h3>Brak rekordów</h3>' +
              '<p>Dodaj pierwszy wpis, używając przycisku u góry.</p>' +
            '</div>' +
          '</td></tr>';
        return;
      }

      var html = '';
      items.forEach(function (item) {
        html += '<tr>';
        cfg.columns.forEach(function (column, index) {
          var key = column[0];
          var value = item[key];
          html += '<td class="' + (index === 1 ? 'cell-main' : '') + '">' + formatCell(collection, key, value) + '</td>';
        });

        html +=
          '<td><div class="actions-cell">' +
            '<button class="icon-button" title="Podgląd" onclick="openView(\'' + collection + '\',\'' + item.id + '\')">⌕</button>' +
            '<button class="icon-button" title="Edytuj" onclick="openEdit(\'' + collection + '\',\'' + item.id + '\')">✎</button>' +
            '<button class="icon-button" title="Drukuj" onclick="printRecord(\'' + collection + '\',\'' + item.id + '\')">▣</button>' +
          '</div></td></tr>';
      });
      body.innerHTML = html;
    }

    function formatDutyDuration(ms, compact) {
      var totalSeconds = Math.max(0, Math.floor(Number(ms || 0) / 1000));
      var hours = Math.floor(totalSeconds / 3600);
      var minutes = Math.floor((totalSeconds % 3600) / 60);
      var seconds = totalSeconds % 60;
      if (compact) {
        return String(hours).padStart(2, '0') + ':' +
          String(minutes).padStart(2, '0') + ':' +
          String(seconds).padStart(2, '0');
      }
      return hours + ' godz. ' + String(minutes).padStart(2, '0') + ' min';
    }

    function dutyEffectiveTotal(item) {
      var elapsed = item && item.active ? Math.max(0, Date.now() - state.dutyFetchedAt) : 0;
      return Math.max(0, Number(item && item.totalMs || 0)) + elapsed;
    }

    function dutyEffectiveSession(item) {
      var elapsed = item && item.active ? Math.max(0, Date.now() - state.dutyFetchedAt) : 0;
      return Math.max(0, Number(item && item.currentSessionMs || 0)) + elapsed;
    }

    function dutyAvatar(item) {
      if (item.avatar) {
        return '<span class="duty-avatar"><img src="' + escapeHtml(item.avatar) + '" alt=""></span>';
      }
      return '<span class="duty-avatar">' + escapeHtml((item.displayName || 'F').slice(0, 1).toUpperCase()) + '</span>';
    }

    function renderDutyView(data) {
      if (state.currentPage !== 'duty') return;
      var current = data.current || {};
      var leaderboard = data.leaderboard || [];
      var action = current.active
        ? '<button class="button danger duty-main-button" onclick="stopDuty()">■ Zakończ służbę</button>'
        : '<button class="button success duty-main-button" onclick="openDutyStart()">▶ Rozpocznij służbę</button>';

      var statusControl = '';
      if (current.active) {
        var patrolStatuses = ['Dostępny', 'Przydzielony', 'W drodze', 'Na miejscu', 'Transport', 'Pościg', 'Przerwa'];
        statusControl = '<div class="duty-status-control"><select id="patrolStatusSelect" class="form-control">' +
          patrolStatuses.map(function (status) {
            return '<option value="' + escapeHtml(status) + '"' + (current.patrolStatus === status ? ' selected' : '') + '>' + escapeHtml(status) + '</option>';
          }).join('') + '</select>' +
          '<button class="button" onclick="changePatrolStatus()">Ustaw status</button></div>';
      }

      var html = pageHeader(
        'Aktywna służba',
        'Uruchom patrol, ustaw callsign i aktualizuj status widoczny w dyspozytorni CAD.',
        '<button class="button ghost" onclick="renderDuty()">↻ Odśwież tabelę</button>' +
        '<button class="button" onclick="navigate(\'cad\')">⌖ Otwórz CAD</button>'
      );

      html +=
        '<div class="duty-grid">' +
          '<div class="duty-summary ' + (current.active ? 'active' : '') + '">' +
            '<div class="duty-summary-head">' + dutyAvatar(current) +
              '<div><span>Twój status</span><strong>' + escapeHtml(current.displayName || state.user.displayName || state.user.username) + '</strong></div>' +
            '</div>' +
            '<div class="duty-status-line"><span class="pulse-dot"></span>' +
              (current.active ? escapeHtml(current.callSign || 'Patrol') + ' · ' + escapeHtml(current.patrolStatus || 'Dostępny') : 'Poza służbą') +
            '</div>' +
            (current.active ? '<div class="duty-meta-grid">' +
              '<div class="duty-meta"><span>Callsign</span><strong>' + escapeHtml(current.callSign || '—') + '</strong></div>' +
              '<div class="duty-meta"><span>Rodzaj patrolu</span><strong>' + escapeHtml(current.unitType || 'Patrol') + '</strong></div>' +
              '<div class="duty-meta"><span>Radiowóz</span><strong>' + escapeHtml(current.vehicle || 'Nie przypisano') + '</strong></div>' +
              '<div class="duty-meta"><span>Kanał</span><strong>' + escapeHtml(current.radioChannel || 'Nie przypisano') + '</strong></div>' +
              '<div class="duty-meta" style="grid-column:1/-1"><span>Partner</span><strong>' + escapeHtml(current.partner || 'Patrol jednoosobowy') + '</strong></div>' +
            '</div>' : '') +
            '<div class="duty-time-label">Bieżąca zmiana</div>' +
            '<div id="currentDutySession" class="duty-time">' + formatDutyDuration(dutyEffectiveSession(current), true) + '</div>' +
            '<div class="duty-total-row"><span>Łączny czas</span><strong id="currentDutyTotal">' +
              escapeHtml(formatDutyDuration(dutyEffectiveTotal(current), false)) + '</strong></div>' +
            '<div class="duty-total-row"><span>Liczba zakończonych zmian</span><strong>' + Number(current.shiftCount || 0) + '</strong></div>' +
            statusControl + action +
          '</div>' +
          '<div class="panel duty-leaderboard">' +
            '<div class="panel-header"><div><h3>Ranking czasu służby</h3><span>Aktywne patrole są opisane callsignem i statusem</span></div>' +
              '<span class="badge blue">' + leaderboard.length + ' osób</span></div>' +
            '<div class="table-wrap duty-table-wrap"><table><thead><tr>' +
              '<th>#</th><th>Funkcjonariusz</th><th>Callsign</th><th>Status patrolu</th><th>Bieżąca zmiana</th><th>Łączny czas</th>' +
            '</tr></thead><tbody>' +
              (leaderboard.length ? leaderboard.map(function (item, index) {
                return '<tr>' +
                  '<td class="duty-rank">' + (index + 1) + '</td>' +
                  '<td><div class="duty-person">' + dutyAvatar(item) + '<div><strong>' + escapeHtml(item.displayName) +
                    '</strong><span>' + escapeHtml(item.unitType || item.userId) + '</span></div></div></td>' +
                  '<td class="cell-main">' + escapeHtml(item.active ? (item.callSign || '—') : '—') + '</td>' +
                  '<td>' + statusBadge(item.active ? item.patrolStatus : 'Poza służbą') + '</td>' +
                  '<td class="duty-session-value" data-user-id="' + escapeHtml(item.userId) + '">' +
                    escapeHtml(formatDutyDuration(dutyEffectiveSession(item), true)) + '</td>' +
                  '<td class="cell-main duty-total-value" data-user-id="' + escapeHtml(item.userId) + '">' +
                    escapeHtml(formatDutyDuration(dutyEffectiveTotal(item), false)) + '</td>' +
                '</tr>';
              }).join('') : '<tr><td colspan="6"><div class="empty-state"><p>Tabela jest jeszcze pusta.</p></div></td></tr>') +
            '</tbody></table></div>' +
          '</div>' +
        '</div>';

      document.getElementById('content').innerHTML = html;
    }

    function updateDutyClocks() {
      if (state.currentPage !== 'duty' || !state.dutyData) return;
      var current = state.dutyData.current || {};
      var currentSession = document.getElementById('currentDutySession');
      var currentTotal = document.getElementById('currentDutyTotal');
      if (currentSession) currentSession.textContent = formatDutyDuration(dutyEffectiveSession(current), true);
      if (currentTotal) currentTotal.textContent = formatDutyDuration(dutyEffectiveTotal(current), false);

      var leaderboard = state.dutyData.leaderboard || [];
      var oldOrder = leaderboard.map(function (item) { return String(item.userId); }).join('|');
      leaderboard.sort(function (a, b) {
        var difference = dutyEffectiveTotal(b) - dutyEffectiveTotal(a);
        if (difference !== 0) return difference;
        if (a.active !== b.active) return a.active ? -1 : 1;
        return String(a.displayName || '').localeCompare(String(b.displayName || ''), 'pl');
      });
      var newOrder = leaderboard.map(function (item) { return String(item.userId); }).join('|');
      if (newOrder !== oldOrder) {
        renderDutyView(state.dutyData);
        return;
      }

      leaderboard.forEach(function (item) {
        var sessionCell = document.querySelector('.duty-session-value[data-user-id="' + CSS.escape(String(item.userId)) + '"]');
        var totalCell = document.querySelector('.duty-total-value[data-user-id="' + CSS.escape(String(item.userId)) + '"]');
        if (sessionCell) sessionCell.textContent = formatDutyDuration(dutyEffectiveSession(item), true);
        if (totalCell) totalCell.textContent = formatDutyDuration(dutyEffectiveTotal(item), false);
      });
    }

    async function refreshDutyData() {
      var data = await api('/api/duty');
      if (state.currentPage !== 'duty') return;
      state.dutyData = data;
      state.dutyFetchedAt = Date.now();
      renderDutyView(data);
    }

    async function renderDuty() {
      if (state.dutyTimer) {
        clearInterval(state.dutyTimer);
        state.dutyTimer = null;
      }
      await refreshDutyData();
      state.dutyTick = 0;
      state.dutyTimer = setInterval(function () {
        if (state.currentPage !== 'duty') return;
        updateDutyClocks();
        state.dutyTick += 1;
        if (state.dutyTick % 10 === 0) {
          refreshDutyData().catch(function (error) { console.error(error); });
        }
      }, 1000);
    }

    function openDutyStart() {
      state.modalMode = 'duty-start';
      document.getElementById('modalTitle').textContent = 'Rozpoczęcie służby';
      document.getElementById('modalSubtitle').textContent = 'Dane patrolu będą widoczne w dyspozytorni CAD.';
      document.getElementById('modalBody').innerHTML =
        '<form id="dutyStartForm" class="form-grid">' +
          '<div class="form-group"><label>Callsign *</label><input class="form-control" name="callSign" required placeholder="np. KSP-21"></div>' +
          '<div class="form-group"><label>Rodzaj patrolu *</label><input class="form-control" name="unitType" required placeholder="np. patrol drogowy"></div>' +
          '<div class="form-group"><label>Radiowóz</label><input class="form-control" name="vehicle" placeholder="np. BMW 330i · KSP 021"></div>' +
          '<div class="form-group"><label>Kanał radiowy</label><input class="form-control" name="radioChannel" placeholder="np. TAC-1"></div>' +
          '<div class="form-group full"><label>Partner / skład patrolu</label><input class="form-control" name="partner" placeholder="Wpisz nazwę drugiego funkcjonariusza"></div>' +
        '</form>';
      document.getElementById('modalFooter').innerHTML =
        '<button class="button ghost" onclick="closeModal()">Anuluj</button>' +
        '<button class="button success" onclick="confirmDutyStart()">▶ Rozpocznij służbę</button>';
      openModal();
    }

    async function confirmDutyStart() {
      var form = document.getElementById('dutyStartForm');
      if (!form || !form.reportValidity()) return;
      var payload = {};
      new FormData(form).forEach(function (value, key) { payload[key] = value; });
      try {
        await api('/api/duty/start', { method: 'POST', body: JSON.stringify(payload) });
        closeModal();
        toast('Służba rozpoczęta', 'Patrol jest widoczny w CAD i czas jest naliczany.', 'success');
        await renderDuty();
      } catch (error) {
        toast('Nie udało się rozpocząć służby', error.message, 'error');
      }
    }

    async function changePatrolStatus() {
      var select = document.getElementById('patrolStatusSelect');
      if (!select) return;
      try {
        await api('/api/duty/status', { method: 'PATCH', body: JSON.stringify({ status: select.value }) });
        toast('Status zaktualizowany', 'Dyspozytornia widzi teraz status: ' + select.value + '.', 'success');
        await refreshDutyData();
      } catch (error) {
        toast('Nie udało się zmienić statusu', error.message, 'error');
      }
    }

    async function stopDuty() {
      if (!confirm('Zakończyć bieżącą służbę i zapisać przepracowany czas?')) return;
      try {
        await api('/api/duty/stop', { method: 'POST', body: '{}' });
        toast('Służba zakończona', 'Czas zmiany został dodany do łącznej liczby godzin.', 'success');
        await renderDuty();
      } catch (error) {
        toast('Nie udało się zakończyć służby', error.message, 'error');
      }
    }

    function cadUnitCard(unit) {
      return '<div class="cad-unit">' +
        '<div class="cad-unit-head"><div class="cad-unit-name"><strong>' + escapeHtml(unit.callSign || unit.displayName) + '</strong>' +
        '<span>' + escapeHtml(unit.displayName) + ' · ' + escapeHtml(unit.unitType || 'Patrol') + '</span></div>' +
        statusBadge(unit.patrolStatus) + '</div>' +
        '<div class="cad-unit-details">' +
          '<div class="cad-detail"><span>Radiowóz</span><strong>' + escapeHtml(unit.vehicle || 'Nie przypisano') + '</strong></div>' +
          '<div class="cad-detail"><span>Kanał</span><strong>' + escapeHtml(unit.radioChannel || 'Nie przypisano') + '</strong></div>' +
          '<div class="cad-detail"><span>Partner</span><strong>' + escapeHtml(unit.partner || 'Patrol jednoosobowy') + '</strong></div>' +
          '<div class="cad-detail"><span>Czas służby</span><strong>' + escapeHtml(formatDutyDuration(unit.currentSessionMs, false)) + '</strong></div>' +
        '</div></div>';
    }

    function cadCallCard(call, units) {
      var assignedIds = Array.isArray(call.assignedUnitIds) ? call.assignedUnitIds.map(String) : [];
      var assigned = units.filter(function (unit) { return assignedIds.includes(String(unit.userId)); });
      var available = units.filter(function (unit) { return !assignedIds.includes(String(unit.userId)); });
      var selectId = 'cadAssign' + String(call.id).replace(/[^a-zA-Z0-9_-]/g, '');
      var priorityClass = String(call.priority || '').slice(0, 2).toLowerCase();
      var assignedHtml = assigned.length
        ? assigned.map(function (unit) {
            return '<button class="button small ghost" onclick="unassignUnit(\'' + call.id + '\',\'' + unit.userId + '\')">' +
              escapeHtml(unit.callSign || unit.displayName) + ' ×</button>';
          }).join('')
        : '<span class="cell-muted">Nie przydzielono patrolu</span>';

      var assignOptions = '<option value="">Wybierz aktywną jednostkę</option>' + available.map(function (unit) {
        return '<option value="' + escapeHtml(unit.userId) + '">' + escapeHtml(unit.callSign || unit.displayName) + ' · ' + escapeHtml(unit.patrolStatus) + '</option>';
      }).join('');

      return '<div class="cad-call ' + escapeHtml(priorityClass) + '">' +
        '<div class="cad-call-head"><div class="cad-call-title"><strong>' + escapeHtml(call.callNo || call.id) + ' · ' + escapeHtml(call.category || 'Zdarzenie') + '</strong>' +
        '<span>' + escapeHtml(formatDate(call.createdAtCustom || call.createdAt, true)) + ' · ' + escapeHtml(call.caller || 'Zgłoszenie systemowe') + '</span></div>' +
        '<div style="display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end">' + statusBadge(call.priority) + statusBadge(call.status) + '</div></div>' +
        '<div class="cad-call-details">' +
          '<div class="cad-detail"><span>Lokalizacja</span><strong>' + escapeHtml(call.location || 'Nie podano') + '</strong></div>' +
          '<div class="cad-detail"><span>Przydzielone jednostki</span><strong>' + escapeHtml(call.units || 'Nie przydzielono') + '</strong></div>' +
        '</div>' +
        (call.description ? '<div class="cad-call-description">' + escapeHtml(call.description) + '</div>' : '') +
        '<div class="cad-status-buttons">' +
          '<button class="button ghost" onclick="setDispatchStatus(\'' + call.id + '\',\'Przyjęte\')">Przyjęte</button>' +
          '<button class="button ghost" onclick="setDispatchStatus(\'' + call.id + '\',\'Jednostka w drodze\')">W drodze</button>' +
          '<button class="button ghost" onclick="setDispatchStatus(\'' + call.id + '\',\'Na miejscu\')">Na miejscu</button>' +
          '<button class="button success" onclick="setDispatchStatus(\'' + call.id + '\',\'Zamknięte\')">Zamknij</button>' +
          '<button class="button danger" onclick="setDispatchStatus(\'' + call.id + '\',\'Anulowane\')">Anuluj</button>' +
          '<button class="button" onclick="openView(\'dispatch\',\'' + call.id + '\')">Szczegóły</button>' +
        '</div>' +
        '<div class="cad-actions"><select id="' + selectId + '" class="form-control">' + assignOptions + '</select>' +
          '<button class="button primary" onclick="assignUnit(\'' + call.id + '\',\'' + selectId + '\')">Przydziel</button>' +
          '<div style="display:flex;gap:5px;flex-wrap:wrap">' + assignedHtml + '</div></div>' +
      '</div>';
    }

    function renderCadView(data) {
      if (state.currentPage !== 'cad') return;
      var units = data.units || [];
      var calls = data.calls || [];
      var current = data.current || {};
      var stats = data.stats || {};

      var html = pageHeader(
        'CAD · centrum dyspozytorskie',
        'Aktywne patrole, statusy jednostek oraz przydzielanie zgłoszeń w czasie rzeczywistym.',
        '<button class="button primary" onclick="openCreate(\'dispatch\')">＋ Nowe zgłoszenie</button>' +
        '<button class="button ghost" onclick="refreshCad()">↻ Odśwież</button>'
      );

      html += '<div class="cad-current-banner"><div><strong>' +
        (current.active ? escapeHtml((current.callSign || current.displayName) + ' · ' + current.patrolStatus) : 'Nie jesteś obecnie na służbie') +
        '</strong><span>' + (current.active ? 'Twój patrol jest widoczny dla dyspozytora.' : 'Rozpocznij służbę, aby pojawić się na liście patroli.') +
        '</span></div><button class="button ' + (current.active ? 'ghost' : 'success') + '" onclick="navigate(\'duty\')">' +
        (current.active ? 'Zmień status' : 'Rozpocznij służbę') + '</button></div>';

      var cards = [
        ['Aktywne jednostki', stats.activeUnits || 0, '◉', '#3bd391', 'Patrole zalogowane do systemu'],
        ['Dostępne', stats.availableUnits || 0, '⌖', '#55e7ff', 'Gotowe do przydzielenia'],
        ['Zgłoszenia P1', stats.urgentCalls || 0, '!', '#ff5364', 'Najwyższy priorytet'],
        ['Otwarte zgłoszenia', stats.openCalls || 0, '☎', '#ffc857', 'Oczekujące i realizowane']
      ];
      html += '<div class="stats-grid">' + cards.map(function (card) {
        return '<div class="stat-card" style="--accent:' + card[3] + '"><div class="stat-top"><span>' + escapeHtml(card[0]) +
          '</span><span class="stat-icon">' + card[2] + '</span></div><div class="stat-value">' + Number(card[1]) +
          '</div><div class="stat-foot">' + escapeHtml(card[4]) + '</div></div>';
      }).join('') + '</div>';

      html += '<div class="cad-layout"><div class="cad-column"><div class="panel">' +
        '<div class="panel-header"><div><h3>Jednostki</h3><span>Patrole aktualnie na służbie</span></div><span class="badge blue">' + units.length + '</span></div>' +
        '<div class="panel-body"><div class="cad-column">' +
        (units.length ? units.map(cadUnitCard).join('') : '<div class="empty-state"><p>Nie ma aktywnych patroli.</p></div>') +
        '</div></div></div></div>' +
        '<div class="cad-column"><div class="panel"><div class="panel-header"><div><h3>Aktywne zgłoszenia</h3><span>Sortowanie według priorytetu i czasu przyjęcia</span></div>' +
        '<span class="badge blue">' + calls.length + '</span></div><div class="panel-body"><div class="cad-column">' +
        (calls.length ? calls.map(function (call) { return cadCallCard(call, units); }).join('') : '<div class="empty-state"><p>Nie ma otwartych zgłoszeń.</p></div>') +
        '</div></div></div></div></div>';

      document.getElementById('content').innerHTML = html;
    }

    async function refreshCad() {
      var data = await api('/api/cad');
      if (state.currentPage !== 'cad') return;
      state.cadData = data;
      renderCadView(data);
    }

    async function renderCad() {
      if (state.cadTimer) clearInterval(state.cadTimer);
      await refreshCad();
      state.cadTimer = setInterval(function () {
        if (state.currentPage === 'cad') refreshCad().catch(function (error) { console.error(error); });
      }, 5000);
    }

    async function assignUnit(callId, selectId) {
      var select = document.getElementById(selectId);
      if (!select || !select.value) {
        toast('Wybierz jednostkę', 'Wskaż aktywny patrol do przydzielenia.', 'error');
        return;
      }
      try {
        await api('/api/dispatch/' + encodeURIComponent(callId) + '/assign', {
          method: 'POST', body: JSON.stringify({ userId: select.value })
        });
        toast('Jednostka przydzielona', 'Patrol został przypisany do zgłoszenia.', 'success');
        await refreshCad();
      } catch (error) {
        toast('Nie udało się przydzielić jednostki', error.message, 'error');
      }
    }

    async function unassignUnit(callId, userId) {
      try {
        await api('/api/dispatch/' + encodeURIComponent(callId) + '/unassign', {
          method: 'POST', body: JSON.stringify({ userId: userId })
        });
        await refreshCad();
      } catch (error) {
        toast('Nie udało się odłączyć jednostki', error.message, 'error');
      }
    }

    async function setDispatchStatus(callId, status) {
      try {
        await api('/api/dispatch/' + encodeURIComponent(callId) + '/status', {
          method: 'POST', body: JSON.stringify({ status: status })
        });
        toast('Status zgłoszenia', 'Ustawiono: ' + status + '.', 'success');
        await refreshCad();
      } catch (error) {
        toast('Nie udało się zmienić statusu', error.message, 'error');
      }
    }

    async function renderAudit() {
      var response = await api('/api/audit?limit=500');
      var items = response.items || [];

      var html = pageHeader(
        'Dziennik operacji',
        'Niezmienny ślad tworzenia, edycji, usuwania i eksportowania danych.',
        '<a class="button" href="/api/export">⇩ Eksport kopii bazy</a>'
      );

      html +=
        '<div class="table-toolbar">' +
          '<input id="auditSearch" class="table-search" placeholder="Szukaj po użytkowniku, akcji lub rekordzie...">' +
          '<span class="badge blue">' + items.length + ' wpisów</span>' +
        '</div>' +
        '<div class="table-wrap"><table><thead><tr>' +
          '<th>Data</th><th>Użytkownik</th><th>Akcja</th><th>Moduł</th><th>Rekord</th><th>Szczegóły</th>' +
        '</tr></thead><tbody id="auditBody"></tbody></table></div>';

      document.getElementById('content').innerHTML = html;

      function draw(list) {
        var body = document.getElementById('auditBody');
        if (!list.length) {
          body.innerHTML = '<tr><td colspan="6"><div class="empty-state"><p>Brak wpisów.</p></div></td></tr>';
          return;
        }
        body.innerHTML = list.map(function (item) {
          return (
            '<tr>' +
              '<td>' + escapeHtml(formatDate(item.timestamp, true)) + '</td>' +
              '<td class="cell-main">' + escapeHtml(item.actorName || 'System') + '</td>' +
              '<td>' + statusBadge(item.action) + '</td>' +
              '<td>' + escapeHtml(collectionLabels[item.collection] || item.collection || 'System') + '</td>' +
              '<td>' + escapeHtml(item.recordId || '—') + '</td>' +
              '<td class="cell-muted">' + escapeHtml(item.details || '—') + '</td>' +
            '</tr>'
          );
        }).join('');
      }

      draw(items);

      document.getElementById('auditSearch').addEventListener('input', function (event) {
        var query = event.target.value.toLowerCase().trim();
        draw(items.filter(function (item) {
          return Object.values(item).join(' ').toLowerCase().includes(query);
        }));
      });
    }

    function renderSettings() {
      var html = pageHeader(
        'Ustawienia City OS',
        'Informacje o sesji, integracjach, bezpieczeństwie oraz kopiach zapasowych.',
        ''
      );

      html +=
        '<div class="settings-grid">' +
          '<div class="settings-card">' +
            '<h3>Kopia zapasowa</h3>' +
            '<p>Pobierz pełną bazę danych wraz z dziennikiem operacji. Plik można bezpiecznie przechowywać poza serwerem.</p>' +
            '<a class="button primary" href="/api/export">⇩ Pobierz kopię JSON</a>' +
          '</div>' +
          '<div class="settings-card">' +
            '<h3>Sesja Discord</h3>' +
            '<p>Zalogowano jako <strong>' + escapeHtml(state.user.displayName || state.user.username) +
            '</strong>. Dostęp jest weryfikowany na podstawie roli Discord przy logowaniu.</p>' +
            '<a class="button danger" href="/auth/logout">Wyloguj z terminala</a>' +
          '</div>' +
          '<div class="settings-card">' +
            '<h3>Przechowywanie danych</h3>' +
            '<p>Rekordy są zapisywane na serwerze w lokalnej bazie JSON. Do większego wdrożenia warto później podłączyć PostgreSQL lub SQLite.</p>' +
          '</div>' +
          '<div class="settings-card">' +
            '<h3>Nieoficjalny system RP</h3>' +
            '<p>System jest nieoficjalnym projektem roleplay dla ER:LC i nie jest powiązany z prawdziwymi służbami ani instytucjami. Nie umieszczaj w nim prawdziwych danych osobowych.</p>' +
          '</div>' +
        '</div>';

      document.getElementById('content').innerHTML = html;
    }

    function buildInput(field, record) {
      var value = record && record[field.key] !== undefined ? record[field.key] : '';

      if (field.key === 'officer' && !value && state.user) {
        value = state.user.displayName || state.user.username;
      }

      if ((field.key === 'date' || field.key === 'startDate' || field.key === 'createdAtCustom') && !value) {
        value = new Date().toISOString();
      }

      var required = field.required ? ' required' : '';
      var placeholder = field.placeholder ? ' placeholder="' + escapeHtml(field.placeholder) + '"' : '';

      if (field.type === 'textarea') {
        return '<textarea class="form-control" name="' + field.key + '"' + required + placeholder + '>' +
          escapeHtml(value) + '</textarea>';
      }

      if (field.type === 'select') {
        var options = '<option value="">— wybierz —</option>';
        (field.options || []).forEach(function (option) {
          options += '<option value="' + escapeHtml(option) + '"' +
            (String(value) === String(option) ? ' selected' : '') + '>' +
            escapeHtml(option) + '</option>';
        });
        return '<select class="form-control" name="' + field.key + '"' + required + '>' + options + '</select>';
      }

      if (field.type === 'citizen' || field.type === 'vehicle') {
        var relationPlaceholder = field.type === 'citizen'
          ? 'Wpisz ID albo imię i nazwisko osoby'
          : 'Wpisz ID albo numer rejestracyjny pojazdu';
        return '<input class="form-control" type="text" name="' + field.key + '" value="' +
          escapeHtml(value) + '"' + required + ' placeholder="' + relationPlaceholder + '">';
      }

      var type = field.type || 'text';
      var inputValue = type === 'datetime-local' ? toLocalInputDate(value) : value;
      return '<input class="form-control" type="' + type + '" name="' + field.key + '" value="' +
        escapeHtml(inputValue) + '"' + required + placeholder + '>';
    }

    async function openCreate(collection) {
      await loadLookups();
      var cfg = pageConfig[collection];
      state.modalMode = 'create';
      state.currentRecord = null;

      document.getElementById('modalTitle').textContent = 'Nowy rekord · ' + cfg.title;
      document.getElementById('modalSubtitle').textContent = 'Wypełnij formularz i zapisz wpis w terminalu.';

      var html = '<form id="recordForm" class="form-grid">';
      cfg.fields.forEach(function (field) {
        html +=
          '<div class="form-group ' + (field.full ? 'full' : '') + '">' +
            '<label>' + escapeHtml(field.label) + (field.required ? ' *' : '') + '</label>' +
            buildInput(field, null) +
          '</div>';
      });
      html += '</form>';

      document.getElementById('modalBody').innerHTML = html;
      document.getElementById('modalFooter').innerHTML =
        '<button class="button ghost" onclick="closeModal()">Anuluj</button>' +
        '<button class="button primary" onclick="saveRecord(\'' + collection + '\')">Zapisz rekord</button>';

      openModal();
    }

    async function openEdit(collection, id) {
      await loadLookups();
      var response = await api('/api/' + collection + '/' + encodeURIComponent(id));
      var record = response.item;
      var cfg = pageConfig[collection];

      state.modalMode = 'edit';
      state.currentRecord = record;

      document.getElementById('modalTitle').textContent = 'Edycja · ' + getRecordTitle(collection, record);
      document.getElementById('modalSubtitle').textContent = record.id;

      var html = '<form id="recordForm" class="form-grid">';
      cfg.fields.forEach(function (field) {
        html +=
          '<div class="form-group ' + (field.full ? 'full' : '') + '">' +
            '<label>' + escapeHtml(field.label) + (field.required ? ' *' : '') + '</label>' +
            buildInput(field, record) +
          '</div>';
      });
      html += '</form>';

      document.getElementById('modalBody').innerHTML = html;
      document.getElementById('modalFooter').innerHTML =
        '<button class="button danger" onclick="deleteRecord(\'' + collection + '\',\'' + record.id + '\')">Usuń</button>' +
        '<button class="button ghost" onclick="closeModal()">Anuluj</button>' +
        '<button class="button primary" onclick="saveRecord(\'' + collection + '\',\'' + record.id + '\')">Zapisz zmiany</button>';

      openModal();
    }

    async function openView(collection, id) {
      var response = await api('/api/' + collection + '/' + encodeURIComponent(id));
      var record = response.item;
      var cfg = pageConfig[collection];
      state.currentRecord = record;
      state.modalMode = 'view';

      document.getElementById('modalTitle').textContent = getRecordTitle(collection, record);
      document.getElementById('modalSubtitle').textContent =
        (collectionLabels[collection] || collection) + ' · ' + record.id;

      var keys = [];
      cfg.fields.forEach(function (field) { keys.push(field.key); });
      ['id', 'caseNo', 'callNo', 'createdAt', 'updatedAt', 'createdBy', 'updatedBy'].forEach(function (key) {
        if (record[key] !== undefined && !keys.includes(key)) keys.push(key);
      });

      var html = '<div class="detail-grid">';
      keys.forEach(function (key) {
        var value = record[key];
        if (value === undefined || value === null || value === '') return;

        var label = (fieldLabels[collection] && fieldLabels[collection][key]) || key;
        if (key === 'citizenId' || key === 'ownerId') value = findCitizenName(value);
        if (key === 'vehicleId') value = findVehicleName(value);
        if (/date|At$/i.test(key)) value = formatDate(value, true);

        var full = String(value).length > 90 || ['notes', 'details', 'description', 'summary', 'articles', 'items'].includes(key);

        html +=
          '<div class="detail ' + (full ? 'full' : '') + '">' +
            '<span class="detail-label">' + escapeHtml(label) + '</span>' +
            '<div class="detail-value">' + escapeHtml(value) + '</div>' +
          '</div>';
      });
      html += '</div>';

      if (collection === 'dispatch' && Array.isArray(record.history) && record.history.length) {
        html += '<div class="panel" style="margin-top:14px"><div class="panel-header"><div><h3>Historia zgłoszenia</h3>' +
          '<span>Zmiany statusu i przydziały jednostek</span></div></div><div class="panel-body"><div class="list">' +
          record.history.map(function (entry) {
            return '<div class="list-item"><div class="list-item-main"><strong>' + escapeHtml(entry.action || 'Operacja') +
              '</strong><span>' + escapeHtml(entry.details || '') + ' · ' + escapeHtml(entry.actorName || 'System') +
              ' · ' + escapeHtml(formatDate(entry.timestamp, true)) + '</span></div></div>';
          }).join('') + '</div></div></div>';
      }

      document.getElementById('modalBody').innerHTML = html;
      document.getElementById('modalFooter').innerHTML =
        '<button class="button" onclick="printRecord(\'' + collection + '\',\'' + record.id + '\')">▣ Drukuj</button>' +
        '<button class="button ghost" onclick="closeModal()">Zamknij</button>' +
        '<button class="button primary" onclick="openEdit(\'' + collection + '\',\'' + record.id + '\')">✎ Edytuj</button>';

      openModal();
    }

    function openModal() {
      document.getElementById('modalBackdrop').classList.add('open');
      document.body.style.overflow = 'hidden';
    }

    function closeModal() {
      document.getElementById('modalBackdrop').classList.remove('open');
      document.body.style.overflow = '';
      state.currentRecord = null;
      state.modalMode = null;
    }

    async function saveRecord(collection, id) {
      var form = document.getElementById('recordForm');
      if (!form) return;

      if (!form.reportValidity()) {
        toast('Uzupełnij dane', 'Wypełnij wszystkie wymagane pola.', 'error');
        return;
      }

      var formData = new FormData(form);
      var payload = {};
      formData.forEach(function (value, key) {
        var field = pageConfig[collection].fields.find(function (item) { return item.key === key; });
        if (field && field.type === 'number') {
          payload[key] = value === '' ? '' : Number(value);
        } else if (field && field.type === 'datetime-local' && value) {
          payload[key] = new Date(value).toISOString();
        } else {
          payload[key] = value;
        }
      });

      try {
        var response = await api(
          id ? '/api/' + collection + '/' + encodeURIComponent(id) : '/api/' + collection,
          {
            method: id ? 'PUT' : 'POST',
            body: JSON.stringify(payload)
          }
        );

        toast('Zapisano', id ? 'Rekord został zaktualizowany.' : 'Utworzono nowy rekord.', 'success');
        closeModal();
        await loadLookups();
        await navigate(state.currentPage === 'dashboard' ? 'dashboard' : (state.currentPage === 'cad' ? 'cad' : collection));
        return response.item;
      } catch (error) {
        toast('Nie udało się zapisać', error.message, 'error');
      }
    }

    async function deleteRecord(collection, id) {
      if (!confirm('Czy na pewno chcesz trwale usunąć ten rekord? Operacja zostanie zapisana w dzienniku.')) return;

      try {
        await api('/api/' + collection + '/' + encodeURIComponent(id), { method: 'DELETE' });
        toast('Usunięto', 'Rekord został usunięty.', 'success');
        closeModal();
        await loadLookups();
        await navigate(collection);
      } catch (error) {
        toast('Nie udało się usunąć', error.message, 'error');
      }
    }

    async function printRecord(collection, id) {
      try {
        var response = await api('/api/' + collection + '/' + encodeURIComponent(id));
        var record = response.item;
        var cfg = pageConfig[collection];
        var title = getRecordTitle(collection, record);
        var rows = '';

        Object.keys(record).forEach(function (key) {
          if (['createdById', 'updatedById'].includes(key)) return;
          var value = record[key];
          if (value === undefined || value === null || value === '') return;
          if (key === 'citizenId' || key === 'ownerId') value = findCitizenName(value);
          if (key === 'vehicleId') value = findVehicleName(value);
          if (/date|At$/i.test(key)) value = formatDate(value, true);
          var label = (fieldLabels[collection] && fieldLabels[collection][key]) || key;

          rows +=
            '<div class="row"><div class="label">' + escapeHtml(label) + '</div>' +
            '<div class="value">' + escapeHtml(value) + '</div></div>';
        });

        var popup = window.open('', '_blank', 'width=900,height=800');
        if (!popup) {
          toast('Drukowanie', 'Przeglądarka zablokowała nowe okno.', 'error');
          return;
        }

        popup.document.write(
          '<!doctype html><html lang="pl"><head><meta charset="utf-8"><title>' +
          escapeHtml(title) +
          '</title><style>' +
          'body{font-family:Arial,sans-serif;color:#111;margin:35px}.head{border-bottom:3px solid #163f70;padding-bottom:15px;margin-bottom:22px}' +
          'h1{margin:0;font-size:25px}.sub{color:#555;margin-top:7px}.row{display:grid;grid-template-columns:220px 1fr;border-bottom:1px solid #ddd;padding:10px 0}' +
          '.label{font-size:11px;text-transform:uppercase;font-weight:bold;color:#536477}.value{white-space:pre-wrap;line-height:1.5}' +
          '.footer{margin-top:35px;color:#777;font-size:10px;text-align:center}@media print{body{margin:12mm}}' +
          '</style></head><body><div class="head"><h1>Liberty Operations · KSP · ' + escapeHtml(title) + '</h1>' +
          '<div class="sub">' + escapeHtml(cfg.title) + ' · ' + escapeHtml(record.id) + '</div></div>' +
          rows +
          '<div class="footer">Wydruk wygenerowany ' + escapeHtml(formatDate(new Date().toISOString(), true)) +
          ' przez ' + escapeHtml(state.user.displayName || state.user.username) + '</div>' +
          '<script>window.onload=function(){window.print()}<\/script></body></html>'
        );
        popup.document.close();
      } catch (error) {
        toast('Drukowanie', error.message, 'error');
      }
    }

    function exportCsv(collection) {
      var cfg = pageConfig[collection];
      var items = state.currentItems || [];
      if (!items.length) {
        toast('Eksport CSV', 'Brak rekordów do wyeksportowania.', 'error');
        return;
      }

      var keys = Array.from(new Set(items.flatMap(function (item) { return Object.keys(item); })));
      var rows = [keys.map(csvEscape).join(';')];

      items.forEach(function (item) {
        rows.push(keys.map(function (key) {
          var value = item[key];
          if (key === 'citizenId' || key === 'ownerId') value = findCitizenName(value);
          if (key === 'vehicleId') value = findVehicleName(value);
          return csvEscape(value);
        }).join(';'));
      });

      var blob = new Blob(['\ufeff' + rows.join('\n')], { type: 'text/csv;charset=utf-8' });
      var url = URL.createObjectURL(blob);
      var link = document.createElement('a');
      link.href = url;
      link.download = 'ksp-' + collection + '-' + new Date().toISOString().slice(0,10) + '.csv';
      link.click();
      URL.revokeObjectURL(url);
      toast('Eksport CSV', 'Pobrano ' + items.length + ' rekordów z modułu ' + cfg.title + '.', 'success');
    }

    function csvEscape(value) {
      var text = value === null || value === undefined ? '' : String(value);
      return '"' + text.replace(/"/g, '""') + '"';
    }

    async function globalSearch(query) {
      var resultsBox = document.getElementById('searchResults');
      if (query.trim().length < 2) {
        resultsBox.classList.remove('open');
        resultsBox.innerHTML = '';
        return;
      }

      try {
        var response = await api('/api/search?q=' + encodeURIComponent(query.trim()));
        var results = response.results || [];

        if (!results.length) {
          resultsBox.innerHTML = '<div class="empty-state" style="padding:25px 10px"><p>Brak wyników.</p></div>';
        } else {
          resultsBox.innerHTML = results.map(function (item) {
            return (
              '<button class="search-result" onclick="openSearchResult(\'' +
              item.collection + '\',\'' + item.id + '\')">' +
                '<span class="search-result-tag">' + escapeHtml(item.collectionLabel) + '</span>' +
                '<span><strong>' + escapeHtml(item.title) + '</strong><span>' +
                escapeHtml(item.subtitle || item.id) + '</span></span>' +
              '</button>'
            );
          }).join('');
        }
        resultsBox.classList.add('open');
      } catch (error) {
        console.error(error);
      }
    }

    async function openSearchResult(collection, id) {
      document.getElementById('searchResults').classList.remove('open');
      document.getElementById('globalSearch').value = '';
      await openView(collection, id);
    }

    function showAuthError() {
      var params = new URLSearchParams(location.search);
      var error = params.get('authError');
      if (!error) return;
      var box = document.getElementById('loginError');
      box.textContent = error.replace(/_/g, ' ');
      box.classList.remove('hidden');
      history.replaceState({}, '', '/');
    }

    function bindEvents() {
      document.getElementById('navigation').addEventListener('click', function (event) {
        var button = event.target.closest('.nav-button');
        if (!button) return;
        navigate(button.dataset.page);
      });

      document.getElementById('mobileMenu').addEventListener('click', function () {
        document.getElementById('sidebar').classList.toggle('open');
      });

      document.getElementById('modalClose').addEventListener('click', closeModal);
      document.getElementById('modalBackdrop').addEventListener('click', function (event) {
        if (event.target.id === 'modalBackdrop') closeModal();
      });

      document.addEventListener('keydown', function (event) {
        if (event.key === 'Escape') {
          closeModal();
          document.getElementById('searchResults').classList.remove('open');
        }
        if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
          event.preventDefault();
          document.getElementById('globalSearch').focus();
        }
      });

      var search = document.getElementById('globalSearch');
      search.addEventListener('input', function (event) {
        clearTimeout(state.searchTimer);
        state.searchTimer = setTimeout(function () {
          globalSearch(event.target.value);
        }, 280);
      });

      document.addEventListener('click', function (event) {
        if (!event.target.closest('.global-search-wrap')) {
          document.getElementById('searchResults').classList.remove('open');
        }
      });
    }

    async function init() {
      showAuthError();
      bindEvents();
      setClock();
      setInterval(setClock, 1000);

      try {
        var response = await api('/api/me');
        setUser(response.user);
        showApp();
        await loadLookups();
        await navigate('dashboard');
      } catch (error) {
        showLogin();
      }
    }

    window.navigate = navigate;
    window.openCreate = openCreate;
    window.openEdit = openEdit;
    window.openView = openView;
    window.closeModal = closeModal;
    window.saveRecord = saveRecord;
    window.deleteRecord = deleteRecord;
    window.printRecord = printRecord;
    window.exportCsv = exportCsv;
    window.openSearchResult = openSearchResult;
    window.renderDuty = renderDuty;
    window.openDutyStart = openDutyStart;
    window.confirmDutyStart = confirmDutyStart;
    window.changePatrolStatus = changePatrolStatus;
    window.stopDuty = stopDuty;
    window.renderCad = renderCad;
    window.refreshCad = refreshCad;
    window.assignUnit = assignUnit;
    window.unassignUnit = unassignUnit;
    window.setDispatchStatus = setDispatchStatus;

    init();
  </script>
</body>
</html>`;

app.get('/health', (req, res) => {
  res.json({ ok: true, service: 'Liberty Operations Center V3 Preview', time: new Date().toISOString() });
});

app.get('/', (req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(HTML);
});

app.use((error, req, res, next) => {
  console.error('[SERVER]', error);
  if (res.headersSent) return next(error);

  if (req.path.startsWith('/api/')) {
    return res.status(500).json({ error: 'Wewnętrzny błąd serwera.' });
  }
  res.status(500).send('Wewnętrzny błąd serwera.');
});

app.listen(PORT, () => {
  console.log('');
  console.log('===============================================================');
  console.log(' LIBERTY OPERATIONS CENTER — V3 Preview uruchomiony');
  console.log(` Adres: ${BASE_URL}`);
  console.log(` Callback Discord: ${BASE_URL}/auth/callback`);
  console.log(` Guild ID: ${DISCORD_GUILD_ID}`);
  console.log(` Role gate: ${DISCORD_REQUIRE_ROLE ? `ON (${DISCORD_ROLE_ID})` : 'OFF — tylko członkostwo Discord'}`);
  console.log(` Preview login: ${PREVIEW_LOGIN_ENABLED ? 'ON — tylko odczyt' : 'OFF'}`);
  console.log(` Baza: ${DB_FILE}`);
  console.log('===============================================================');
  console.log('');
});
