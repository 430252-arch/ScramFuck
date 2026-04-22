const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const http = require('http');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'scramfuck-secret-change-in-prod';
const DATA_DIR = process.env.DATA_DIR || './data';
const FRONTEND_URL = process.env.FRONTEND_URL || '*';

// Data dir setup
[DATA_DIR, path.join(DATA_DIR, 'uploads')].forEach(d => {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
});

const DB_FILE = path.join(DATA_DIR, 'db.json');

function readDB() {
  if (!fs.existsSync(DB_FILE)) {
    return {
      users: {},
      chat: { global: [], off_topic: [], games: [] },
      online: {},
      meta: { userCount: 0 }
    };
  }
  try {
    return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  } catch {
    return { users: {}, chat: { global: [], off_topic: [], games: [] }, online: {}, meta: { userCount: 0 } };
  }
}

function writeDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db), 'utf8');
}

// Multer - store uploads with original extension hint
const upload = multer({
  dest: path.join(DATA_DIR, 'uploads'),
  limits: { fileSize: 8 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    cb(null, allowed.includes(file.mimetype));
  }
});

// CORS - allow frontend origin
app.use(cors({
  origin: FRONTEND_URL === '*' ? true : FRONTEND_URL.split(',').map(s => s.trim()),
  credentials: true
}));
app.use(express.json({ limit: '2mb' }));
app.use('/uploads', express.static(path.join(DATA_DIR, 'uploads')));

// Auth middleware
function auth(req, res, next) {
  const h = req.headers.authorization || (req.query.token ? 'Bearer ' + req.query.token : null);
  if (!h) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(h.replace('Bearer ', ''), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ── SSE clients ──────────────────────────────────────────────────────────────
const clients = {}; // uid → [res, ...]

app.get('/stream', auth, (req, res) => {
  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no'
  });
  res.flushHeaders();

  const uid = req.user.uid;
  if (!clients[uid]) clients[uid] = [];
  clients[uid].push(res);

  const db = readDB();
  db.online[uid] = { uid, ts: Date.now() };
  writeDB(db);
  broadcastOnlineCount();

  // Heartbeat to keep connection alive
  const hb = setInterval(() => {
    try { res.write(': heartbeat\n\n'); } catch { clearInterval(hb); }
  }, 25000);

  req.on('close', () => {
    clearInterval(hb);
    clients[uid] = (clients[uid] || []).filter(r => r !== res);
    const db2 = readDB();
    delete db2.online[uid];
    writeDB(db2);
    broadcastOnlineCount();
  });

  res.write(`data: ${JSON.stringify({ type: 'connected', uid })}\n\n`);
});

function broadcast(type, data, excludeUid) {
  const msg = `data: ${JSON.stringify({ type, data })}\n\n`;
  Object.entries(clients).forEach(([uid, rs]) => {
    if (uid === excludeUid) return;
    rs.forEach(r => { try { r.write(msg); } catch {} });
  });
}

function broadcastAll(type, data) {
  broadcast(type, data);
}

function broadcastOnlineCount() {
  const count = Object.values(clients).filter(rs => rs.length > 0).length;
  broadcastAll('online', { count });
}

// ── Health ───────────────────────────────────────────────────────────────────
app.get('/health', (_, res) => res.json({ status: 'ok', time: Date.now() }));

// ── Auth ─────────────────────────────────────────────────────────────────────
app.post('/auth/register', async (req, res) => {
  const { email, password, username } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be 6+ characters' });

  const db = readDB();
  if (Object.values(db.users).find(u => u.email === email.toLowerCase())) {
    return res.status(409).json({ error: 'Email already registered' });
  }

  const uid = 'u_' + Date.now() + '_' + Math.random().toString(36).slice(2);
  db.meta.userCount = (db.meta.userCount || 0) + 1;
  const hash = await bcrypt.hash(password, 10);
  const safeUsername = (username || email.split('@')[0]).slice(0, 32).replace(/[<>]/g, '');

  db.users[uid] = {
    uid,
    email: email.toLowerCase(),
    password: hash,
    username: safeUsername,
    bio: '',
    avatarUrl: '',
    bannerUrl: '',
    status: 'active',
    badges: {},
    userIndex: db.meta.userCount,
    createdAt: Date.now(),
    lastSeen: Date.now()
  };
  writeDB(db);

  const token = jwt.sign({ uid, email: email.toLowerCase() }, JWT_SECRET, { expiresIn: '30d' });
  const { password: _, ...user } = db.users[uid];
  res.json({ token, user });
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' });

  const db = readDB();
  const entry = Object.entries(db.users).find(([, u]) => u.email === email.toLowerCase());
  if (!entry) return res.status(401).json({ error: 'Invalid credentials' });

  const [uid, user] = entry;
  if (!await bcrypt.compare(password, user.password)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  db.users[uid].lastSeen = Date.now();
  writeDB(db);

  const token = jwt.sign({ uid, email: email.toLowerCase() }, JWT_SECRET, { expiresIn: '30d' });
  const { password: _, ...safeUser } = db.users[uid];
  res.json({ token, user: safeUser });
});

app.post('/auth/logout', auth, (req, res) => {
  const db = readDB();
  if (db.users[req.user.uid]) {
    db.users[req.user.uid].lastSeen = Date.now();
    writeDB(db);
  }
  res.json({ ok: true });
});

app.get('/auth/me', auth, (req, res) => {
  const db = readDB();
  const user = db.users[req.user.uid];
  if (!user) return res.status(404).json({ error: 'Not found' });
  const { password: _, ...safe } = user;
  res.json(safe);
});

// ── Users ────────────────────────────────────────────────────────────────────
app.get('/users', auth, (req, res) => {
  const db = readDB();
  const users = Object.values(db.users)
    .map(({ password: _, ...u }) => u)
    .sort((a, b) => (a.userIndex || 0) - (b.userIndex || 0));
  res.json(users);
});

app.get('/users/search', auth, (req, res) => {
  const q = (req.query.q || '').toLowerCase();
  const db = readDB();
  const results = Object.values(db.users)
    .filter(u => (u.username || '').toLowerCase().includes(q))
    .map(({ password: _, ...u }) => u)
    .slice(0, 10);
  res.json(results);
});

app.get('/users/:uid', auth, (req, res) => {
  const db = readDB();
  const user = db.users[req.params.uid];
  if (!user) return res.status(404).json({ error: 'Not found' });
  const { password: _, ...safe } = user;
  res.json(safe);
});

app.patch('/users/me', auth, (req, res) => {
  const db = readDB();
  if (!db.users[req.user.uid]) return res.status(404).json({ error: 'Not found' });
  const allowed = ['username', 'bio', 'avatarUrl', 'bannerUrl'];
  allowed.forEach(k => {
    if (req.body[k] !== undefined) {
      db.users[req.user.uid][k] = String(req.body[k]).slice(0, k === 'bio' ? 300 : 200).replace(/[<>]/g, '');
    }
  });
  db.users[req.user.uid].updatedAt = Date.now();
  writeDB(db);
  const { password: _, ...safe } = db.users[req.user.uid];
  // Notify others of profile update
  broadcastAll('userUpdate', { uid: req.user.uid, username: safe.username, avatarUrl: safe.avatarUrl });
  res.json(safe);
});

app.post('/users/me/avatar', auth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file or invalid type' });
  const host = process.env.BACKEND_URL || `${req.protocol}://${req.get('host')}`;
  const url = `${host}/uploads/${req.file.filename}`;
  const db = readDB();
  if (db.users[req.user.uid]) {
    db.users[req.user.uid].avatarUrl = url;
    writeDB(db);
  }
  res.json({ url });
});

app.post('/users/me/banner', auth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file or invalid type' });
  const host = process.env.BACKEND_URL || `${req.protocol}://${req.get('host')}`;
  const url = `${host}/uploads/${req.file.filename}`;
  const db = readDB();
  if (db.users[req.user.uid]) {
    db.users[req.user.uid].bannerUrl = url;
    writeDB(db);
  }
  res.json({ url });
});

// ── Chat ─────────────────────────────────────────────────────────────────────
const VALID_ROOMS = ['global', 'off_topic', 'games'];

app.get('/chat/:room', auth, (req, res) => {
  if (!VALID_ROOMS.includes(req.params.room)) return res.status(400).json({ error: 'Invalid room' });
  const db = readDB();
  const msgs = (db.chat[req.params.room] || []).slice(-100);
  res.json(msgs);
});

app.post('/chat/:room', auth, (req, res) => {
  if (!VALID_ROOMS.includes(req.params.room)) return res.status(400).json({ error: 'Invalid room' });
  const { text } = req.body;
  if (!text || !text.trim()) return res.status(400).json({ error: 'No text' });

  const db = readDB();
  const user = db.users[req.user.uid];
  if (!user) return res.status(403).json({ error: 'User not found' });

  const clean = String(text).slice(0, 500).replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const msg = {
    key: 'm_' + Date.now() + '_' + Math.random().toString(36).slice(2),
    uid: req.user.uid,
    username: user.username || 'Anonymous',
    avatarUrl: user.avatarUrl || '',
    badges: user.badges || {},
    text: clean,
    ts: Date.now()
  };

  if (!db.chat[req.params.room]) db.chat[req.params.room] = [];
  db.chat[req.params.room].push(msg);
  if (db.chat[req.params.room].length > 500) {
    db.chat[req.params.room] = db.chat[req.params.room].slice(-500);
  }

  db.users[req.user.uid].lastSeen = Date.now();
  writeDB(db);

  broadcastAll('message', { room: req.params.room, msg });
  res.json(msg);
});

app.delete('/chat/:room/:key', auth, (req, res) => {
  if (!VALID_ROOMS.includes(req.params.room)) return res.status(400).json({ error: 'Invalid room' });
  const db = readDB();
  if (!db.chat[req.params.room]) return res.status(404).json({ error: 'Room not found' });

  const idx = db.chat[req.params.room].findIndex(
    m => m.key === req.params.key && m.uid === req.user.uid
  );
  if (idx === -1) return res.status(403).json({ error: 'Not your message' });

  db.chat[req.params.room].splice(idx, 1);
  writeDB(db);
  broadcastAll('delete', { room: req.params.room, key: req.params.key });
  res.json({ ok: true });
});

// ── Online count ─────────────────────────────────────────────────────────────
app.get('/online', auth, (req, res) => {
  const count = Object.values(clients).filter(rs => rs.length > 0).length;
  res.json({ count });
});

// ── Proxy ─────────────────────────────────────────────────────────────────────
// ScramFuck/FckScramjet - advanced proxy with URL rewriting
app.get('/proxy', async (req, res) => {
  const url = req.query.url;
  if (!url) return res.status(400).json({ error: 'Missing url' });

  // Basic URL validation
  let parsedUrl;
  try {
    parsedUrl = new URL(url);
    if (!['http:', 'https:'].includes(parsedUrl.protocol)) throw new Error('Bad protocol');
  } catch {
    return res.status(400).json({ error: 'Invalid URL' });
  }

  try {
    const fetch = (await import('node-fetch')).default;
    const backendBase = process.env.BACKEND_URL || `${req.protocol}://${req.get('host')}`;

    const response = await fetch(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'identity', // avoid compressed responses we can't easily decode
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Cache-Control': 'max-age=0',
        'Referer': parsedUrl.origin
      },
      redirect: 'follow',
      size: 10 * 1024 * 1024 // 10MB limit
    });

    const contentType = response.headers.get('content-type') || 'text/html';

    // Strip security headers
    const skipHeaders = new Set([
      'content-security-policy', 'x-frame-options', 'x-xss-protection',
      'strict-transport-security', 'content-encoding', 'transfer-encoding'
    ]);
    response.headers.forEach((val, key) => {
      if (!skipHeaders.has(key.toLowerCase())) {
        try { res.set(key, val); } catch {}
      }
    });
    res.set('Content-Type', contentType);
    res.set('Access-Control-Allow-Origin', '*');

    if (contentType.includes('text/html')) {
      let html = await response.text();
      const origin = parsedUrl.origin;
      const proxyBase = `${backendBase}/proxy?url=`;

      // Remove CSP meta tags
      html = html.replace(/<meta[^>]*http-equiv=["']Content-Security-Policy["'][^>]*>/gi, '');
      html = html.replace(/<meta[^>]*http-equiv=["']X-Frame-Options["'][^>]*>/gi, '');

      // Inject proxy base + script interceptors
      const injectScript = `
<script>
(function() {
  const PROXY = ${JSON.stringify(proxyBase)};
  const ORIGIN = ${JSON.stringify(origin)};
  const PAGE_URL = ${JSON.stringify(url)};

  function proxyUrl(u) {
    if (!u || u.startsWith('data:') || u.startsWith('blob:') || u.startsWith('#') || u.startsWith('javascript:')) return u;
    try {
      const abs = new URL(u, PAGE_URL).href;
      if (abs.startsWith('http://') || abs.startsWith('https://')) {
        return PROXY + encodeURIComponent(abs);
      }
    } catch(e) {}
    return u;
  }

  // Intercept fetch
  const origFetch = window.fetch;
  window.fetch = function(input, init) {
    if (typeof input === 'string') input = proxyUrl(input);
    return origFetch.call(this, input, init);
  };

  // Intercept XHR
  const origOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url, ...args) {
    return origOpen.call(this, method, proxyUrl(url), ...args);
  };

  // Fix all <a> links to route through proxy navigation
  document.addEventListener('click', function(e) {
    const a = e.target.closest('a');
    if (!a) return;
    const href = a.getAttribute('href');
    if (!href || href.startsWith('#') || href.startsWith('javascript:')) return;
    try {
      const abs = new URL(href, PAGE_URL).href;
      if (abs.startsWith('http://') || abs.startsWith('https://')) {
        e.preventDefault();
        window.parent.postMessage({ type: 'navigate', url: abs }, '*');
      }
    } catch(e) {}
  }, true);

  // Fix form submissions
  document.addEventListener('submit', function(e) {
    const form = e.target;
    const action = form.action || PAGE_URL;
    try {
      const abs = new URL(action, PAGE_URL).href;
      e.preventDefault();
      const data = new FormData(form);
      const method = (form.method || 'GET').toUpperCase();
      if (method === 'GET') {
        const params = new URLSearchParams(data).toString();
        window.parent.postMessage({ type: 'navigate', url: abs + (params ? '?' + params : '') }, '*');
      } else {
        origFetch(PROXY + encodeURIComponent(abs), { method, body: data })
          .then(r => r.text())
          .then(html => window.parent.postMessage({ type: 'htmlResponse', html }, '*'));
      }
    } catch(err) {}
  }, true);

  // Rewrite history pushState for SPAs
  const origPush = history.pushState.bind(history);
  history.pushState = function(state, title, url) {
    try {
      const abs = new URL(url, PAGE_URL).href;
      window.parent.postMessage({ type: 'urlChange', url: abs }, '*');
    } catch(e) {}
    return origPush(state, title, url);
  };
})();
<\/script>`;

      // Inject after <head> opening or at start
      if (html.includes('<head>')) {
        html = html.replace('<head>', '<head>' + injectScript);
      } else if (html.includes('<head ')) {
        html = html.replace(/<head[^>]*>/, m => m + injectScript);
      } else {
        html = injectScript + html;
      }

      // Rewrite src/href attributes for static assets
      html = html.replace(/(src|href|action)=["']([^"']+)["']/g, (match, attr, val) => {
        if (val.startsWith('data:') || val.startsWith('blob:') || val.startsWith('#') ||
            val.startsWith('javascript:') || val.startsWith('//')) {
          if (val.startsWith('//')) {
            return `${attr}="${proxyBase + encodeURIComponent('https:' + val)}"`;
          }
          return match;
        }
        try {
          const abs = new URL(val, url).href;
          if (abs.startsWith('http://') || abs.startsWith('https://')) {
            return `${attr}="${proxyBase + encodeURIComponent(abs)}"`;
          }
        } catch {}
        return match;
      });

      // Rewrite CSS url() references
      html = html.replace(/url\(["']?([^"')]+)["']?\)/g, (match, val) => {
        if (val.startsWith('data:') || val.startsWith('blob:')) return match;
        try {
          const abs = new URL(val, url).href;
          if (abs.startsWith('http://') || abs.startsWith('https://')) {
            return `url("${proxyBase + encodeURIComponent(abs)}")`;
          }
        } catch {}
        return match;
      });

      res.send(html);
    } else if (contentType.includes('application/javascript') || contentType.includes('text/javascript')) {
      let js = await response.text();
      // Basic JS URL rewriting - fix absolute URLs in JS
      res.send(js);
    } else if (contentType.includes('text/css')) {
      let css = await response.text();
      css = css.replace(/url\(["']?([^"')]+)["']?\)/g, (match, val) => {
        if (val.startsWith('data:') || val.startsWith('blob:')) return match;
        try {
          const abs = new URL(val, url).href;
          if (abs.startsWith('http://') || abs.startsWith('https://')) {
            return `url("${process.env.BACKEND_URL || `${req.protocol}://${req.get('host')}`}/proxy?url=${encodeURIComponent(abs)}")`;
          }
        } catch {}
        return match;
      });
      res.send(css);
    } else {
      // Binary — stream through
      const buffer = await response.arrayBuffer();
      res.send(Buffer.from(buffer));
    }
  } catch (e) {
    console.error('Proxy error:', e.message);
    res.status(502).send(`
      <!DOCTYPE html><html><body style="background:#020a12;color:#ff6b6b;font-family:monospace;padding:40px;text-align:center;">
      <h2>⚠ Proxy Error</h2><p>${e.message}</p>
      <p style="color:#666;font-size:12px;">Some sites block proxy access. Try a different URL.</p>
      </body></html>
    `);
  }
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`ScramFuck/FckScramjet backend running on port ${PORT}`);
  console.log(`CORS origin: ${FRONTEND_URL}`);
});
