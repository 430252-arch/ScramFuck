const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'endless-proxy-secret-change-in-prod';
const DATA_DIR = process.env.DATA_DIR || './data';
const FRONTEND_URL = process.env.FRONTEND_URL || '*';

// ── Directories ──────────────────────────────────────────────────────────────
[DATA_DIR, path.join(DATA_DIR, 'uploads')].forEach(d => {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
});

// ── JSON Database ─────────────────────────────────────────────────────────────
const DB_FILE = path.join(DATA_DIR, 'db.json');
function readDB() {
  if (!fs.existsSync(DB_FILE)) {
    return { users: {}, chat: { global: [], off_topic: [], games: [] }, online: {}, meta: { userCount: 0 } };
  }
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch { return { users: {}, chat: { global: [], off_topic: [], games: [] }, online: {}, meta: { userCount: 0 } }; }
}
function writeDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), 'utf8');
}

// ── Multer (file uploads) ─────────────────────────────────────────────────────
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(DATA_DIR, 'uploads')),
  filename: (req, file, cb) => cb(null, Date.now() + '_' + Math.random().toString(36).slice(2) + path.extname(file.originalname))
});
const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 } });

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(cors({
  origin: FRONTEND_URL === '*' ? true : FRONTEND_URL.split(',').map(s => s.trim()),
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));
app.use(express.json());
app.use('/uploads', (req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  next();
}, express.static(path.join(DATA_DIR, 'uploads')));

// ── Auth middleware ───────────────────────────────────────────────────────────
function auth(req, res, next) {
  const h = req.headers.authorization || (req.query.token ? 'Bearer ' + req.query.token : null);
  if (!h) return res.status(401).json({ error: 'No token' });
  try { req.user = jwt.verify(h.replace('Bearer ', ''), JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid token' }); }
}

// ── SSE clients ───────────────────────────────────────────────────────────────
const clients = {};  // uid → [res, ...]

function broadcast(type, data, excludeUid) {
  const msg = `data: ${JSON.stringify({ type, data })}\n\n`;
  Object.entries(clients).forEach(([uid, rs]) => {
    if (uid === excludeUid) return;
    rs.forEach(r => { try { r.write(msg); } catch {} });
  });
}

function send(uid, type, data) {
  const msg = `data: ${JSON.stringify({ type, data })}\n\n`;
  (clients[uid] || []).forEach(r => { try { r.write(msg); } catch {} });
}

// ── Health ────────────────────────────────────────────────────────────────────
app.get('/health', (_, res) => res.json({ status: 'ok', ts: Date.now() }));

// ── SSE Stream ────────────────────────────────────────────────────────────────
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

  // Mark online
  const db = readDB();
  db.online[uid] = { uid, ts: Date.now() };
  writeDB(db);
  broadcast('online_count', Object.keys(db.online).length);

  // Heartbeat
  const hb = setInterval(() => { try { res.write(': ping\n\n'); } catch { clearInterval(hb); } }, 25000);

  req.on('close', () => {
    clearInterval(hb);
    clients[uid] = (clients[uid] || []).filter(r => r !== res);
    const db2 = readDB();
    delete db2.online[uid];
    writeDB(db2);
    broadcast('online_count', Object.keys(db2.online).length);
  });

  res.write(`data: ${JSON.stringify({ type: 'connected', uid })}\n\n`);
});

// ── Auth routes ───────────────────────────────────────────────────────────────
app.post('/auth/register', async (req, res) => {
  const { email, password, username } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' });
  const db = readDB();
  if (Object.values(db.users).find(u => u.email === email))
    return res.status(409).json({ error: 'Email already registered' });

  const uid = 'u_' + Date.now() + '_' + Math.random().toString(36).slice(2);
  db.meta.userCount = (db.meta.userCount || 0) + 1;
  const hash = await bcrypt.hash(password, 10);
  db.users[uid] = {
    uid, email,
    password: hash,
    username: username || email.split('@')[0],
    bio: '',
    avatarUrl: '',
    bannerUrl: '',
    status: 'online',
    badges: {},
    userIndex: db.meta.userCount,
    createdAt: Date.now(),
    lastSeen: Date.now()
  };
  writeDB(db);

  const token = jwt.sign({ uid, email }, JWT_SECRET, { expiresIn: '7d' });
  const { password: _, ...user } = db.users[uid];
  res.json({ token, user });
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const db = readDB();
  const entry = Object.entries(db.users).find(([, u]) => u.email === email);
  if (!entry) return res.status(401).json({ error: 'Invalid credentials' });
  const [uid, user] = entry;
  if (!await bcrypt.compare(password, user.password))
    return res.status(401).json({ error: 'Invalid credentials' });
  db.users[uid].status = 'online';
  db.users[uid].lastSeen = Date.now();
  writeDB(db);
  const token = jwt.sign({ uid, email }, JWT_SECRET, { expiresIn: '7d' });
  const { password: _, ...safeUser } = db.users[uid];
  res.json({ token, user: safeUser });
});

app.post('/auth/logout', auth, (req, res) => {
  const db = readDB();
  if (db.users[req.user.uid]) {
    db.users[req.user.uid].status = 'offline';
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

// ── User routes ───────────────────────────────────────────────────────────────
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
    .filter(u => (u.username || '').toLowerCase().includes(q) || (u.email || '').toLowerCase().includes(q))
    .map(({ password: _, ...u }) => u)
    .slice(0, 8);
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
  allowed.forEach(k => { if (req.body[k] !== undefined) db.users[req.user.uid][k] = req.body[k]; });
  db.users[req.user.uid].updatedAt = Date.now();
  writeDB(db);
  const { password: _, ...safe } = db.users[req.user.uid];
  broadcast('user_update', safe);
  res.json(safe);
});

app.post('/users/me/avatar', auth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  const protocol = req.headers['x-forwarded-proto'] || req.protocol;
  const host = req.headers['x-forwarded-host'] || req.get('host');
  const url = `${protocol}://${host}/uploads/${req.file.filename}`;
  const db = readDB();
  if (db.users[req.user.uid]) { db.users[req.user.uid].avatarUrl = url; writeDB(db); }
  res.json({ url });
});

app.post('/users/me/banner', auth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  const protocol = req.headers['x-forwarded-proto'] || req.protocol;
  const host = req.headers['x-forwarded-host'] || req.get('host');
  const url = `${protocol}://${host}/uploads/${req.file.filename}`;
  const db = readDB();
  if (db.users[req.user.uid]) { db.users[req.user.uid].bannerUrl = url; writeDB(db); }
  res.json({ url });
});

// ── Chat routes ───────────────────────────────────────────────────────────────
const VALID_ROOMS = ['global', 'off_topic', 'games'];

app.get('/chat/:room', auth, (req, res) => {
  const room = req.params.room;
  if (!VALID_ROOMS.includes(room)) return res.status(400).json({ error: 'Invalid room' });
  const db = readDB();
  res.json((db.chat[room] || []).slice(-100));
});

app.post('/chat/:room', auth, (req, res) => {
  const room = req.params.room;
  if (!VALID_ROOMS.includes(room)) return res.status(400).json({ error: 'Invalid room' });
  const { text } = req.body;
  if (!text || !text.trim()) return res.status(400).json({ error: 'No text' });
  const db = readDB();
  const user = db.users[req.user.uid];
  if (!user || user.banned) return res.status(403).json({ error: 'Banned' });

  const msg = {
    key: 'm_' + Date.now() + '_' + Math.random().toString(36).slice(2),
    uid: req.user.uid,
    username: user.username || 'Anonymous',
    avatarUrl: user.avatarUrl || '',
    badges: user.badges || {},
    text: text.trim().slice(0, 500),
    ts: Date.now()
  };

  if (!db.chat[room]) db.chat[room] = [];
  db.chat[room].push(msg);
  if (db.chat[room].length > 300) db.chat[room] = db.chat[room].slice(-300);
  db.users[req.user.uid].lastSeen = Date.now();
  writeDB(db);

  broadcast('message', { room, msg });
  res.json(msg);
});

app.delete('/chat/:room/:key', auth, (req, res) => {
  const room = req.params.room;
  if (!VALID_ROOMS.includes(room)) return res.status(400).json({ error: 'Invalid room' });
  const db = readDB();
  if (!db.chat[room]) return res.status(404).json({ error: 'Room not found' });
  const idx = db.chat[room].findIndex(m => m.key === req.params.key && m.uid === req.user.uid);
  if (idx === -1) return res.status(403).json({ error: 'Not your message' });
  db.chat[room].splice(idx, 1);
  writeDB(db);
  broadcast('delete', { room, key: req.params.key });
  res.json({ ok: true });
});

// ── Online count ──────────────────────────────────────────────────────────────
app.get('/online', auth, (req, res) => {
  const db = readDB();
  res.json({ count: Object.keys(db.online).length });
});

// ── Proxy endpoint ────────────────────────────────────────────────────────────
// Rewrites HTML so all links/resources route back through this proxy.
// No blob URLs, no external tab opening.
const BLOCKED_HOSTS = ['localhost', '127.0.0.1', '0.0.0.0', '::1'];

app.get('/proxy', async (req, res) => {
  const url = req.query.url;
  if (!url) return res.status(400).json({ error: 'Missing url' });

  let parsed;
  try { parsed = new URL(url); }
  catch { return res.status(400).json({ error: 'Invalid URL' }); }

  if (BLOCKED_HOSTS.includes(parsed.hostname))
    return res.status(403).json({ error: 'Blocked host' });

  try {
    const fetch = (await import('node-fetch')).default;
    const response = await fetch(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
      },
      redirect: 'follow',
      timeout: 15000
    });

    const contentType = response.headers.get('content-type') || 'text/html';

    // Strip security headers that would break embedding
    const skipHeaders = new Set([
      'content-security-policy', 'x-frame-options',
      'strict-transport-security', 'x-content-type-options',
      'permissions-policy', 'cross-origin-opener-policy',
      'cross-origin-embedder-policy', 'cross-origin-resource-policy'
    ]);
    response.headers.forEach((v, k) => {
      if (!skipHeaders.has(k.toLowerCase())) res.setHeader(k, v);
    });
    res.setHeader('Access-Control-Allow-Origin', '*');

    if (contentType.includes('text/html')) {
      let html = await response.text();
      const base = `${parsed.origin}`;

      // Rewrite absolute URLs to go through proxy
      const proxyBase = `${req.protocol}://${req.get('host')}/proxy?url=`;

      // Inject rewrite script + base tag right after <head>
      const injectScript = `
<base href="${parsed.href}">
<script>
(function(){
  var _proxyBase = ${JSON.stringify(proxyBase)};
  var _origin = ${JSON.stringify(parsed.origin)};
  function rewriteUrl(u){
    if(!u||u.startsWith('data:')||u.startsWith('javascript:')||u.startsWith('#')||u.startsWith('blob:')) return u;
    try {
      var abs = new URL(u, _origin).href;
      return _proxyBase + encodeURIComponent(abs);
    } catch(e){ return u; }
  }
  // Override window.open to prevent new tab opening
  window.open = function(url,name,features){
    if(url) window.location.href = rewriteUrl(url);
    return null;
  };
  // Intercept link clicks
  document.addEventListener('click', function(e){
    var el = e.target.closest('a');
    if(!el) return;
    var href = el.getAttribute('href');
    if(!href||href.startsWith('#')||href.startsWith('javascript:')) return;
    e.preventDefault();
    try{
      var abs = new URL(href, document.baseURI).href;
      window.parent.postMessage({type:'navigate',url:abs},'*');
    }catch(err){}
  }, true);
  // Intercept form submits
  document.addEventListener('submit', function(e){
    var form = e.target;
    var action = form.action || window.location.href;
    try{ action = new URL(action, document.baseURI).href; } catch(err){}
    e.preventDefault();
    var method = (form.method||'get').toUpperCase();
    if(method === 'GET'){
      var params = new URLSearchParams(new FormData(form)).toString();
      var url = action + (params ? '?'+params : '');
      window.parent.postMessage({type:'navigate',url:url},'*');
    } else {
      // POST: attempt fetch and load result
      fetch(_proxyBase + encodeURIComponent(action), {
        method:'POST',
        body: new FormData(form)
      }).then(r=>r.text()).then(html=>{
        document.open(); document.write(html); document.close();
      });
    }
  }, true);
})();
<\/script>`;

      // Inject after <head> tag, or prepend
      if (/<head[^>]*>/i.test(html)) {
        html = html.replace(/<head([^>]*)>/i, `<head$1>${injectScript}`);
      } else {
        html = injectScript + html;
      }

      // Strip CSP meta tags
      html = html.replace(/<meta[^>]*http-equiv=["']?Content-Security-Policy["']?[^>]*>/gi, '');
      html = html.replace(/<meta[^>]*http-equiv=["']?X-Frame-Options["']?[^>]*>/gi, '');

      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.send(html);
    } else {
      // Binary / CSS / JS / etc — pass through as-is
      const buffer = await response.arrayBuffer();
      res.setHeader('Content-Type', contentType);
      res.send(Buffer.from(buffer));
    }
  } catch (e) {
    console.error('Proxy error:', url, e.message);
    res.status(502).json({ error: e.message || 'Proxy error' });
  }
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`Endless Proxy backend running on port ${PORT}`));
