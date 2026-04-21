const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret-in-production';
const DATA_DIR = process.env.DATA_DIR || './data';

[DATA_DIR, path.join(DATA_DIR,'uploads')].forEach(d => { if(!fs.existsSync(d)) fs.mkdirSync(d,{recursive:true}); });

const DB_FILE = path.join(DATA_DIR, 'db.json');
function readDB() {
  if (!fs.existsSync(DB_FILE)) return { users:{}, chat:{global:[],off_topic:[],games:[]}, online:{}, meta:{userCount:0} };
  return JSON.parse(fs.readFileSync(DB_FILE,'utf8'));
}
function writeDB(db) { fs.writeFileSync(DB_FILE, JSON.stringify(db), 'utf8'); }

const upload = multer({ dest: path.join(DATA_DIR,'uploads'), limits:{fileSize:5*1024*1024} });

app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(DATA_DIR,'uploads')));

function auth(req,res,next) {
  const h = req.headers.authorization || (req.query.token ? 'Bearer '+req.query.token : null);
  if(!h) return res.status(401).json({error:'No token'});
  try { req.user = jwt.verify(h.replace('Bearer ',''), JWT_SECRET); next(); }
  catch { res.status(401).json({error:'Invalid token'}); }
}

const clients = {};
app.get('/stream', auth, (req,res) => {
  res.set({'Content-Type':'text/event-stream','Cache-Control':'no-cache','Connection':'keep-alive'});
  res.flushHeaders();
  const uid = req.user.uid;
  if(!clients[uid]) clients[uid]=[];
  clients[uid].push(res);
  const db=readDB(); db.online[uid]={uid,ts:Date.now()}; writeDB(db);
  req.on('close',()=>{
    clients[uid]=(clients[uid]||[]).filter(r=>r!==res);
    const db=readDB(); delete db.online[uid]; writeDB(db);
    broadcast('online', Object.keys(readDB().online).length);
  });
  res.write(`data: ${JSON.stringify({type:'connected'})}\n\n`);
});

function broadcast(type, data, exclude) {
  const msg = `data: ${JSON.stringify({type,data})}\n\n`;
  Object.entries(clients).forEach(([uid,rs])=>{
    if(uid===exclude) return;
    rs.forEach(r=>{ try{r.write(msg);}catch{} });
  });
}
function send(uid, type, data) {
  (clients[uid]||[]).forEach(r=>{ try{r.write(`data: ${JSON.stringify({type,data})}\n\n`);}catch{} });
}

app.get('/health', (_,res)=>res.json({status:'ok'}));

app.post('/auth/register', async (req,res)=>{
  const {email,password,username}=req.body;
  if(!email||!password) return res.status(400).json({error:'Missing fields'});
  const db=readDB();
  if(Object.values(db.users).find(u=>u.email===email)) return res.status(409).json({error:'Email already registered'});
  const uid = 'u_'+Date.now()+'_'+Math.random().toString(36).slice(2);
  db.meta.userCount=(db.meta.userCount||0)+1;
  const hash = await bcrypt.hash(password,10);
  db.users[uid]={uid,email,password:hash,username:username||email.split('@')[0],bio:'',avatarUrl:'',bannerUrl:'',status:'active',badges:{},userIndex:db.meta.userCount,createdAt:Date.now(),lastSeen:Date.now()};
  writeDB(db);
  const token = jwt.sign({uid,email},JWT_SECRET,{expiresIn:'7d'});
  const {password:_,...user}=db.users[uid];
  res.json({token,user});
});

app.post('/auth/login', async (req,res)=>{
  const {email,password}=req.body;
  const db=readDB();
  const entry=Object.entries(db.users).find(([,u])=>u.email===email);
  if(!entry) return res.status(401).json({error:'Invalid credentials'});
  const [uid,user]=entry;
  if(!await bcrypt.compare(password,user.password)) return res.status(401).json({error:'Invalid credentials'});
  db.users[uid].status='active'; db.users[uid].lastSeen=Date.now(); writeDB(db);
  const token=jwt.sign({uid,email},JWT_SECRET,{expiresIn:'7d'});
  const {password:_,...safeUser}=db.users[uid];
  res.json({token,user:safeUser});
});

app.post('/auth/logout', auth, (req,res)=>{
  const db=readDB();
  if(db.users[req.user.uid]){db.users[req.user.uid].status='offline';db.users[req.user.uid].lastSeen=Date.now();writeDB(db);}
  res.json({ok:true});
});

app.get('/auth/me', auth, (req,res)=>{
  const db=readDB();
  const user=db.users[req.user.uid];
  if(!user) return res.status(404).json({error:'Not found'});
  const {password:_,...safe}=user;
  res.json(safe);
});

app.get('/users', auth, (req,res)=>{
  const db=readDB();
  const users=Object.values(db.users).map(({password:_,...u})=>u).sort((a,b)=>(a.userIndex||0)-(b.userIndex||0));
  res.json(users);
});

app.get('/users/search', auth, (req,res)=>{
  const q=(req.query.q||'').toLowerCase();
  const db=readDB();
  const results=Object.values(db.users).filter(u=>(u.username||'').toLowerCase().includes(q)).map(({password:_,...u})=>u).slice(0,8);
  res.json(results);
});

app.get('/users/:uid', auth, (req,res)=>{
  const db=readDB();
  const user=db.users[req.params.uid];
  if(!user) return res.status(404).json({error:'Not found'});
  const {password:_,...safe}=user;
  res.json(safe);
});

app.patch('/users/me', auth, (req,res)=>{
  const db=readDB();
  if(!db.users[req.user.uid]) return res.status(404).json({error:'Not found'});
  const allowed=['username','bio','status','avatarUrl','bannerUrl'];
  allowed.forEach(k=>{ if(req.body[k]!==undefined) db.users[req.user.uid][k]=req.body[k]; });
  db.users[req.user.uid].updatedAt=Date.now();
  writeDB(db);
  const {password:_,...safe}=db.users[req.user.uid];
  res.json(safe);
});

app.post('/users/me/avatar', auth, upload.single('file'), (req,res)=>{
  if(!req.file) return res.status(400).json({error:'No file'});
  const url=`${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
  const db=readDB();
  if(db.users[req.user.uid]) { db.users[req.user.uid].avatarUrl=url; writeDB(db); }
  res.json({url});
});

app.post('/users/me/banner', auth, upload.single('file'), (req,res)=>{
  if(!req.file) return res.status(400).json({error:'No file'});
  const url=`${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
  const db=readDB();
  if(db.users[req.user.uid]) { db.users[req.user.uid].bannerUrl=url; writeDB(db); }
  res.json({url});
});

app.patch('/users/:uid/admin', auth, (req,res)=>{
  const db=readDB();
  const me=db.users[req.user.uid];
  if(!me||me.email!==process.env.ADMIN_EMAIL) return res.status(403).json({error:'Forbidden'});
  const target=db.users[req.params.uid];
  if(!target) return res.status(404).json({error:'Not found'});
  const allowed=['status','banned','username','badges'];
  allowed.forEach(k=>{ if(req.body[k]!==undefined) db.users[req.params.uid][k]=req.body[k]; });
  writeDB(db);
  res.json({ok:true});
});

app.get('/chat/:room', auth, (req,res)=>{
  const db=readDB();
  const msgs=(db.chat[req.params.room]||[]).slice(-50);
  res.json(msgs);
});

app.post('/chat/:room', auth, async (req,res)=>{
  const {text}=req.body;
  if(!text) return res.status(400).json({error:'No text'});
  const db=readDB();
  const user=db.users[req.user.uid];
  if(!user||user.banned||user.status==='banned') return res.status(403).json({error:'Banned'});
  const msg={key:'m_'+Date.now()+'_'+Math.random().toString(36).slice(2),uid:req.user.uid,username:user.username||'Anonymous',avatarUrl:user.avatarUrl||'',badges:user.badges||{},text:text.slice(0,500),ts:Date.now()};
  if(!db.chat[req.params.room]) db.chat[req.params.room]=[];
  db.chat[req.params.room].push(msg);
  if(db.chat[req.params.room].length>200) db.chat[req.params.room]=db.chat[req.params.room].slice(-200);
  db.users[req.user.uid].status='chat'; db.users[req.user.uid].lastSeen=Date.now();
  writeDB(db);
  broadcast('message',{room:req.params.room,msg});
  res.json(msg);
});

app.delete('/chat/:room/:key', auth, (req,res)=>{
  const db=readDB();
  if(!db.chat[req.params.room]) return res.status(404).json({error:'Room not found'});
  const idx=db.chat[req.params.room].findIndex(m=>m.key===req.params.key&&m.uid===req.user.uid);
  if(idx===-1) return res.status(403).json({error:'Not your message'});
  db.chat[req.params.room].splice(idx,1);
  writeDB(db);
  broadcast('delete',{room:req.params.room,key:req.params.key});
  res.json({ok:true});
});

app.get('/online', auth, (req,res)=>{
  const db=readDB();
  res.json({count:Object.keys(db.online).length});
});

app.get('/proxy', (req,res)=>{
  const url=req.query.url;
  if(!url) return res.status(400).json({error:'Missing url'});
  import('node-fetch').then(({default:fetch})=>fetch(url,{headers:{'User-Agent':'Mozilla/5.0'}}).then(async r=>{
    res.set('Content-Type',r.headers.get('content-type')||'text/html');
    res.send(await r.text());
  })).catch(e=>res.status(502).json({error:e.message}));
});

app.listen(PORT,()=>console.log(`EP backend running on port ${PORT}`));
