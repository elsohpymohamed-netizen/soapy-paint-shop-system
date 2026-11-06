'use strict';
// نظام MES لخط الدهان - خادم بدون أي مكتبات خارجية (Node 22+)
const http=require('node:http'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {DatabaseSync}=require('node:sqlite');
const PORT=+process.env.PORT||3000,BASE=(process.env.BASE_URL||`http://localhost:${PORT}`).replace(/\/$/,'');
const db=new DatabaseSync(process.env.DB_FILE||path.join(__dirname,'mes.db'));
db.exec(`PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE,name TEXT,role TEXT,station TEXT,hash TEXT,must_change INTEGER DEFAULT 0,invite TEXT,invite_exp INTEGER,active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,uid INTEGER,exp INTEGER);
CREATE TABLE IF NOT EXISTS cars(chassis TEXT PRIMARY KEY,model TEXT,color TEXT,station TEXT,status TEXT,ts INTEGER);
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,chassis TEXT,station TEXT,action TEXT,by TEXT,ts INTEGER);
CREATE INDEX IF NOT EXISTS ev_c ON events(chassis);
CREATE TABLE IF NOT EXISTS readings(id INTEGER PRIMARY KEY,station TEXT,kind TEXT,text TEXT,by TEXT,ts INTEGER);`);
const ST={ed:'خط ED',edsand:'صنفرة ED',sealer:'Sealer',pvc:'PVC',primer:'Primer',primersand:'صنفرة البرايمر',topcoat:'Top Coat',spot:'Spot Repair',repair:'Repair',ovens:'الكبائن والأفران'};
const ORDER=['ed','edsand','sealer','pvc','primer','primersand','topcoat','repair'];
const MODELS=['T4','T7pro','T8','JAC','Proton','GD','Toktok'],COLORS=['11u','22u','35u','55u','65u','85L','88u','95u','Solid'];
const ACTIONS=['enter','pass','spot','repair','repaint'];
const sha=t=>crypto.createHash('sha256').update(t).digest('hex');
const hash=p=>{const s=crypto.randomBytes(16);return s.toString('hex')+':'+crypto.scryptSync(p,s,64).toString('hex')};
const check=(p,h)=>{const [s,k]=h.split(':'),d=crypto.scryptSync(p,Buffer.from(s,'hex'),64);return crypto.timingSafeEqual(d,Buffer.from(k,'hex'))};
const rnd=n=>{const a='abcdefghjkmnpqrstuvwxyz23456789';let o='';for(const b of crypto.randomBytes(n))o+=a[b%a.length];return o};
const q=(s,...a)=>db.prepare(s).all(...a),one=(s,...a)=>db.prepare(s).get(...a),run=(s,...a)=>db.prepare(s).run(...a);
const baseOf=req=>process.env.BASE_URL?BASE:`${req.headers['x-forwarded-proto']||(req.socket.encrypted?'https':'http')}://${req.headers.host}`;
const inviteFor=(uid,req)=>{const t=rnd(28);run('UPDATE users SET invite=?,invite_exp=? WHERE id=?',sha(t),Date.now()+7*864e5,uid);return `${baseOf(req)}/?invite=${t}`};
// ---- أول تشغيل: 5 متحكمين رئيسيين بكلمات مرور مختلفة وعشوائية
if(!one('SELECT 1 x FROM users')){let t='';for(let i=1;i<=5;i++){const p=rnd(10);run('INSERT INTO users(username,name,role,hash,must_change) VALUES(?,?,?,?,1)',`controller${i}`,`متحكم ${i}`,'controller',hash(p));t+=`controller${i}  ${p}\n`}
  fs.writeFileSync(path.join(__dirname,'initial-passwords.txt'),t,{mode:0o600});console.log('\nكلمات المرور الأولية (احفظها ثم احذف الملف):\n'+t)}
if(process.argv[2]==='reset'){const u=one('SELECT id FROM users WHERE username=?',process.argv[3]);if(!u){console.log('المستخدم غير موجود');process.exit(1)}const p=rnd(10);run('UPDATE users SET hash=?,must_change=1,active=1 WHERE id=?',hash(p),u.id);console.log('كلمة المرور الجديدة:',p);process.exit(0)}
const fails=new Map();
const user=req=>{const m=/(?:^|; )sid=([a-f0-9]+)/.exec(req.headers.cookie||'');if(!m)return null;const s=one('SELECT uid FROM sessions WHERE token=? AND exp>?',sha(m[1]),Date.now());return s?one('SELECT id,username,name,role,station,must_change FROM users WHERE id=? AND active=1',s.uid):null};
const send=(res,c,o,h={})=>{res.writeHead(c,{'Content-Type':'application/json; charset=utf-8',...h});res.end(JSON.stringify(o))};
const body=req=>new Promise(r=>{let b='';req.on('data',d=>{b+=d;if(b.length>2e4)req.destroy()});req.on('end',()=>{try{r(JSON.parse(b||'{}'))}catch{r({})}})});
http.createServer(async(req,res)=>{
  res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('X-Frame-Options','DENY');res.setHeader('Referrer-Policy','no-referrer');
  const url=new URL(req.url,BASE),p=url.pathname;
  if(req.method==='GET'&&p==='/'){res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});return res.end(fs.readFileSync(path.join(__dirname,'public','index.html')))}
  if(!p.startsWith('/api/'))return send(res,404,{});
  try{
  const b=req.method==='POST'?await body(req):{},u=user(req),err=(c,m)=>send(res,c,{error:m});
  let m;
  if(p==='/api/login'){const k=req.socket.remoteAddress+'|'+String(b.username).toLowerCase(),f=fails.get(k);
    if(f&&f.until>Date.now())return err(429,'محاولات كثيرة، حاول بعد 5 دقائق');
    const r=one('SELECT * FROM users WHERE lower(username)=lower(?) AND active=1',String(b.username||'').trim());
    if(!r||!check(String(b.password||'').trim(),r.hash)){const n=(f?f.n:0)+1;fails.set(k,{n,until:n>=5?Date.now()+3e5:0});return err(401,'اسم المستخدم أو كلمة المرور غير صحيحة')}
    fails.delete(k);const t=crypto.randomBytes(32).toString('hex');run('INSERT INTO sessions VALUES(?,?,?)',sha(t),r.id,Date.now()+12*36e5);
    return send(res,200,{ok:1},{'Set-Cookie':`sid=${t}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200${(req.headers['x-forwarded-proto']==='https'||req.socket.encrypted)?'; Secure':''}`})}
  if((m=/^\/api\/invite\/(\w+)$/.exec(p))){const r=one('SELECT username,name,station FROM users WHERE invite=? AND invite_exp>? AND active=1',sha(m[1]),Date.now());return r?send(res,200,{username:r.username,name:r.name,station:ST[r.station]}):err(404,'الرابط غير صالح أو منتهي')}
  if(!u)return err(401,'سجّل الدخول');
  if(p==='/api/me')return send(res,200,{...u,stationName:ST[u.station]||''});
  if(p==='/api/logout'){const c=/sid=([a-f0-9]+)/.exec(req.headers.cookie||'');if(c)run('DELETE FROM sessions WHERE token=?',sha(c[1]));return send(res,200,{ok:1},{'Set-Cookie':'sid=; Max-Age=0; Path=/'})}
  if(p==='/api/password'){const n=String(b.password||'').trim();if(n.length<8)return err(400,'كلمة المرور 8 أحرف على الأقل');run('UPDATE users SET hash=?,must_change=0,invite=NULL WHERE id=?',hash(n),u.id);return send(res,200,{ok:1})}
  if(u.must_change)return err(403,'غيّر كلمة المرور أولاً');
  if(u.role==='controller'){
    if(p==='/api/dashboard'){const counts={};for(const r of q("SELECT station,COUNT(*) n FROM cars WHERE status='in' GROUP BY station"))counts[r.station]=r.n;
      return send(res,200,{counts,cars:q('SELECT * FROM cars ORDER BY ts DESC LIMIT 300'),events:q('SELECT * FROM events ORDER BY id DESC LIMIT 40'),readings:q('SELECT * FROM readings ORDER BY id DESC LIMIT 30')})}
    if((m=/^\/api\/car\/([\w-]+)$/.exec(p))){const c=one('SELECT * FROM cars WHERE chassis=?',m[1].toUpperCase());return c?send(res,200,{car:c,events:q('SELECT * FROM events WHERE chassis=? ORDER BY id',c.chassis)}):err(404,'رقم الشاسيه غير مسجل')}
    if(p==='/api/users')return send(res,200,q("SELECT id,username,name,station,active FROM users WHERE role='supervisor' ORDER BY id DESC"));
    if(p==='/api/supervisors'){if(!ST[b.station]||!String(b.name||'').trim())return err(400,'أدخل الاسم والمحطة');
      let un;do un=b.station+'_'+rnd(3);while(one('SELECT 1 x FROM users WHERE username=?',un));const pw=rnd(10);
      const id=run('INSERT INTO users(username,name,role,station,hash,must_change) VALUES(?,?,?,?,?,1)',un,String(b.name).trim().slice(0,60),'supervisor',b.station,hash(pw)).lastInsertRowid;
      return send(res,200,{username:un,password:pw,link:inviteFor(id,req),station:ST[b.station]})}
    if((m=/^\/api\/users\/(\d+)\/(reset|toggle)$/.exec(p))){const t=one("SELECT * FROM users WHERE id=? AND role='supervisor'",m[1]);if(!t)return err(404,'غير موجود');
      if(m[2]==='toggle'){run('UPDATE users SET active=? WHERE id=?',t.active?0:1,t.id);run('DELETE FROM sessions WHERE uid=?',t.id);return send(res,200,{ok:1})}
      const pw=rnd(10);run('UPDATE users SET hash=?,must_change=1,active=1 WHERE id=?',hash(pw),t.id);run('DELETE FROM sessions WHERE uid=?',t.id);return send(res,200,{username:t.username,password:pw,link:inviteFor(t.id,req),station:ST[t.station]})}
  }else{
    const S=u.station;
    if(p==='/api/station')return send(res,200,{cars:q("SELECT * FROM cars WHERE station=? ORDER BY ts DESC LIMIT 100",S),readings:q('SELECT * FROM readings WHERE station=? ORDER BY id DESC LIMIT 20',S)});
    if(p==='/api/car'&&S!=='ovens'){const ch=String(b.chassis||'').trim().toUpperCase(),a=b.action;
      if(!/^[A-Z0-9-]{3,30}$/.test(ch)||!MODELS.includes(b.model)||!COLORS.includes(b.color)||!ACTIONS.includes(a))return err(400,'بيانات غير صحيحة');
      const c=one('SELECT * FROM cars WHERE chassis=?',ch),now=Date.now();
      if(a!=='enter'&&(!c||c.station!==S))return err(400,'العربية ليست في محطتك حالياً');
      if(a==='pass'&&c.status!=='in')return err(400,'العربية ليست داخل المحطة');
      let st=S,status='in';
      if(a==='pass')status=S==='repair'?'approved':'passed';
      if(a==='spot')st='spot';if(a==='repair')st='repair';if(a==='repaint')status='repaint';
      run('INSERT INTO cars VALUES(?,?,?,?,?,?) ON CONFLICT(chassis) DO UPDATE SET model=excluded.model,color=excluded.color,station=excluded.station,status=excluded.status,ts=excluded.ts',ch,b.model,b.color,st,status,now);
      run('INSERT INTO events(chassis,station,action,by,ts) VALUES(?,?,?,?,?)',ch,S,a,u.username,now);return send(res,200,{ok:1})}
    if(p==='/api/reading'&&(S==='ed'||S==='ovens')){const t=String(b.text||'').trim().slice(0,200),k=String(b.kind||'').slice(0,60);if(!t)return err(400,'أدخل القراءة');run('INSERT INTO readings(station,kind,text,by,ts) VALUES(?,?,?,?,?)',S,k,t,u.username,Date.now());return send(res,200,{ok:1})}
  }
  err(403,'غير مسموح');
  }catch(e){console.error(e);send(res,500,{error:'خطأ في الخادم'})}
}).listen(PORT,()=>console.log(`MES يعمل على ${BASE}`));
