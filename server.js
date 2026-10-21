import http from 'node:http';
import { readFileSync, existsSync, mkdirSync, statSync } from 'node:fs';
import { join, extname, dirname, resolve } from 'node:path';
import {fileURLToPath} from 'node:url';
import { randomBytes, scryptSync, timingSafeEqual, createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import {mailConfigured,sendMail} from './lib/mailer.js';
import {ROLES,scopeData,mergeState,hasUnsafeText} from './lib/scope.js';

const BASE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(BASE, 'public');
const DATA_DIR = resolve(process.env.SGO_DATA_DIR || join(BASE, 'data'));
const DB_FILE = join(DATA_DIR, 'qualigest.sqlite');
const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '127.0.0.1';
const PROD = process.env.NODE_ENV === 'production';
const PUBLIC_ORIGIN = process.env.PUBLIC_ORIGIN || '';
const EMAIL = 'luan.oliveira@britania.com.br';
const ALLOWED_DOMAIN = (process.env.ALLOWED_EMAIL_DOMAIN || 'britania.com.br').toLowerCase();
const validEmail=e=>typeof e==='string'&&/^[a-z0-9._%+-]+@[a-z0-9.-]+$/.test(e)&&e.endsWith('@'+ALLOWED_DOMAIN)&&e.length<=254;
const NAME = 'Luan Lespico de Oliveira';
const EIGHT_HOURS = 8 * 60 * 60 * 1000;
const MAX_BODY = 5_000_000;
const SESSION_COOKIE = 'sgo_session';
const KEYS = ['fields','colabs','monitorias','ausencias','treinamentos','solicitacoesTreinamento','notificacoes','audit','historico','lotes','emails','pbo','pboDelegacoes','ocorrenciaDelegacoes','solicitacoes','kanban'];
const MODULES = new Set(['demandas','agenda','passagem','monitorias','planos','treinamentos','colaboradores','ausencias','desenvolvimento','comunicados','procedimentos']);
const MIME = {'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8'};
const sha = s => createHash('sha256').update(s).digest('hex');
if (!Number.isSafeInteger(PORT) || PORT < 1 || PORT > 65535) throw Error('PORT inválida (1 a 65535).');
if (PROD && (!PUBLIC_ORIGIN || !PUBLIC_ORIGIN.startsWith('https://'))) throw Error('Em produção, informe PUBLIC_ORIGIN com HTTPS (ex.: https://sgo.exemplo.com.br) e configure um proxy TLS.');
if (PUBLIC_ORIGIN) { const u = new URL(PUBLIC_ORIGIN); if (!['http:', 'https:'].includes(u.protocol) || u.username || u.password || u.pathname !== '/' || u.search || u.hash || u.origin !== PUBLIC_ORIGIN) throw Error('PUBLIC_ORIGIN deve ser somente a origem (esquema + domínio + porta opcional), sem barra final.'); }
mkdirSync(DATA_DIR, {recursive:true, mode:0o700});
const db = new DatabaseSync(DB_FILE);
db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,email TEXT UNIQUE NOT NULL,name TEXT NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'admin',created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id),csrf TEXT NOT NULL,expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS app_state(id INTEGER PRIMARY KEY CHECK(id=1),revision INTEGER NOT NULL DEFAULT 0,data TEXT NOT NULL DEFAULT '{}');
CREATE TABLE IF NOT EXISTS records(id INTEGER PRIMARY KEY AUTOINCREMENT,module TEXT NOT NULL,title TEXT NOT NULL,details TEXT NOT NULL DEFAULT '',status TEXT NOT NULL DEFAULT 'Aberto',due_date TEXT NOT NULL DEFAULT '',created_at TEXT DEFAULT CURRENT_TIMESTAMP,updated_at TEXT DEFAULT CURRENT_TIMESTAMP,created_by INTEGER NOT NULL REFERENCES users(id));
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,action TEXT NOT NULL,record_id INTEGER,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE INDEX IF NOT EXISTS idx_records_module ON records(module);CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires);
CREATE TABLE IF NOT EXISTS reset_tokens(token_hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id),expires INTEGER NOT NULL,created_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_reset_exp ON reset_tokens(expires);
CREATE TABLE IF NOT EXISTS auth_failures(identity TEXT PRIMARY KEY, count INTEGER NOT NULL, expires INTEGER NOT NULL);`);
const strongPassword = p => typeof p==='string'&&p.length>=12&&p.length<=512&&/[a-z]/.test(p)&&/[A-Z]/.test(p)&&/[0-9]/.test(p)&&/[^a-zA-Z0-9]/.test(p);
const hashPass = password => { const salt = randomBytes(32);return `${salt.toString('hex')}:${scryptSync(password,salt,64).toString('hex')}`; };
const verify = (password, stored) => {try{const [s,h] = stored.split(':');const actual=scryptSync(password,Buffer.from(s,'hex'),64),expected=Buffer.from(h,'hex');return expected.length===64&&timingSafeEqual(actual,expected);}catch{return false;}};
const existing = db.prepare('SELECT id FROM users WHERE email=?').get(EMAIL);
if (!existing) {
 const pwd = process.env.ADMIN_INITIAL_PASSWORD;
 if (!strongPassword(pwd)) throw Error('Senha inicial: use 12+ caracteres, com letra maiúscula, minúscula, número e símbolo.');
 db.prepare('INSERT INTO users(email,name,password_hash,role) VALUES(?,?,?,?)').run(EMAIL,NAME,hashPass(pwd),'admin');
 console.log('Conta administrativa criada. Retire ADMIN_INITIAL_PASSWORD do ambiente após o início.');
}
db.prepare("INSERT OR IGNORE INTO app_state(id,revision,data) VALUES(1,0,'{}')").run();
// O colaborador e a função administrativa são identidades diferentes do mesmo usuário.
// Id 904 era a referência de Meu Perfil no frontend original; preservar quando disponível.
const ADMIN_COLAB_ID = 904;
for(const [column,definition] of [['colab_id','INTEGER'],['active','INTEGER NOT NULL DEFAULT 1'],['must_change','INTEGER NOT NULL DEFAULT 0']]){
 if(!db.prepare('PRAGMA table_info(users)').all().some(c=>c.name===column))db.exec(`ALTER TABLE users ADD COLUMN ${column} ${definition}`);
}
const auditActor = (u, action, id=null)=>log(u,action,id);
function vincularAdminAoCadastro() {
 db.exec('BEGIN IMMEDIATE');
 try {
  const state=db.prepare('SELECT revision,data FROM app_state WHERE id=1').get();
  const data=JSON.parse(state.data);
  if(!data||typeof data!=='object'||Array.isArray(data))throw Error('Estado do sistema inválido. Restaure o backup antes de iniciar.');
  if(!Array.isArray(data.colabs))data.colabs=[];
  const matching=data.colabs.filter(c=>c&&typeof c==='object'&&String(c.email||'').trim().toLowerCase()===EMAIL);
  let collaborator=matching.find(c=>Number.isSafeInteger(c.id)&&c.id>0);
  let changed=false;
  if(!collaborator){
   // Nunca substituir outro colaborador que já ocupe 904, nem inventar matrícula corporativa.
   const used=new Set(data.colabs.map(c=>c.id));
   const id=used.has(ADMIN_COLAB_ID)?Math.max(ADMIN_COLAB_ID,...[...used].filter(Number.isSafeInteger))+1:ADMIN_COLAB_ID;
   collaborator={id,matricula:'PENDENTE-'+id,nome:NAME,email:EMAIL,telefone:'',cargo:'Colaborador',equipe:'Não informada',gestor:'',status:'Ativo',foto:'',areaFixa:'',endereco:{},custom:{}};
   data.colabs.push(collaborator);
   changed=true;
  }
  // A tabela users concede acesso; a ficha de colaborador guarda os dados profissionais.
  const user=db.prepare('SELECT id,colab_id FROM users WHERE email=?').get(EMAIL);
  if(!user)throw Error('Conta administradora não encontrada.');
  if(user.colab_id!==collaborator.id)db.prepare('UPDATE users SET colab_id=? WHERE id=?').run(collaborator.id,user.id);
  if(changed){
   // Em bancos existentes, aumentar a revisão para invalidar clientes com estado antigo.
   const revised=state.data==='{}'?state.revision:state.revision+1;
   db.prepare('UPDATE app_state SET revision=?,data=? WHERE id=1').run(revised,JSON.stringify(data));
  }
  db.exec('COMMIT');
 } catch(e){db.exec('ROLLBACK');throw e;}
}
vincularAdminAoCadastro();
// Sem cadastro automático de contas de demonstração.
const passReset = process.env.ADMIN_INITIAL_PASSWORD;
if (existing && passReset) console.log('ADMIN_INITIAL_PASSWORD não altera senhas já existentes. Use npm run reset-admin para trocar a senha.');
function headers(res) {
 res.setHeader('X-Content-Type-Options','nosniff');
 res.setHeader('X-Frame-Options','DENY');
 res.setHeader('Referrer-Policy','no-referrer');
 res.setHeader('Permissions-Policy','camera=(), microphone=(), geolocation=()');
 res.setHeader('Cross-Origin-Resource-Policy','same-origin');
 res.setHeader('X-Permitted-Cross-Domain-Policies','none');
 res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'self' https://cdn.tailwindcss.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'");
 if (PROD) res.setHeader('Strict-Transport-Security','max-age=31536000; includeSubDomains');
}
function json(res,code,data,extra={}) {res.writeHead(code,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','Pragma':'no-cache',...extra});res.end(JSON.stringify(data));}
function cookieValue(req,name) {const part=(req.headers.cookie||'').split(';').map(v=>v.trim()).find(v=>v.startsWith(name+'='));return part?.slice(name.length+1)||'';}
function session(req) {
 const token=cookieValue(req,SESSION_COOKIE);
 if (!/^[0-9a-f]{64}$/.test(token)) return null;
 return db.prepare('SELECT s.*,u.email,u.name,u.role,u.colab_id,u.must_change FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires>? AND u.active=1').get(sha(token),Date.now())||null;
}
function originOk(req) {
 if (!req.headers.origin || typeof req.headers.origin !== 'string') return false;
 try {
   const origin = new URL(req.headers.origin);
   if (origin.origin !== req.headers.origin) return false;
   const expected = PUBLIC_ORIGIN || `http://${req.headers.host}`;
   return origin.origin === expected;
 } catch {return false;}
}
function body(req) {
 return new Promise((ok,bad)=>{
   let size=0, parts=[], tooLarge=false;
   req.on('data', chunk=>{size+=chunk.length;if(size>MAX_BODY){tooLarge=true;parts=[];}else if(!tooLarge)parts.push(chunk);});
   req.on('end',()=>{if(tooLarge)return bad(Object.assign(Error('Dados excedem 5 MB.'),{status:413}));try{const obj=JSON.parse(Buffer.concat(parts).toString('utf8')||'{}');if(obj===null||typeof obj!=='object'||Array.isArray(obj))throw Error();ok(obj);}catch{return bad(Object.assign(Error('JSON inválido.'),{status:400}));}});
   req.on('error',bad);
 });
}
function log(userId, action, recordId=null) {db.prepare('INSERT INTO audit(user_id,action,record_id) VALUES(?,?,?)').run(userId,action,recordId);}
const formUser = u=>({name:u.name,email:u.email,role:u.role,colabId:u.colab_id,mustChange:!!u.must_change});
const adminOnly=(user,res)=>{if(user.role!=='admin'){json(res,403,{error:'Acesso exclusivo do administrador.'});return false;}return true;};
function colabFor(user){const state=JSON.parse(db.prepare('SELECT data FROM app_state WHERE id=1').get().data);return state.colabs?.find(c=>c.id===user.colab_id);}
function ensureActive(user){const colab=colabFor(user);return !!(colab&&String(colab.email||'').toLowerCase()===user.email&&(user.role==='admin'||colab.status==='Ativo'));}
function fail(identity){const now=Date.now(),row=db.prepare('SELECT * FROM auth_failures WHERE identity=?').get(identity),count=row&&row.expires>now?row.count+1:1;db.prepare('INSERT INTO auth_failures(identity,count,expires) VALUES(?,?,?) ON CONFLICT(identity) DO UPDATE SET count=excluded.count,expires=excluded.expires').run(identity,count,now+15*60_000);return count;}
function blocked(identity){const row=db.prepare('SELECT * FROM auth_failures WHERE identity=?').get(identity);return !!(row&&row.expires>Date.now()&&row.count>=8);}
function clearFail(identity){db.prepare('DELETE FROM auth_failures WHERE identity=?').run(identity);}
async function emailLink(user,kind){
 if(!mailConfigured())throw Object.assign(Error('Integração de e-mail não configurada pelo TI.'),{status:503});
 const token=randomBytes(32).toString('hex');const url=(PUBLIC_ORIGIN||`http://${HOST}:${PORT}`)+'/#reset='+encodeURIComponent(token);
 db.prepare('DELETE FROM reset_tokens WHERE user_id=?').run(user.id);
 db.prepare('INSERT INTO reset_tokens(token_hash,user_id,expires,created_at) VALUES(?,?,?,?)').run(sha(token),user.id,Date.now()+30*60_000,Date.now());
 try{await sendMail(user.email,kind==='invite'?'Convite para acessar QualiGest SGO':'Redefinição de senha do QualiGest SGO',url,DATA_DIR);}catch(e){db.prepare('DELETE FROM reset_tokens WHERE token_hash=?').run(sha(token));throw e;}
}

function sessionCookie(token,maxAge=0) {return `${SESSION_COOKIE}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}${PROD?'; Secure':''}`;}
const attempts=new Map();
function throttle(req,identity='global') {
 const addr=(req.socket.remoteAddress||'unknown')+'|'+String(identity).slice(0,256),now=Date.now();
 if(attempts.size>15000) for(const [key,value] of attempts) if(value.until<now)attempts.delete(key);
 const old=attempts.get(addr);const info=old&&old.until>now?old:{count:0,until:now+15*60_000};
 info.count++;attempts.set(addr,info);return info.count>12;
}
let requestCount=0;
function prune() {if(++requestCount%100===0){db.prepare('DELETE FROM sessions WHERE expires<?').run(Date.now());db.prepare('DELETE FROM reset_tokens WHERE expires<?').run(Date.now());db.prepare('DELETE FROM auth_failures WHERE expires<?').run(Date.now());}}
function validateState(data) {
 if(!data||typeof data!=='object'||Array.isArray(data)) return null;
 if(Object.keys(data).some(k=>!KEYS.includes(k)&&k!=='extras')) return null;
 const clean={};
 for(const key of KEYS){if(data[key]!==undefined){if(!Array.isArray(data[key])||data[key].length>30000)return null;clean[key]=data[key];}}
 if(data.extras!==undefined){
   if(!data.extras||typeof data.extras!=='object'||Array.isArray(data.extras))return null;
   const entries=Object.entries(data.extras);
   if(entries.length>100) return null;
   clean.extras={};
   for(const [key,value] of entries){if(!(/^(sgo_[a-z0-9_]{1,90}|SGO_MURAL_(?:LEITURA_REGISTROS_V1|LIDOS_\d{1,15}))$/.test(key)))return null;clean.extras[key]=value;}
 }
 return clean;
}
const server = http.createServer(async (req,res) => {
 try {
  headers(res);prune();
  if(req.url.length>4000)return json(res,414,{error:'Endereço muito longo.'});
  const url=new URL(req.url,'http://localhost');
  if(url.pathname.startsWith('/api/')) {
   if(!['GET','POST','PUT','PATCH','DELETE'].includes(req.method))return json(res,405,{error:'Método não permitido.',},{Allow:'GET, POST, PUT, PATCH, DELETE'});
   if(req.method!=='GET'&&!originOk(req))return json(res,403,{error:'Origem não autorizada.'});
   if(url.pathname==='/api/auth/request-reset'&&req.method==='POST'){
    const b=await body(req),email=String(b.email||'').trim().toLowerCase();
    if(throttle(req,'reset:'+email))return json(res,429,{error:'Muitas solicitações. Aguarde alguns minutos.'});
    const u=validEmail(email)?db.prepare('SELECT * FROM users WHERE email=? AND active=1').get(email):null;
    if(u&&ensureActive(u)){
     try{await emailLink(u,'reset');log(u.id,'password-reset-request');}
     catch(e){console.warn('Falha no envio de recuperação:',e.message);if(e.status===503)return json(res,503,{error:'Serviço de e-mail não configurado. Contate a administração.'});}
    }
    return json(res,200,{ok:true,message:'Se a conta estiver ativa, um link será enviado ao e-mail informado.'});
   }
   if(url.pathname==='/api/auth/reset'&&req.method==='POST'){
    const b=await body(req),token=String(b.token||''),password=b.password;
    if(throttle(req,'token:'+token))return json(res,429,{error:'Muitas tentativas. Aguarde.'});
    if(!/^[0-9a-f]{64}$/.test(token)||!strongPassword(password))return json(res,400,{error:'Link inválido ou senha fora das regras (12+ caracteres, letra maiúscula, minúscula, número e símbolo).'});
    db.exec('BEGIN IMMEDIATE');
    try{
     const entry=db.prepare('SELECT r.*,u.active FROM reset_tokens r JOIN users u ON r.user_id=u.id WHERE token_hash=? AND r.expires>?').get(sha(token),Date.now());
     if(!entry||!entry.active){db.exec('ROLLBACK');return json(res,400,{error:'Link inválido ou expirado.'});}
     db.prepare('UPDATE users SET password_hash=?,must_change=0 WHERE id=?').run(hashPass(password),entry.user_id);
     db.prepare('DELETE FROM reset_tokens WHERE user_id=?').run(entry.user_id);
     db.prepare('DELETE FROM sessions WHERE user_id=?').run(entry.user_id);
     log(entry.user_id,'password-reset');db.exec('COMMIT');return json(res,200,{ok:true});
    }catch(e){db.exec('ROLLBACK');throw e;}
   }
   if(url.pathname==='/api/login'&&req.method==='POST') {
    const b=await body(req),email=String(b.email||'').trim().toLowerCase(),password=String(b.password||'');
    if(throttle(req,'login:'+email))return json(res,429,{error:'Muitas tentativas. Tente novamente mais tarde.'},{'Retry-After':'900'});
    const user=validEmail(email)?db.prepare('SELECT * FROM users WHERE email=? AND active=1').get(email):null;
    if(blocked('email:'+email))return json(res,429,{error:'Muitas tentativas para esta conta. Aguarde 15 minutos.'});
    if(!user||!verify(password,user.password_hash)||!ensureActive(user)||user.must_change){fail('email:'+email);return json(res,401,{error:'Credenciais inválidas.'});}
    clearFail('email:'+email);
    const token=randomBytes(32).toString('hex'),csrf=randomBytes(32).toString('hex');
    db.prepare('DELETE FROM sessions WHERE user_id=?').run(user.id); // um acesso ativo por vez
    db.prepare('INSERT INTO sessions(token_hash,user_id,csrf,expires) VALUES(?,?,?,?)').run(sha(token),user.id,csrf,Date.now()+EIGHT_HOURS);
    log(user.id,'login');return json(res,200,{user:formUser(user),csrf},{'Set-Cookie':sessionCookie(token,EIGHT_HOURS/1000)});
   }
   const user=session(req);if(!user||!ensureActive(user)||user.must_change)return json(res,401,{error:'Sessão expirada ou acesso desativado. Entre novamente.'});
   if(req.method!=='GET'&&req.headers['x-csrf-token']!==user.csrf)return json(res,403,{error:'CSRF inválido.'});
   if(url.pathname==='/api/me'&&req.method==='GET')return json(res,200,{user:formUser(user),csrf:user.csrf});
   if(url.pathname==='/api/change-password'&&req.method==='POST'){
    const b=await body(req),oldPassword=String(b.current||''),newPassword=String(b.next||'');
    if(!strongPassword(newPassword)||oldPassword===newPassword)return json(res,400,{error:'Use uma senha diferente da anterior, com 12+ caracteres, maiúscula, minúscula, número e símbolo.'});
    const row=db.prepare('SELECT password_hash FROM users WHERE id=?').get(user.user_id);
    if(!row||!verify(oldPassword,row.password_hash))return json(res,400,{error:'Senha atual incorreta.'});
    db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(hashPass(newPassword),user.user_id);
    db.prepare('DELETE FROM sessions WHERE user_id=? AND token_hash<>?').run(user.user_id,user.token_hash);
    db.prepare('UPDATE users SET must_change=0 WHERE id=?').run(user.user_id);
    log(user.user_id,'password-change');return json(res,200,{ok:true});
   }

   if(url.pathname==='/api/admin/users'&&req.method==='GET'){
    if(!adminOnly(user,res))return;
    const rows=db.prepare('SELECT id,email,name,role,colab_id,active,must_change,created_at FROM users ORDER BY name').all();
    return json(res,200,{users:rows.map(u=>({...formUser(u),id:u.id,active:!!u.active,createdAt:u.created_at}))});
   }
   if(url.pathname==='/api/admin/users/invite'&&req.method==='POST'){
    if(!adminOnly(user,res))return;
    if(!mailConfigured())return json(res,503,{error:'Configure o provedor de e-mail antes de convidar colaboradores.'});
    const b=await body(req),email=String(b.email||'').trim().toLowerCase(),role=b.role||'operacao';
    if(!validEmail(email)||!ROLES.has(role)||role==='admin')return json(res,400,{error:'E-mail corporativo ou função inválidos.'});
    const colabs=JSON.parse(db.prepare('SELECT data FROM app_state WHERE id=1').get().data).colabs||[];
    const rec=colabs.find(c=>String(c.email||'').trim().toLowerCase()===email&&c.status==='Ativo');
    if(!rec)return json(res,400,{error:'Primeiro cadastre o colaborador ativo com este e-mail na tela Colaboradores.'});
    let u=db.prepare('SELECT * FROM users WHERE email=?').get(email);
    if(u&&u.role==='admin')return json(res,403,{error:'O administrador principal não pode ser alterado por este fluxo.'});
    if(!u){
     const created=db.prepare('INSERT INTO users(email,name,password_hash,role,colab_id,active,must_change) VALUES(?,?,?,?,?,1,1)').run(email,rec.nome,hashPass(randomBytes(32).toString('hex')),role,rec.id);
     u=db.prepare('SELECT * FROM users WHERE id=?').get(Number(created.lastInsertRowid));
    }else{
     db.prepare('UPDATE users SET role=?,colab_id=?,name=?,active=1,must_change=1 WHERE id=?').run(role,rec.id,rec.nome,u.id);
    }
    await emailLink(u,'invite');db.prepare('DELETE FROM sessions WHERE user_id=?').run(u.id);log(user.user_id,'invite-user',u.id);
    return json(res,200,{ok:true,message:'Convite enviado. O colaborador definirá a própria senha pelo link recebido.'});
   }
   const mUser=url.pathname.match(/^\/api\/admin\/users\/(\d+)$/);
   if(mUser&&req.method==='PATCH'){
    if(!adminOnly(user,res))return;
    const id=Number(mUser[1]),b=await body(req),u=db.prepare('SELECT * FROM users WHERE id=?').get(id);
    if(!u)return json(res,404,{error:'Usuário não encontrado.'});
    if(u.email===EMAIL||u.id===user.user_id)return json(res,403,{error:'Não é permitido alterar a própria conta administradora.'});
    if(b.role!==undefined&&(!ROLES.has(b.role)||b.role==='admin'))return json(res,400,{error:'Papel inválido.'});
    if(b.active!==undefined&&typeof b.active!=='boolean')return json(res,400,{error:'Status inválido.'});
    db.prepare('UPDATE users SET role=?,active=? WHERE id=?').run(b.role??u.role,b.active===undefined?u.active:Number(b.active),id);
    if(b.active===false)db.prepare('DELETE FROM sessions WHERE user_id=?').run(id);
    log(user.user_id,'user-permissions',id);return json(res,200,{ok:true});
   }
   if(url.pathname==='/api/logout'&&req.method==='POST'){db.prepare('DELETE FROM sessions WHERE token_hash=?').run(user.token_hash);log(user.user_id,'logout');return json(res,200,{ok:true},{'Set-Cookie':sessionCookie('',0)});}
   if(url.pathname==='/api/state'&&req.method==='GET'){
    const row=db.prepare('SELECT revision,data FROM app_state WHERE id=1').get();
    return json(res,200,{revision:row.revision,data:scopeData(JSON.parse(row.data),user)});
   }
   if(url.pathname==='/api/state'&&req.method==='PUT'){
    const b=await body(req),data=validateState(b.data);
    if(!data||hasUnsafeText(data)||!Number.isSafeInteger(b.revision)||b.revision<0)return json(res,400,{error:'Dados ou revisão inválidos.'});
    const base=b.base===undefined?null:validateState(b.base);
    if(b.base!==undefined&&!base)return json(res,400,{error:'Estado-base inválido.'});
    // Escrita atômica: diferencia itens específicos quando há base, mantendo CAS legado para admin.
    db.exec('BEGIN IMMEDIATE');
    try{
     const row=db.prepare('SELECT revision,data FROM app_state WHERE id=1').get(),previous=JSON.parse(row.data);
     let updated;
     if(base){
      const projection=scopeData(previous,user);
      // Não permitir que um cliente declare como base registros fora de seu escopo.
      for(const key of Object.keys(base))if(key!=='extras'&&Array.isArray(base[key])&&user.role!=='admin'){
       const allowed=projection[key]||[];
       for(const entry of base[key])if(!allowed.some(a=>JSON.stringify(a)===JSON.stringify(entry)))throw Object.assign(Error('Registro-base fora de seu escopo ou já alterado.'),{status:409});
      }
      updated=mergeState(previous,base,data,user);
     }else{
      if(user.role!=='admin')throw Object.assign(Error('Atualize o navegador para continuar.'),{status:403});
      if(b.revision!==row.revision)throw Object.assign(Error('Os dados foram atualizados em outra sessão.'),{status:409});
      updated={data,changes:1};
     }
     const matches=updated.data.colabs?.filter(c=>c&&c.id===user.colab_id)||[];
     if(matches.length!==1||String(matches[0].email||'').trim().toLowerCase()!==user.email||!String(matches[0].nome||'').trim())throw Object.assign(Error('O cadastro do usuário não pode ser excluído ou desvinculado.'),{status:400});
     const identities=db.prepare('SELECT email,colab_id FROM users').all();
     const employeeIds=new Set(),employeeMails=new Set();
     for(const employee of updated.data.colabs||[]){
      const mail=String(employee.email||'').trim().toLowerCase();
      if(!Number.isSafeInteger(employee.id)||employee.id<=0||employeeIds.has(employee.id)||mail&&employeeMails.has(mail))throw Object.assign(Error('Cadastro de colaboradores contém IDs ou e-mails duplicados.'),{status:400});
      employeeIds.add(employee.id);if(mail)employeeMails.add(mail);
     }
     for(const identity of identities){const record=updated.data.colabs?.find(c=>c.id===identity.colab_id);
      if(!record||String(record.email||'').trim().toLowerCase()!==identity.email)throw Object.assign(Error('Um colaborador com conta ativa não pode ser excluído ou ter o e-mail desvinculado.'),{status:400});
     }
     const serialized=JSON.stringify(updated.data);
     if(Buffer.byteLength(serialized)>MAX_BODY)throw Object.assign(Error('Limite de dados excedido.'),{status:413});
     const revision=row.revision+(updated.changes?1:0);
     if(updated.changes){db.prepare('UPDATE app_state SET revision=?,data=? WHERE id=1').run(revision,serialized);log(user.user_id,'state-save');}
     db.exec('COMMIT');return json(res,200,{revision});
    }catch(e){db.exec('ROLLBACK');throw e;}
   }
   if(url.pathname==='/api/summary'&&req.method==='GET'){if(!adminOnly(user,res))return;const rows=db.prepare('SELECT module,status,COUNT(*) total FROM records GROUP BY module,status').all();return json(res,200,{rows,latest:db.prepare('SELECT id,module,title,status,created_at FROM records ORDER BY id DESC LIMIT 8').all()});}
   if(url.pathname==='/api/audit'&&req.method==='GET'){if(!adminOnly(user,res))return;return json(res,200,{rows:db.prepare('SELECT a.id,a.action,a.record_id,a.created_at,u.name FROM audit a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 200').all()});}
   if(url.pathname==='/api/records'&&req.method==='GET'){if(!adminOnly(user,res))return;
    const mod=url.searchParams.get('module');if(!MODULES.has(mod))return json(res,400,{error:'Módulo inválido.'});
    return json(res,200,{rows:db.prepare('SELECT id,module,title,details,status,due_date,created_at,updated_at FROM records WHERE module=? ORDER BY id DESC LIMIT 1000').all(mod)});
   }
   if(url.pathname==='/api/records'&&req.method==='POST'){if(!adminOnly(user,res))return;
    const b=await body(req);if(!MODULES.has(b.module)||typeof b.title!=='string'||!b.title.trim()||b.title.length>180||String(b.details||'').length>10000||String(b.due_date||'').length>10)return json(res,400,{error:'Dados inválidos.'});
    const result=db.prepare('INSERT INTO records(module,title,details,status,due_date,created_by) VALUES(?,?,?,?,?,?)').run(b.module,b.title.trim(),String(b.details||''),'Aberto',String(b.due_date||''),user.user_id);
    log(user.user_id,'create',Number(result.lastInsertRowid));return json(res,201,{id:Number(result.lastInsertRowid)});
   }
   const m=url.pathname.match(/^\/api\/records\/(\d+)$/);
   if(m) {
    if(!adminOnly(user,res))return;
    const id=Number(m[1]);if(!Number.isSafeInteger(id))return json(res,400,{error:'Identificador inválido.'});
    const old=db.prepare('SELECT * FROM records WHERE id=?').get(id);if(!old)return json(res,404,{error:'Registro não encontrado.'});
    if(req.method==='PATCH'){
     const b=await body(req),title=String(b.title??old.title).trim(),details=String(b.details??old.details),status=String(b.status??old.status),due=String(b.due_date??old.due_date);
     if(!title||title.length>180||details.length>10000||!['Aberto','Em andamento','Concluído','Cancelado'].includes(status)||due.length>10)return json(res,400,{error:'Dados inválidos.'});
     db.prepare('UPDATE records SET title=?,details=?,status=?,due_date=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(title,details,status,due,id);log(user.user_id,'update',id);return json(res,200,{ok:true});
    }
    if(req.method==='DELETE'){db.prepare('DELETE FROM records WHERE id=?').run(id);log(user.user_id,'delete',id);return json(res,200,{ok:true});}
   }
   return json(res,404,{error:'Rota não encontrada.'});
  }
  if(url.pathname==='/healthz'&&req.method==='GET')return json(res,200,{status:'ok'});
  if(!['GET','HEAD'].includes(req.method)){res.writeHead(405,{Allow:'GET, HEAD'});return res.end();}
  const path=url.pathname==='/'?'/index.html':url.pathname;
  if(!/^\/(index\.html|css\/style\.css|js\/[0-9]{2}-[a-z-]+\.js)$/.test(path)){res.writeHead(404);return res.end('Não encontrado');}
  const file=join(ROOT,path);if(!existsSync(file)||!statSync(file).isFile()){res.writeHead(404);return res.end('Não encontrado');}
  const data=readFileSync(file);res.writeHead(200,{'Content-Type':MIME[extname(file)],'Cache-Control':'no-store'});return res.end(req.method==='HEAD'?undefined:data);
 } catch(e) {
  if([400,403,409,413,429,502,503].includes(e.status)) return json(res,e.status,{error:e.message});
  console.error('Erro na requisição:',e);
  if(!res.headersSent)json(res,500,{error:'Erro interno do servidor.'});else res.end();
 }
});
server.requestTimeout=30_000;server.headersTimeout=15_000;server.keepAliveTimeout=5_000;
server.on('error',e=>{console.error('Não foi possível iniciar o servidor:',e.message);process.exitCode=1;});
server.listen(PORT,HOST,()=>console.log(`QualiGest disponível em http://${HOST}:${PORT} (abrir a URL e fazer login)`));
function shutdown(signal){console.log(`Encerrando com segurança (${signal})...`);server.close(()=>{db.close();process.exit(0);});setTimeout(()=>process.exit(1),8000).unref();}
process.on('SIGINT',()=>shutdown('SIGINT'));process.on('SIGTERM',()=>shutdown('SIGTERM'));
