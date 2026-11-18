import http from 'node:http';
import {readFile} from 'node:fs/promises';
import {randomBytes,randomInt,scryptSync,timingSafeEqual,createHmac} from 'node:crypto';
const salt=process.env.TEACHER_SALT,hash=process.env.TEACHER_HASH,secret=process.env.SESSION_SECRET;
if(!salt||!hash||!secret)throw Error('Configure TEACHER_SALT, TEACHER_HASH e SESSION_SECRET.');
const root=new URL('./',import.meta.url),rooms=new Map(),attempts=new Map();
const sign=s=>createHmac('sha256',secret).update(s).digest('hex');
function auth(req){const raw=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('ic_session='))?.slice(11)||'';const [exp,sig]=raw.split('.');if(!exp||!sig||Date.now()>Number(exp))return false;const expected=sign(exp);return sig.length===expected.length&&timingSafeEqual(Buffer.from(sig),Buffer.from(expected));}
function json(res,status,data){res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});res.end(JSON.stringify(data));}
async function body(req){let text='';for await(const chunk of req){text+=chunk;if(text.length>40000)throw Error('Dados muito grandes.');}return JSON.parse(text||'{}');}
const clean=(s,max)=>typeof s==='string'?s.trim().slice(0,max):'';
function room(code){if(!/^[a-f0-9]{24}$/.test(code))throw Error('Sala inválida.');if(!rooms.has(code)){if(rooms.size>=200)throw Error('Limite de salas.');rooms.set(code,{events:[],listeners:new Set(),updated:Date.now()});}return rooms.get(code);}
function broadcast(r){r.updated=Date.now();for(const out of r.listeners)out.write('data: '+JSON.stringify(r.events)+'\n\n');}
const server=http.createServer(async(req,res)=>{try{
 res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('X-Frame-Options','DENY');res.setHeader('Cache-Control','no-store');res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
 const u=new URL(req.url,'http://localhost');
 if(req.method==='POST'){
  const origin=req.headers.origin;if(origin&&new URL(origin).host!==req.headers.host)return json(res,403,{error:'Origem não autorizada.'});
  if(u.pathname==='/api/login'){
   const ip=req.headers['x-forwarded-for']?.split(',')[0]||req.socket.remoteAddress,now=Date.now();let a=attempts.get(ip);if(!a||now>a.until){a={count:0,until:now+900000};attempts.set(ip,a);}if(++a.count>10)return json(res,429,{error:'Muitas tentativas. Aguarde 15 minutos.'});
   const data=await body(req);const pass=clean(data.password,200);if(!pass||!timingSafeEqual(scryptSync(pass,salt,32),Buffer.from(hash,'hex')))return json(res,401,{error:'Senha incorreta.'});
   attempts.delete(ip);const exp=String(Date.now()+8*3600000);res.setHeader('Set-Cookie',`ic_session=${exp}.${sign(exp)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${process.env.LOCAL_TEST?'':'; Secure'}`);return json(res,200,{ok:true});
  }
  if(!auth(req))return json(res,401,{error:'Entre como professor.'});
  if(u.pathname==='/api/logout'){res.setHeader('Set-Cookie','ic_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');return json(res,200,{ok:true});}
  if(u.pathname==='/api/draw'){
   const data=await body(req),code=clean(data.room,24),team=clean(data.team,100),group=clean(data.group,2),names=data.names;
   if(!team||!['AB','CD'].includes(group)||!Array.isArray(names)||names.length<1||names.length>30||names.some(n=>typeof n!=='string'||!n.trim()||n.length>150)||new Set(names.map(n=>n.trim().toLocaleLowerCase())).size!==names.length)return json(res,400,{error:'Confira turma, equipe e integrantes sem repetição (até 30).'});
   const r=room(code);if(r.events.length>=200)return json(res,400,{error:'Limite de sorteios da sala.'});
   if(r.events.some(e=>e.team===team&&e.group===group)&&data.redraw!==true)return json(res,409,{error:'Esta equipe já tem sorteio. Confirme um novo sorteio.'});
   const event={id:randomBytes(8).toString('hex'),team,group,presenter:names[randomInt(names.length)].trim(),time:new Date().toISOString()};r.events.push(event);broadcast(r);return json(res,200,event);
  }
  if(u.pathname==='/api/restore'){
   const data=await body(req);if(!Array.isArray(data.events)||data.events.length>200)return json(res,400,{error:'Histórico inválido.'});const r=room(clean(data.room,24));
   if(r.events.length)return json(res,409,{error:'A sala já tem resultados. Reabra o link atual.'});
   r.events=data.events.map(e=>({id:clean(e.id,32),team:clean(e.team,100),group:clean(e.group,2),presenter:clean(e.presenter,150),time:clean(e.time,40)}));broadcast(r);return json(res,200,{ok:true});
  }
  return json(res,404,{error:'Recurso indisponível.'});
 }
 if(req.method!=='GET')return json(res,405,{error:'Método indisponível.'});
 if(u.pathname==='/api/health')return json(res,200,{ok:true});
 if(u.pathname==='/api/events'){
  const r=room(u.searchParams.get('room')||'');res.writeHead(200,{'Content-Type':'text/event-stream','Cache-Control':'no-cache','Connection':'keep-alive','X-Accel-Buffering':'no'});res.write('retry: 3000\ndata: '+JSON.stringify(r.events)+'\n\n');r.listeners.add(res);const timer=setInterval(()=>res.write(': keepalive\n\n'),20000);req.on('close',()=>{clearInterval(timer);r.listeners.delete(res);});return;
 }
 if(u.pathname==='/api/session')return json(res,auth(req)?200:401,{ok:auth(req)});
 const file=u.pathname==='/app.js'?'app.js':u.pathname==='/'||u.pathname==='/professor'?'index.html':null;if(!file)return json(res,404,{error:'Não encontrado.'});
 res.setHeader('Content-Type',file.endsWith('.js')?'text/javascript; charset=utf-8':'text/html; charset=utf-8');res.end(await readFile(new URL(file,root)));
 }catch{if(!res.headersSent)json(res,400,{error:'Não foi possível processar. Confira os dados e tente novamente.'});else res.end();}});
setInterval(()=>{for(const [k,r]of rooms)if(!r.listeners.size&&Date.now()-r.updated>86400000)rooms.delete(k);for(const[k,a]of attempts)if(Date.now()>a.until)attempts.delete(k);},60000).unref();
server.listen(Number(process.env.PORT)||3000,'0.0.0.0');
process.on('SIGTERM',()=>{for(const r of rooms.values())for(const c of r.listeners)c.end();server.close(()=>process.exit(0));});
