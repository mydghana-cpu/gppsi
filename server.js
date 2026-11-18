const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const E=process.env,PORT=E.PORT||3000,MIN=+(E.MIN_RATINGS||30),CYCLE=+(E.CYCLE||1);
const SBU=E.SUPABASE_URL,SBK=E.SUPABASE_KEY,AU=E.ADMIN_USER||'admin',AP=E.ADMIN_PASSWORD,SALT=E.HASH_SALT||'';
const INST=JSON.parse(fs.readFileSync(path.join(__dirname,'institutions.json'),'utf8'));
const ALL=new Set(Object.values(INST).flat());
const OTP_ON=!!E.ARKESEL_API_KEY,intl=p=>'233'+p.slice(1),RK=E.RESEND_API_KEY,NOTIFY=E.NOTIFY_EMAIL;
const sign=(p,e)=>crypto.createHmac('sha256',SALT+'v').update(p+'|'+e).digest('hex');
const mkTok=p=>{const e=Date.now()+72e5;return p+'|'+e+'|'+sign(p,e)};
const okTok=(t,ph)=>{const[p,e,g]=String(t||'').split('|');return p===ph&&+e>Date.now()&&!!g&&g.length===64&&crypto.timingSafeEqual(Buffer.from(g),Buffer.from(sign(p,e)))};
const ark=(u,o)=>fetch('https://sms.arkesel.com/api/v2/otp/'+u,{method:'POST',headers:{'api-key':E.ARKESEL_API_KEY,'Content-Type':'application/json'},body:JSON.stringify(o)}).then(x=>x.json()).catch(()=>({}));
function notify(t,o){if(!RK||!NOTIFY||t==='ratings'||(t==='complaints'&&!['High','Urgent'].includes(o.priority)))return;
 const m=t==='messages';fetch('https://api.resend.com/emails',{method:'POST',headers:{Authorization:'Bearer '+RK,'Content-Type':'application/json'},body:JSON.stringify({from:'GPSSI <onboarding@resend.dev>',to:[NOTIFY],reply_to:m?o.email:undefined,subject:m?`GPSSI message: ${o.reason||'General'} - ${o.name}`:`GPSSI ${o.priority} complaint: ${o.institution}`,text:m?`From: ${o.name} <${o.email}>\nOrg: ${o.organisation||'-'}\nReason: ${o.reason}\n\n${o.message}`:`${o.institution} (${o.region})\n\n${o.description}\n\nContact: ${o.contact||'none'}`})}).catch(e=>console.error('mail',e.message));}
const REG=['Greater Accra','Ashanti','Western','Western North','Central','Eastern','Volta','Oti','Northern','Savannah','North East','Upper East','Upper West','Bono','Bono East','Ahafo'];
const sb=(p,o={})=>fetch(SBU+'/rest/v1/'+p,{...o,headers:{apikey:SBK,Authorization:'Bearer '+SBK,'Content-Type':'application/json',...(o.headers||{})}});
async function all(t,cols,extra=''){let out=[],i=0;for(;;){const r=await sb(`${t}?select=${cols}${extra}`,{headers:{Range:`${i}-${i+999}`}});if(!r.ok)throw new Error(await r.text());const d=await r.json();out=out.concat(d);if(d.length<1000)return out;i+=1000;}}
const tier=s=>s>=90?'Gold':s>=75?'Silver':s>=60?'Bronze':s>=40?'Red':'Critical';
let cache=null,cat=0;
async function stats(){if(cache&&Date.now()-cat<30000)return cache;
 const rs=await all('ratings','institution,responsiveness,quality,satisfaction',`&cycle=eq.${CYCLE}`);
 const cs=await sb('complaints?select=id',{method:'HEAD',headers:{Prefer:'count=exact'}});
 const m={};rs.forEach(x=>{const a=m[x.institution]||(m[x.institution]={n:0,r:0,q:0,s:0});a.n++;a.r+=x.responsiveness;a.q+=x.quality;a.s+=x.satisfaction;});
 const institutions=Object.entries(m).map(([name,a])=>{const r=a.r/a.n*20,q=a.q/a.n*20,s=a.s/a.n*20,score=Math.round((.4*r+.4*q+.2*s)*10)/10;
  return{name,n:a.n,r:Math.round(r),q:Math.round(q),s:Math.round(s),score,ranked:a.n>=MIN,tier:a.n>=MIN?tier(score):null};});
 cache={total:rs.length,min:MIN,complaints:+((cs.headers.get('content-range')||'/0').split('/')[1])||0,institutions};cat=Date.now();return cache;}
const hits=new Map();
function limited(ip,k,max,win){const key=k+ip,now=Date.now(),a=(hits.get(key)||[]).filter(t=>now-t<win);a.push(now);hits.set(key,a);return a.length>max;}
setInterval(()=>{const n=Date.now();for(const[k,a]of hits){if(!a.length||n-a[a.length-1]>36e5)hits.delete(k);}},6e5);
function body(req){return new Promise(r=>{let b='';req.on('data',c=>{b+=c;if(b.length>2e4)req.destroy();});req.on('end',()=>{try{r(JSON.parse(b))}catch{r({})}});});}
const J=(res,c,o)=>{res.writeHead(c,{'Content-Type':'application/json'});res.end(JSON.stringify(o));};
const clean=(s,n)=>String(s||'').replace(/[\u0000-\u001f]/g,' ').trim().slice(0,n);
const phone=p=>{let d=String(p||'').replace(/\D/g,'');if(d.startsWith('233'))d='0'+d.slice(3);return/^0(2\d|5\d)\d{7}$/.test(d)?d:null;};
function admin(req,res,ip){if(!AP){J(res,503,{error:'ADMIN_PASSWORD not set'});return false;}
 if(limited(ip,'af',10,9e5)){J(res,429,{error:'Too many attempts'});return false;}
 const[u,...p]=Buffer.from((req.headers.authorization||'').slice(6),'base64').toString().split(':');
 const ok=(a,b)=>a.length===b.length&&crypto.timingSafeEqual(Buffer.from(a),Buffer.from(b));
 if(u&&ok(u,AU)&&ok(p.join(':'),AP)){hits.delete('af'+ip);return true;}
 res.writeHead(401,{'WWW-Authenticate':'Basic realm="GPSSI Admin"'});res.end('Login required');return false;}
const ADMIN=`<!DOCTYPE html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>GPSSI Admin</title><style>body{font:14px system-ui;margin:0;background:#f4f7f4}header{background:#004D2B;color:#fff;padding:14px 24px;font-weight:700}main{padding:20px 24px}h2{margin:24px 0 8px}table{width:100%;border-collapse:collapse;background:#fff}td,th{padding:8px 10px;border-bottom:1px solid #e5e5e5;text-align:left;vertical-align:top}th{background:#eef3ef}a{color:#006B3C;font-weight:600}.k{display:inline-block;background:#fff;border:1px solid #ddd;border-radius:8px;padding:10px 16px;margin:0 8px 8px 0}</style><header>GPSSI Admin</header><main><div id=k></div>
<h2>Institution scores</h2><table id=i></table><h2>Complaints <a href="/api/admin/export?t=complaints">CSV</a></h2><table id=c></table><h2>Ratings <a href="/api/admin/export?t=ratings">CSV</a></h2><table id=r></table><h2>Messages <a href="/api/admin/export?t=messages">CSV</a></h2><table id=m></table></main><script>
const e=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const t=(id,h,rows)=>document.getElementById(id).innerHTML='<tr>'+h.map(x=>'<th>'+x+'</th>').join('')+'</tr>'+rows.map(r=>'<tr>'+r.map(x=>'<td>'+e(x)+'</td>').join('')+'</tr>').join('');
fetch('/api/admin/data').then(r=>r.json()).then(d=>{k.innerHTML=[['Ratings',d.stats.total],['Complaints',d.complaints.length],['Messages',d.messages.length]].map(x=>'<span class=k><b>'+x[1]+'</b> '+x[0]+'</span>').join('');
t('i',['Institution','Ratings','Score','Tier'],d.stats.institutions.sort((a,b)=>b.score-a.score).map(x=>[x.name,x.n,x.score,x.tier||'collecting']));
t('c',['Time','Institution','Region','Priority','Description','Contact'],d.complaints.map(x=>[new Date(x.created_at).toLocaleString(),x.institution,x.region,x.priority,x.description,x.contact]));
t('r',['Time','Institution','Region','R','Q','S','Feedback'],d.ratings.map(x=>[new Date(x.created_at).toLocaleString(),x.institution,x.region,x.responsiveness,x.quality,x.satisfaction,x.feedback]));
t('m',['Time','Name','Email','Reason','Org','Message'],d.messages.map(x=>[new Date(x.created_at).toLocaleString(),x.name,x.email,x.reason,x.organisation,x.message]));});</script>`;
http.createServer(async(req,res)=>{
 const u=new URL(req.url,'http://x'),p=u.pathname,ip=(req.headers['x-forwarded-for']||'').split(',')[0].trim()||req.socket.remoteAddress;
 res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('X-Frame-Options','DENY');res.setHeader('Referrer-Policy','same-origin');
 try{
 if(p==='/'||p==='/index.html'){res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});return res.end(fs.readFileSync(path.join(__dirname,'index.html')));}
 if(p==='/api/institutions')return J(res,200,{categories:INST,regions:REG,min:MIN,otp:OTP_ON});
 if(p==='/api/stats')return J(res,200,await stats());
 if(p==='/admin'){if(!admin(req,res,ip))return;res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});return res.end(ADMIN);}
 if(p==='/api/admin/data'){if(!admin(req,res,ip))return;const[ratings,complaints,messages]=await Promise.all([all('ratings','*','&order=id.desc&limit=1000'),all('complaints','*','&order=id.desc'),all('messages','*','&order=id.desc')]);return J(res,200,{stats:await stats(),ratings:ratings.slice(0,200).map(({phone_hash,...x})=>x),complaints,messages});}
 if(p==='/api/admin/export'){if(!admin(req,res,ip))return;const t=['ratings','complaints','messages'].includes(u.searchParams.get('t'))?u.searchParams.get('t'):'ratings';
  const rows=(await all(t,'*','&order=id.asc')).map(({phone_hash,...x})=>x);const h=rows[0]?Object.keys(rows[0]):[];
  const q=v=>'"'+String(v??'').replace(/"/g,'""').replace(/^([=+@-])/,"'$1")+'"';
  res.writeHead(200,{'Content-Type':'text/csv','Content-Disposition':`attachment; filename="gpssi_${t}.csv"`});return res.end([h.join(','),...rows.map(r=>h.map(k=>q(r[k])).join(','))].join('\n'));}
 if(req.method==='POST'&&p.startsWith('/api/')){
  if(!SBU||!SBK)return J(res,503,{error:'Database not configured'});
  const b=await body(req);if(b.hp)return J(res,200,{ok:true});
  const ins=async(t,o,ex,x={})=>{const r=await sb(t,{method:'POST',body:JSON.stringify(o),headers:{Prefer:'return=representation'}});if(r.status===409)return J(res,409,{error:ex});if(!r.ok){console.error(await r.text());return J(res,500,{error:'Could not save. Please try again.'});}cache=null;notify(t,o);return J(res,200,{ok:true,id:(await r.json())[0].id,...x});};
  if(p==='/api/otp/send'){const ph=phone(b.phone);if(!OTP_ON||!ph)return J(res,400,{error:'Enter a valid Ghana mobile number.'});
   if(limited(ip,'o',15,36e5)||limited(ph,'op',3,36e5))return J(res,429,{error:'Too many codes requested. Try again later.'});
   const r=await ark('send',{expiry:5,length:6,medium:'sms',message:'Your GPSSI verification code is %otp_code%. It expires in 5 minutes.',number:intl(ph),sender_id:E.ARKESEL_SENDER||'GPSSI',type:'numeric'});
   if(r.code==='1000')return J(res,200,{ok:true});console.error('arkesel',r);return J(res,502,{error:'Could not send the code. Try again shortly.'});}
  if(p==='/api/rate'){if(limited(ip,'r',40,36e5))return J(res,429,{error:'Too many submissions from this network. Try later.'});
   const ph=phone(b.phone),[r,q,s]=[b.r,b.q,b.s].map(Number);
   if(!ALL.has(b.institution)||!REG.includes(b.region))return J(res,400,{error:'Choose an institution from the list and your region.'});
   if(![r,q,s].every(x=>Number.isInteger(x)&&x>=1&&x<=5))return J(res,400,{error:'Please give all three star ratings.'});
   if(!ph)return J(res,400,{error:'Enter a valid Ghana mobile number, e.g. 024 000 0000.'});
   const hash=crypto.createHmac('sha256',SALT).update(ph).digest('hex');
   const dup=await(await sb(`ratings?select=id&institution=eq.${encodeURIComponent(b.institution)}&phone_hash=eq.${hash}&cycle=eq.${CYCLE}`)).json();
   if(dup.length)return J(res,409,{error:'This number has already rated that institution. Thank you.'});
   let x={};if(OTP_ON&&!okTok(b.token,ph)){if(!b.code)return J(res,400,{error:'Tap "Send code" and enter the code from your SMS.',needCode:true});
    const v=await ark('verify',{code:String(b.code).slice(0,8),number:intl(ph)});if(v.code!=='1100')return J(res,400,{error:'That code is wrong or has expired.',needCode:true});x={token:mkTok(ph)};}
   return ins('ratings',{cycle:CYCLE,institution:b.institution,region:b.region,responsiveness:r,quality:q,satisfaction:s,feedback:clean(b.feedback,1000),phone_hash:hash},'This number has already rated that institution. Thank you.',x);}
  if(p==='/api/complaint'){if(limited(ip,'c',10,36e5))return J(res,429,{error:'Too many submissions. Try later.'});
   if(!ALL.has(b.institution)||!REG.includes(b.region)||clean(b.description,2000).length<15)return J(res,400,{error:'Please complete all required fields.'});
   return ins('complaints',{institution:b.institution,region:b.region,priority:['Low','Normal','High','Urgent'].includes(b.priority)?b.priority:'Normal',description:clean(b.description,2000),contact:clean(b.contact,200)||null,incident_date:/^\d{4}-\d\d-\d\d$/.test(b.date||'')?b.date:null});}
  if(p==='/api/contact'){if(limited(ip,'m',5,36e5))return J(res,429,{error:'Too many messages. Try later.'});
   if(!clean(b.name,100)||!/^\S+@\S+\.\S+$/.test(b.email||'')||!clean(b.message,3000))return J(res,400,{error:'Please complete all required fields.'});
   return ins('messages',{name:clean(b.name,100),email:clean(b.email,200),reason:clean(b.reason,100),organisation:clean(b.organisation,200),message:clean(b.message,3000)});}}
 res.writeHead(404);res.end('Not found');
 }catch(err){console.error(err);J(res,500,{error:'Server error'});}
}).listen(PORT,'0.0.0.0',()=>console.log('GPSSI on '+PORT));
