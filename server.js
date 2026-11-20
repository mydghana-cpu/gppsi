const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const E=process.env,PORT=E.PORT||3000,MIN=+(E.MIN_RATINGS||30),CYCLE=+(E.CYCLE||1);
const SBU=(E.SUPABASE_URL||'').trim().replace(/\/+$/,''),SBK=(E.SUPABASE_KEY||'').trim(),AU=E.ADMIN_USER||'admin',AP=E.ADMIN_PASSWORD,SALT=E.HASH_SALT||'';
// Arkesel key: strip spaces, line breaks and stray quotes that often get pasted in by mistake
const AK=(E.ARKESEL_API_KEY||'').trim().replace(/^["']+|["']+$/g,'').trim();
// Optional: own codes sent over the normal SMS service with a (sub-)key from Arkesel's SMS API page
const SMSK=(E.SMS_API_KEY||'').trim().replace(/^["']+|["']+$/g,'').trim();
const SMS_KEY=SMSK||AK;
// Limits (override in Render > Environment). IP limits are generous because a whole campus can share one IP address.
const RATE_IP=+(E.RATE_IP_LIMIT||300),OTP_IP=+(E.OTP_IP_LIMIT||200),OTP_CAP=+(E.OTP_DAILY_CAP||1500);
if(!E.PHONE_KEY)console.warn('PHONE_KEY is not set: saved contact numbers are encrypted with HASH_SALT instead. Set a separate PHONE_KEY and back it up.');
const INST=JSON.parse(fs.readFileSync(path.join(__dirname,'institutions.json'),'utf8'));
const ALL=new Set(Object.values(INST).flat());
const GENERIC=new Set(['Metropolitan / Municipal / District Assembly (MMDA)', 'Regional / District Hospital (Ghana Health Service)', 'Polyclinic / CHPS / Health Centre', 'Public Technical / Vocational Institution', 'Ghana Education Service (public schools)'].filter(n=>ALL.has(n)));
const OTP_ON=!!(AK||SMSK),intl=p=>'233'+p.slice(1),RK=E.RESEND_API_KEY,NOTIFY=E.NOTIFY_EMAIL;
const sign=(p,e)=>crypto.createHmac('sha256',SALT+'v').update(p+'|'+e).digest('hex');
const mkTok=p=>{const e=Date.now()+72e5;return p+'|'+e+'|'+sign(p,e)};
const okTok=(t,ph)=>{const[p,e,g]=String(t||'').split('|');return p===ph&&+e>Date.now()&&!!g&&g.length===64&&crypto.timingSafeEqual(Buffer.from(g),Buffer.from(sign(p,e)))};
// Own codes (used when SMS_API_KEY is set): stateless, signed with HASH_SALT, no database needed
const OWN=!!SMS_KEY,OTP_MIN=10;
const osig=(ph,exp,code)=>crypto.createHmac('sha256',SALT+'o').update(ph+'|'+exp+'|'+code).digest('hex');
const mkOtp=(ph,code)=>{const exp=Date.now()+OTP_MIN*6e4;return exp+'.'+osig(ph,exp,code)};
const okOtp=(toks,ph,code)=>String(toks||'').split(',').slice(0,3).some(t=>{const[e,g]=t.split('.');return+e>Date.now()&&!!g&&g.length===64&&crypto.timingSafeEqual(Buffer.from(g),Buffer.from(osig(ph,+e,String(code).trim())))});
async function sendSms(to,msg){try{const u='https://sms.arkesel.com/sms/api?action=send-sms&api_key='+encodeURIComponent(SMS_KEY)+'&to='+to+'&from='+encodeURIComponent(E.ARKESEL_SENDER||'Arkesel')+'&sms='+encodeURIComponent(msg);const r=await fetch(u),t=await r.text();let j={};try{j=JSON.parse(t)}catch{}return{ok:j.code==='ok'||j.status==='success',raw:t.slice(0,300)}}catch(e){return{ok:false,raw:'request failed: '+e.message}}}
// Contacts (only people who tick the opt-in box): number kept encrypted, separate from ratings
const CONTACTS_ON=!!(E.PHONE_KEY||SALT),PKEY=crypto.scryptSync(E.PHONE_KEY||SALT||'x','gpssi-contacts',32);
const cHash=ph=>crypto.createHmac('sha256',SALT+'c').update(ph).digest('hex');
const encPhone=ph=>{const iv=crypto.randomBytes(12),c=crypto.createCipheriv('aes-256-gcm',PKEY,iv),e=Buffer.concat([c.update(ph,'utf8'),c.final()]);return Buffer.concat([iv,c.getAuthTag(),e]).toString('base64')};
const decPhone=t=>{const b=Buffer.from(t,'base64'),d=crypto.createDecipheriv('aes-256-gcm',PKEY,b.subarray(0,12));d.setAuthTag(b.subarray(12,28));return Buffer.concat([d.update(b.subarray(28)),d.final()]).toString('utf8')};
// Arkesel OTP: POST https://sms.arkesel.com/api/otp/generate  and  /api/otp/verify
const ark=(u,o)=>fetch('https://sms.arkesel.com/api/otp/'+u,{method:'POST',headers:{'api-key':AK,'Content-Type':'application/json'},body:JSON.stringify(o)}).then(x=>x.json()).catch(e=>({message:'request failed: '+e.message}));
function notify(t,o){if(!RK||!NOTIFY||t==='ratings'||(t==='complaints'&&!['High','Urgent'].includes(o.priority)))return;
 const m=t==='messages';fetch('https://api.resend.com/emails',{method:'POST',headers:{Authorization:'Bearer '+RK,'Content-Type':'application/json'},body:JSON.stringify({from:'GPSSI <onboarding@resend.dev>',to:[NOTIFY],reply_to:m?o.email:undefined,subject:m?`GPSSI message: ${o.reason||'General'} - ${o.name}`:`GPSSI ${o.priority} complaint: ${o.institution}`,text:m?`From: ${o.name} <${o.email}>\nOrg: ${o.organisation||'-'}\nReason: ${o.reason}\n\n${o.message}`:`${o.institution} (${o.region})\n\n${o.description}\n\nContact: ${o.contact||'none'}`})}).catch(e=>console.error('mail',e.message));}
const REG=['Greater Accra','Ashanti','Western','Western North','Central','Eastern','Volta','Oti','Northern','Savannah','North East','Upper East','Upper West','Bono','Bono East','Ahafo'];
const sb=(p,o={})=>fetch(SBU+'/rest/v1/'+p,{...o,headers:{apikey:SBK,...(SBK.startsWith('eyJ')?{Authorization:'Bearer '+SBK}:{}),'Content-Type':'application/json',...(o.headers||{})}});
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
const hits=new Map(),lastOtp=new Map();let bcast=false;
// Daily cap on verification codes: protects your SMS credit from abuse. Resets at midnight UTC.
let otpDay='',otpN=0;const otpCapped=()=>{const d=new Date().toISOString().slice(0,10);if(d!==otpDay){otpDay=d;otpN=0}return ++otpN>OTP_CAP};
async function afterRate(ph,consent,region,site){if(!consent||!CONTACTS_ON||!SMS_KEY)return;try{
 const hash=cHash(ph),cur=await(await sb('contacts?select=last_sms_at,sms_count&phone_hash=eq.'+hash)).json();
 const up=await sb('contacts?on_conflict=phone_hash',{method:'POST',headers:{Prefer:'resolution=merge-duplicates'},body:JSON.stringify({phone_hash:hash,phone_enc:encPhone(ph),region,opted_out:false})});
 if(!up.ok){console.error('contact save',await up.text());return}
 const c=Array.isArray(cur)?cur[0]:null;if(c&&c.last_sms_at&&Date.now()-Date.parse(c.last_sms_at)<864e5)return;
 const sm=await sendSms(intl(ph),'GPSSI: Thank you for rating a public service. Your voice counts! Rate more at '+site+'  Stop messages: '+site+'/stop');
 if(sm.ok)await sb('contacts?phone_hash=eq.'+hash,{method:'PATCH',body:JSON.stringify({last_sms_at:new Date().toISOString(),sms_count:((c&&c.sms_count)||0)+1})});else console.error('thank-you sms',sm.raw);
}catch(e){console.error('afterRate',e.message)}}
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
const STOP=`<!DOCTYPE html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Stop GPSSI messages</title><style>body{font:16px system-ui;max-width:420px;margin:12vh auto;padding:0 20px;color:#222}h1{font-size:22px}input,button{width:100%;padding:12px;margin-top:10px;font-size:16px;border-radius:8px;border:1px solid #ccc;box-sizing:border-box}button{background:#017E37;color:#fff;border:0;font-weight:700;cursor:pointer}p{color:#555}</style><h1>Stop GPSSI messages</h1><p>Enter the mobile number that receives our messages and we will stop texting it.</p><input id=p type=tel placeholder="024 000 0000"><button onclick="go()">Stop messages</button><p id=m></p><script>function go(){fetch('/api/optout',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({phone:document.getElementById('p').value})}).then(function(r){return r.json()}).then(function(d){document.getElementById('m').textContent=d.error||'Done. We will not text this number again.'})}</script>`;
const ADMIN=`<!DOCTYPE html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>GPSSI Admin</title><style>body{font:14px system-ui;margin:0;background:#f4f7f4}header{background:#004D2B;color:#fff;padding:14px 24px;font-weight:700}main{padding:20px 24px}h2{margin:24px 0 8px}table{width:100%;border-collapse:collapse;background:#fff}td,th{padding:8px 10px;border-bottom:1px solid #e5e5e5;text-align:left;vertical-align:top}th{background:#eef3ef}a{color:#006B3C;font-weight:600}.k{display:inline-block;background:#fff;border:1px solid #ddd;border-radius:8px;padding:10px 16px;margin:0 8px 8px 0}</style><header>GPSSI Admin</header><main><div id=k></div>
<h2>Reminders</h2><div id=rm class=k>Loading...</div><div><textarea id=rmsg rows=3 style="width:100%;max-width:560px"></textarea><br><button id=rbtn>Send to the next 200 eligible contacts</button> <span id=rst></span></div>
<h2>Institution scores</h2><table id=i></table><h2>Complaints <a href="/api/admin/export?t=complaints">CSV</a></h2><table id=c></table><h2>Ratings <a href="/api/admin/export?t=ratings">CSV</a></h2><table id=r></table><h2>Messages <a href="/api/admin/export?t=messages">CSV</a></h2><table id=m></table></main><script>
const e=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const t=(id,h,rows)=>document.getElementById(id).innerHTML='<tr>'+h.map(x=>'<th>'+x+'</th>').join('')+'</tr>'+rows.map(r=>'<tr>'+r.map(x=>'<td>'+e(x)+'</td>').join('')+'</tr>').join('');
rmsg.value='GPSSI: Used a public service lately? Rate it in 1 minute: '+location.origin;
fetch('/api/admin/contacts').then(r=>r.json()).then(c=>{rm.textContent=c.error?c.error:c.on+' opted in ('+c.total+' saved), '+c.eligible+' not messaged in the last 7 days';rbtn.onclick=()=>{if(confirm('Send this SMS to up to 200 eligible contacts? Each message uses SMS credit.'))fetch('/api/admin/broadcast',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message:rmsg.value})}).then(r=>r.json()).then(d=>rst.textContent=d.error||('Sending to '+d.queued+' contacts in the background...'))}});
fetch('/api/admin/data').then(r=>r.json()).then(d=>{k.innerHTML=[['Ratings',d.stats.total],['Complaints',d.complaints.length],['Messages',d.messages.length]].map(x=>'<span class=k><b>'+x[1]+'</b> '+x[0]+'</span>').join('');
t('i',['Institution','Ratings','Score','Tier'],d.stats.institutions.sort((a,b)=>b.score-a.score).map(x=>[x.name,x.n,x.score,x.tier||'collecting']));
t('c',['Time','Institution','Location','Region','Priority','Description','Contact'],d.complaints.map(x=>[new Date(x.created_at).toLocaleString(),x.institution,x.location,x.region,x.priority,x.description,x.contact]));
t('r',['Time','Institution','Location','Region','R','Q','S','Feedback'],d.ratings.map(x=>[new Date(x.created_at).toLocaleString(),x.institution,x.location,x.region,x.responsiveness,x.quality,x.satisfaction,x.feedback]));
t('m',['Time','Name','Email','Reason','Org','Message'],d.messages.map(x=>[new Date(x.created_at).toLocaleString(),x.name,x.email,x.reason,x.organisation,x.message]));});</script>`;
http.createServer(async(req,res)=>{
 const u=new URL(req.url,'http://x'),p=u.pathname,ip=(req.headers['x-forwarded-for']||'').split(',')[0].trim()||req.socket.remoteAddress;
 res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('X-Frame-Options','DENY');res.setHeader('Referrer-Policy','same-origin');
 try{
 if(p==='/'||p==='/index.html'){res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});return res.end(fs.readFileSync(path.join(__dirname,'index.html')));}
 const STATIC={'/manifest.webmanifest':'application/manifest+json','/apple-touch-icon.png':'image/png','/icon-192.png':'image/png','/icon-512.png':'image/png','/icon-maskable-512.png':'image/png','/gpssi-logo.svg':'image/svg+xml'};
 if(STATIC[p]){try{const f=fs.readFileSync(path.join(__dirname,p.slice(1)));res.writeHead(200,{'Content-Type':STATIC[p],'Cache-Control':'public, max-age=86400'});return res.end(f);}catch{res.writeHead(404);return res.end('Not found');}}
 if(p==='/api/institutions')return J(res,200,{categories:INST,regions:REG,min:MIN,otp:OTP_ON,generic:[...GENERIC]});
 if(p==='/api/stats')return J(res,200,await stats());
 if(p==='/api/public/scores.csv'){const d=await stats(),rows=d.institutions.filter(x=>x.ranked).sort((a,b)=>b.score-a.score);
  if(!rows.length){res.writeHead(404,{'Content-Type':'text/plain'});return res.end('No institution has reached the minimum number of ratings yet.');}
  const q=v=>'"'+String(v??'').replace(/"/g,'""')+'"',day=new Date().toISOString().slice(0,10);
  res.writeHead(200,{'Content-Type':'text/csv; charset=utf-8','Content-Disposition':'attachment; filename="gpssi_institution_scores.csv"'});
  return res.end(['institution,ratings,responsiveness,service_quality,satisfaction,score,tier,cycle,generated',...rows.map(x=>[q(x.name),x.n,x.r,x.q,x.s,x.score,x.tier,CYCLE,day].join(','))].join('\n'));}
 if(p==='/admin'){if(!admin(req,res,ip))return;res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});return res.end(ADMIN);}
 if(p==='/api/admin/health'){if(!admin(req,res,ip))return;const o={supabase_url:SBU||'MISSING',key_type:!SBK?'MISSING':SBK.startsWith('eyJ')?'legacy service_role JWT':SBK.startsWith('sb_secret_')?'secret key':SBK.startsWith('sb_publishable_')?'PUBLISHABLE - WRONG, use the secret key':'unknown format',sms_on:OTP_ON,sms_paths:[AK?'arkesel-otp':null,OWN?'own-code-normal-sms':null].filter(Boolean),contacts_on:CONTACTS_ON,phone_key_set:!!E.PHONE_KEY,codes_today:otpN+' of '+OTP_CAP,sms_sender:E.ARKESEL_SENDER||'Arkesel (default)',email_alerts:!!(RK&&NOTIFY),tables:{}};
 for(const t of['ratings','complaints','messages']){try{const r=await sb(t+'?select=id&limit=1');o.tables[t]=r.ok?'OK':r.status+' '+(await r.text()).slice(0,200)}catch(e){o.tables[t]='unreachable: '+e.message}}return J(res,200,o);}
 if(p==='/stop'){res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});return res.end(STOP);}
 if(p==='/api/admin/contacts'){if(!admin(req,res,ip))return;const c=await all('contacts','opted_out,last_sms_at').catch(()=>null);if(!c)return J(res,200,{error:'Contacts table not set up yet.'});const cut=Date.now()-6048e5;return J(res,200,{total:c.length,on:c.filter(x=>!x.opted_out).length,eligible:c.filter(x=>!x.opted_out&&(!x.last_sms_at||Date.parse(x.last_sms_at)<cut)).length});}
 if(p==='/api/admin/broadcast'&&req.method==='POST'){if(!admin(req,res,ip))return;const b=await body(req),site=E.SITE_URL||('https://'+(req.headers.host||''));
  if(bcast)return J(res,409,{error:'A broadcast is already running.'});if(!SMS_KEY||!CONTACTS_ON)return J(res,503,{error:'SMS key or contact storage not set up.'});
  let msg=clean(b.message,300);if(!msg)return J(res,400,{error:'Write a message first.'});if(!msg.includes('/stop'))msg+='  Stop messages: '+site+'/stop';
  const cut=new Date(Date.now()-6048e5).toISOString().slice(0,19)+'Z',rows=await(await sb('contacts?select=phone_hash,phone_enc,sms_count&opted_out=eq.false&or=(last_sms_at.is.null,last_sms_at.lt.'+cut+')&limit=200')).json();
  if(!Array.isArray(rows))return J(res,500,{error:'Could not read contacts.'});bcast=true;J(res,200,{ok:true,queued:rows.length});
  (async()=>{let n=0;for(const r of rows){try{const s=await sendSms(intl(decPhone(r.phone_enc)),msg);if(s.ok){n++;await sb('contacts?phone_hash=eq.'+r.phone_hash,{method:'PATCH',body:JSON.stringify({last_sms_at:new Date().toISOString(),sms_count:(r.sms_count||0)+1})})}else console.error('broadcast sms',s.raw)}catch(e){console.error('broadcast',e.message)}await new Promise(z=>setTimeout(z,300))}console.log('broadcast done',n,'of',rows.length);bcast=false})();return;}
 if(p==='/api/admin/data'){if(!admin(req,res,ip))return;const[ratings,complaints,messages]=await Promise.all([all('ratings','*','&order=id.desc&limit=1000'),all('complaints','*','&order=id.desc'),all('messages','*','&order=id.desc')]);return J(res,200,{stats:await stats(),ratings:ratings.slice(0,200).map(({phone_hash,...x})=>x),complaints,messages});}
 if(p==='/api/admin/export'){if(!admin(req,res,ip))return;const t=['ratings','complaints','messages'].includes(u.searchParams.get('t'))?u.searchParams.get('t'):'ratings';
  const rows=(await all(t,'*','&order=id.asc')).map(({phone_hash,...x})=>x);const h=rows[0]?Object.keys(rows[0]):[];
  const q=v=>'"'+String(v??'').replace(/"/g,'""').replace(/^([=+@-])/,"'$1")+'"';
  res.writeHead(200,{'Content-Type':'text/csv','Content-Disposition':`attachment; filename="gpssi_${t}.csv"`});return res.end([h.join(','),...rows.map(r=>h.map(k=>q(r[k])).join(','))].join('\n'));}
 if(req.method==='POST'&&p.startsWith('/api/')){
  if(!SBU||!SBK)return J(res,503,{error:'Database not configured'});
  const b=await body(req);if(b.hp)return J(res,200,{ok:true});
  const ins=async(t,o,ex,x={},after)=>{const r=await sb(t,{method:'POST',body:JSON.stringify(o),headers:{Prefer:'return=representation'}});if(r.status===409)return J(res,409,{error:ex});if(!r.ok){console.error(await r.text());return J(res,500,{error:'Could not save. Please try again.'});}cache=null;notify(t,o);if(after)after();return J(res,200,{ok:true,id:(await r.json())[0].id,...x});};
  if(p==='/api/optout'){if(limited(ip,'oo',10,36e5))return J(res,429,{error:'Too many requests. Try later.'});const ph=phone(b.phone);if(!ph)return J(res,400,{error:'Enter a valid Ghana mobile number.'});await sb('contacts?phone_hash=eq.'+cHash(ph),{method:'PATCH',body:JSON.stringify({opted_out:true})}).catch(()=>{});return J(res,200,{ok:true});}
  if(p==='/api/otp/send'){const ph=phone(b.phone);if(!OTP_ON||!ph)return J(res,400,{error:'Enter a valid Ghana mobile number.'});
   if(limited(ip,'o',OTP_IP,36e5)||limited(ph,'op',5,36e5))return J(res,429,{error:'Too many codes requested. Try again later.'});
   const wait=40e3-(Date.now()-(lastOtp.get(ph)||0));if(wait>0)return J(res,429,{error:'Please wait '+Math.ceil(wait/1e3)+' seconds before requesting another code.'});
   if(otpCapped())return J(res,429,{error:'Verification is very busy right now. Please try again later or call 024 986 9296.'});
   // Path A: Arkesel OTP service. Path O: our own code sent over normal SMS.
   const A=async()=>{const r=await ark('generate',{expiry:10,length:6,medium:'sms',message:'Your GPSSI verification code is %otp_code%. It expires in 10 minutes.',number:intl(ph),sender_id:E.ARKESEL_SENDER||'Arkesel',type:'numeric'});
    if(r.code==='1000'){lastOtp.set(ph,Date.now());J(res,200,{ok:true,via:'arkesel'});return true;}console.error('arkesel generate',JSON.stringify(r));return null};
   const O=async()=>{const code=String(crypto.randomInt(0,1e6)).padStart(6,'0'),sm=await sendSms(intl(ph),'Your GPSSI code is '+code+'. It is valid for '+OTP_MIN+' minutes. Do not share it.');
    if(sm.ok){lastOtp.set(ph,Date.now());J(res,200,{ok:true,otp:mkOtp(ph,code),via:'own'});return true;}console.error('sms send',sm.raw);return null};
   // first send: Arkesel OTP first, own code as backup. "Send again": own code first, Arkesel as backup. Each falls back to the other if sending fails.
   for(const f of(b.again?[O,A]:[A,O]).filter(f=>f===O?OWN:!!AK)){const o=await f();if(o)return o;}
   return J(res,502,{error:'Could not send the code. Please try again in a moment.'});}
  if(p==='/api/rate'){if(limited(ip,'r',RATE_IP,36e5))return J(res,429,{error:'Too many submissions from this network. Try later.'});
   const ph=phone(b.phone),[r,q,s]=[b.r,b.q,b.s].map(Number);
   if(!ALL.has(b.institution)||!REG.includes(b.region))return J(res,400,{error:'Choose an institution from the list and your region.'});
   if(![r,q,s].every(x=>Number.isInteger(x)&&x>=1&&x<=5))return J(res,400,{error:'Please give all three star ratings.'});
   if(!ph)return J(res,400,{error:'Enter a valid Ghana mobile number, e.g. 024 000 0000.'});
   const hash=crypto.createHmac('sha256',SALT).update(ph).digest('hex');
   const dup=await(await sb(`ratings?select=id&institution=eq.${encodeURIComponent(b.institution)}&phone_hash=eq.${hash}&cycle=eq.${CYCLE}`)).json();
   if(dup.length)return J(res,409,{error:'This number has already rated that institution. Thank you.'});
   let x={};if(OTP_ON&&!okTok(b.token,ph)){if(!b.code)return J(res,400,{error:'Tap "Send verification code" and enter the code from your SMS.',needCode:true});
    if(limited(ph,'ov',8,6e5))return J(res,429,{error:'Too many attempts. Please wait 10 minutes and request a new code.',needCode:true});
    let good=!!(OWN&&b.otp&&okOtp(b.otp,ph,String(b.code).slice(0,8)));
    if(!good&&AK){const vr=await ark('verify',{code:String(b.code).slice(0,8),number:intl(ph)});good=vr.code==='1100';if(!good)console.error('arkesel verify',JSON.stringify(vr));}
    if(!good)return J(res,400,{error:'That code is wrong or has expired.',needCode:true});x={token:mkTok(ph)};}
   return ins('ratings',{cycle:CYCLE,institution:b.institution,region:b.region,responsiveness:r,quality:q,satisfaction:s,feedback:clean(b.feedback,1000),phone_hash:hash,...(GENERIC.has(b.institution)&&clean(b.location,100)?{location:clean(b.location,100)}:{})},'This number has already rated that institution. Thank you.',x,()=>afterRate(ph,b.consent===true,b.region,E.SITE_URL||('https://'+(req.headers.host||''))));}
  if(p==='/api/complaint'){if(limited(ip,'c',10,36e5))return J(res,429,{error:'Too many submissions. Try later.'});
   if(!ALL.has(b.institution)||!REG.includes(b.region)||clean(b.description,2000).length<15)return J(res,400,{error:'Please complete all required fields.'});
   return ins('complaints',{institution:b.institution,region:b.region,priority:['Low','Normal','High','Urgent'].includes(b.priority)?b.priority:'Normal',description:clean(b.description,2000),contact:clean(b.contact,200)||null,incident_date:/^\d{4}-\d\d-\d\d$/.test(b.date||'')?b.date:null,...(GENERIC.has(b.institution)&&clean(b.location,100)?{location:clean(b.location,100)}:{})});}
  if(p==='/api/contact'){if(limited(ip,'m',5,36e5))return J(res,429,{error:'Too many messages. Try later.'});
   if(!clean(b.name,100)||!/^\S+@\S+\.\S+$/.test(b.email||'')||!clean(b.message,3000))return J(res,400,{error:'Please complete all required fields.'});
   return ins('messages',{name:clean(b.name,100),email:clean(b.email,200),reason:clean(b.reason,100),organisation:clean(b.organisation,200),message:clean(b.message,3000)});}}
 res.writeHead(404);res.end('Not found');
 }catch(err){console.error(err);J(res,500,{error:'Server error'});}
}).listen(PORT,'0.0.0.0',()=>console.log('GPSSI on '+PORT));
