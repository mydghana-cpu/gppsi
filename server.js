// GPSSI Backend Server — server.js
// Run locally: node server.js → http://localhost:3000
// Deploy:      push to GitHub → Render auto-deploys

const http = require('http');
const fs   = require('fs');
const path = require('path');
const url  = require('url');

const PORT    = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'gpssi_data.json');

function loadDB() {
  if (!fs.existsSync(DB_FILE)) saveDB({ submissions: [], complaints: [] });
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch(e) { return { submissions: [], complaints: [] }; }
}
function saveDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}
function parseBody(req) {
  return new Promise(resolve => {
    let b = '';
    req.on('data', c => b += c);
    req.on('end', () => { try { resolve(JSON.parse(b)); } catch { resolve({}); } });
  });
}
function getTier(s) {
  if (s >= 90) return 'Gold';
  if (s >= 75) return 'Silver';
  if (s >= 60) return 'Bronze';
  if (s >= 40) return 'Red';
  return 'Black';
}
function computeStats(subs) {
  if (!subs.length) return { count: 0, avg: 0, byInstitution: {}, byRegion: {} };
  const byInst = {}, byRegion = {};
  subs.forEach(s => {
    if (!byInst[s.institution]) byInst[s.institution] = { scores: [], count: 0 };
    byInst[s.institution].scores.push(s.rating * 20);
    byInst[s.institution].count++;
    byRegion[s.region] = (byRegion[s.region] || 0) + 1;
  });
  const byInstitution = {};
  Object.entries(byInst).forEach(([k, v]) => {
    const avg = v.scores.reduce((a,b) => a+b, 0) / v.scores.length;
    byInstitution[k] = { avgScore: Math.round(avg * 10) / 10, count: v.count, tier: getTier(avg) };
  });
  const totalAvg = subs.reduce((a,b) => a + b.rating, 0) / subs.length * 20;
  return { count: subs.length, avg: Math.round(totalAvg * 10) / 10, byInstitution, byRegion };
}

// ── Admin HTML (inline) ──────────────────────────────────
const ADMIN = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>GPSSI Admin</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;600;700&family=Playfair+Display:wght@700&display=swap');
*{box-sizing:border-box;margin:0;padding:0}body{font-family:'DM Sans',sans-serif;background:#F4F7F4;color:#2C3440}
.top{background:#0F1923;color:rgba(255,255,255,.6);padding:10px 32px;font-size:13px;display:flex;justify-content:space-between}
.top strong{color:#FCD116}
nav{background:#fff;border-bottom:1px solid #E0DDD8;padding:14px 32px;display:flex;align-items:center;justify-content:space-between;box-shadow:0 2px 8px rgba(0,0,0,.05)}
.logo{font-family:'Playfair Display',serif;font-size:20px;color:#006B3C;font-weight:700}.logo span{color:#FCD116}
main{max-width:1200px;margin:32px auto;padding:0 32px}
h1{font-family:'Playfair Display',serif;font-size:24px;color:#0F1923;margin-bottom:6px}
.sub{color:#6B7280;font-size:14px;margin-bottom:24px}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:28px}
.stat{background:#fff;border-radius:12px;padding:20px;border:1px solid #E0DDD8}
.sn{font-size:32px;font-weight:700;font-family:'Playfair Display',serif;color:#0F1923}
.sl{font-size:11px;color:#6B7280;text-transform:uppercase;letter-spacing:1px;margin-top:4px}
.card{background:#fff;border-radius:12px;border:1px solid #E0DDD8;margin-bottom:18px;overflow:hidden}
.ch{padding:16px 22px;border-bottom:1px solid #E0DDD8;display:flex;justify-content:space-between;align-items:center}
.ch h2{font-size:14px;font-weight:700}
table{width:100%;border-collapse:collapse}
th{text-align:left;padding:10px 16px;font-size:11px;text-transform:uppercase;letter-spacing:1px;color:#6B7280;background:#F9F9F8;border-bottom:1px solid #E0DDD8}
td{padding:12px 16px;font-size:13px;border-bottom:1px solid #E0DDD8}tr:last-child td{border-bottom:none}tr:hover td{background:#F9F9F8}
.tier{padding:3px 9px;border-radius:99px;font-size:10px;font-weight:700}
.tG{background:#FEF3C7;color:#92400E}.tS{background:#F1F5F9;color:#334155}.tB{background:#FEF9EC;color:#7C3500}.tR{background:#FEE2E2;color:#991B1B}.tK{background:#1F2937;color:#F9FAFB}
.stars{color:#FCD116}.empty{text-align:center;padding:40px;color:#6B7280}
.dl{background:#006B3C;color:#fff;border:none;padding:7px 16px;border-radius:7px;font-size:12px;font-weight:600;cursor:pointer;text-decoration:none;display:inline-block}
.dl:hover{background:#004D2B}
@media(max-width:700px){.stats{grid-template-columns:1fr 1fr}}
</style></head><body>
<div class="top"><span>GPSSI Admin — <strong>MYD Ghana</strong></span><span id="ts"></span></div>
<nav><div class="logo">GPS<span>SI</span> Admin</div><a href="/" style="font-size:13px;color:#006B3C;text-decoration:none">← Back to Site</a></nav>
<main>
  <h1>Live Data Dashboard</h1>
  <p class="sub">All citizen submissions and rankings. Refreshes every 30 seconds.</p>
  <div class="stats">
    <div class="stat"><div class="sn" id="s1">—</div><div class="sl">Total Submissions</div></div>
    <div class="stat"><div class="sn" id="s2">—</div><div class="sl">Avg Score /100</div></div>
    <div class="stat"><div class="sn" id="s3">—</div><div class="sl">Institutions Rated</div></div>
    <div class="stat"><div class="sn" id="s4">—</div><div class="sl">Complaints Filed</div></div>
  </div>
  <div class="card">
    <div class="ch"><h2>📊 Institution Rankings</h2><a class="dl" href="/api/export?type=ratings">⬇ Download CSV</a></div>
    <table><thead><tr><th>#</th><th>Institution</th><th>Score</th><th>Tier</th><th>Responses</th></tr></thead>
    <tbody id="rb"><tr><td colspan="5" class="empty">No ratings yet.</td></tr></tbody></table>
  </div>
  <div class="card">
    <div class="ch"><h2>📝 Submissions (latest 50)</h2></div>
    <table><thead><tr><th>Time</th><th>Institution</th><th>Region</th><th>Rating</th><th>Feedback</th></tr></thead>
    <tbody id="sb"><tr><td colspan="5" class="empty">No submissions yet.</td></tr></tbody></table>
  </div>
  <div class="card">
    <div class="ch"><h2>⚠️ Complaints</h2><a class="dl" href="/api/export?type=complaints">⬇ Download CSV</a></div>
    <table><thead><tr><th>Time</th><th>Institution</th><th>Region</th><th>Priority</th><th>Description</th></tr></thead>
    <tbody id="cb"><tr><td colspan="5" class="empty">No complaints yet.</td></tr></tbody></table>
  </div>
</main>
<script>
document.getElementById('ts').textContent=new Date().toLocaleString();
const tc={Gold:'tG',Silver:'tS',Bronze:'tB',Red:'tR',Black:'tK'};
const stars=n=>'★'.repeat(n)+'☆'.repeat(5-n);
async function load(){
  try{
    const d=await fetch('/api/data').then(r=>r.json());
    document.getElementById('s1').textContent=d.stats.count||0;
    document.getElementById('s2').textContent=d.stats.avg||'—';
    document.getElementById('s3').textContent=Object.keys(d.stats.byInstitution||{}).length;
    document.getElementById('s4').textContent=d.complaints.length;
    const ranks=Object.entries(d.stats.byInstitution||{}).sort((a,b)=>b[1].avgScore-a[1].avgScore);
    document.getElementById('rb').innerHTML=ranks.length?ranks.map(([n,s],i)=>\`<tr><td><strong>#\${i+1}</strong></td><td>\${n}</td><td><strong>\${s.avgScore}</strong></td><td><span class="tier \${tc[s.tier]}">\${s.tier}</span></td><td>\${s.count}</td></tr>\`).join(''):'<tr><td colspan="5" class="empty">No ratings yet.</td></tr>';
    const subs=[...d.submissions].reverse().slice(0,50);
    document.getElementById('sb').innerHTML=subs.length?subs.map(s=>\`<tr><td>\${new Date(s.timestamp).toLocaleString()}</td><td>\${s.institution}</td><td>\${s.region}</td><td class="stars">\${stars(s.rating)}</td><td style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">\${s.feedback||'—'}</td></tr>\`).join(''):'<tr><td colspan="5" class="empty">No submissions yet.</td></tr>';
    const comps=[...d.complaints].reverse().slice(0,50);
    document.getElementById('cb').innerHTML=comps.length?comps.map(c=>\`<tr><td>\${new Date(c.timestamp).toLocaleString()}</td><td>\${c.institution}</td><td>\${c.region}</td><td style="color:red;font-weight:600">\${c.priority}</td><td style="max-width:260px">\${(c.description||'').slice(0,100)}</td></tr>\`).join(''):'<tr><td colspan="5" class="empty">No complaints yet.</td></tr>';
  }catch(e){}
}
load(); setInterval(load,30000);
</script></body></html>`;

// ── HTTP SERVER ──────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const { pathname, query } = url.parse(req.url, true);

  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') { res.writeHead(200); res.end(); return; }

  // ── Serve main site ──
  if (pathname === '/' || pathname === '/index.html') {
    const f = path.join(__dirname, 'index.html');
    if (fs.existsSync(f)) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(fs.readFileSync(f));
    } else {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<h2 style="font-family:sans-serif;padding:40px">GPSSI Server Running ✅<br><a href="/admin">Admin Panel</a></h2>');
    }
    return;
  }

  // ── Admin ──
  if (pathname === '/admin') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(ADMIN);
    return;
  }

  // ── GET all data ──
  if (pathname === '/api/data') {
    const db = loadDB();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ submissions: db.submissions, complaints: db.complaints, stats: computeStats(db.submissions) }));
    return;
  }

  // ── POST rating ──
  if (pathname === '/api/submit' && req.method === 'POST') {
    const b = await parseBody(req);
    if (!b.institution || !b.rating || !b.region) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Missing: institution, rating, region' }));
      return;
    }
    const db = loadDB();
    const entry = {
      id: Date.now(), timestamp: new Date().toISOString(),
      institution: String(b.institution).slice(0,200),
      region: String(b.region).slice(0,100),
      rating: Math.min(5, Math.max(1, parseInt(b.rating) || 3)),
      feedback: String(b.feedback || '').slice(0,1000),
    };
    db.submissions.push(entry);
    saveDB(db);
    console.log('[RATING]', entry.institution, entry.rating+'/5', entry.region);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ success: true, id: entry.id }));
    return;
  }

  // ── POST complaint ──
  if (pathname === '/api/complaint' && req.method === 'POST') {
    const b = await parseBody(req);
    const db = loadDB();
    const comp = {
      id: Date.now(), timestamp: new Date().toISOString(),
      institution: String(b.institution || 'Unknown').slice(0,200),
      region: String(b.region || 'Unknown').slice(0,100),
      description: String(b.description || '').slice(0,2000),
      priority: ['Low','Normal','High','Urgent'].includes(b.priority) ? b.priority : 'Normal',
      contact: String(b.contact || '').slice(0,200),
    };
    db.complaints.push(comp);
    saveDB(db);
    console.log('[COMPLAINT]', comp.institution, 'Priority:', comp.priority);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ success: true, id: comp.id }));
    return;
  }

  // ── Export CSV ──
  if (pathname === '/api/export') {
    const db = loadDB();
    let csv = '';
    if (query.type === 'complaints') {
      csv = 'ID,Timestamp,Institution,Region,Priority,Description\n';
      db.complaints.forEach(c => {
        csv += `${c.id},"${c.timestamp}","${c.institution}","${c.region}","${c.priority}","${(c.description||'').replace(/"/g,'""')}"\n`;
      });
      res.writeHead(200, { 'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename="gpssi_complaints.csv"' });
    } else {
      csv = 'ID,Timestamp,Institution,Region,Rating(1-5),Score(0-100),Feedback\n';
      db.submissions.forEach(s => {
        csv += `${s.id},"${s.timestamp}","${s.institution}","${s.region}",${s.rating},${s.rating*20},"${(s.feedback||'').replace(/"/g,'""')}"\n`;
      });
      res.writeHead(200, { 'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename="gpssi_ratings.csv"' });
    }
    res.end(csv);
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not found');
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n GPSSI Server running → http://localhost:${PORT}`);
  console.log(` Admin panel       → http://localhost:${PORT}/admin\n`);
});
