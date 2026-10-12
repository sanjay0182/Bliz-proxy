// Proxy Hub: fetch lists -> check 24x7 -> API + dashboard. Persists in Blitz SQL. Zero deps (Node 20+).
const http = require('http'), net = require('net'), crypto = require('crypto');
const E = process.env, PORT = +E.PORT || 3000, DB = (E.DB_URL || '').replace(/\/$/, ''), PASS = E.ADMIN_PASSWORD || 'change-me';
const SIG = k => crypto.createHmac('sha256', PASS).update(k).digest('hex');
let CONC = +E.CONCURRENCY || 2000, INT = +E.FETCH_MINUTES || 5, TMO = +E.TIMEOUT_MS || 6000;
const P = new Map(), DEL = new Set(), KEYS = new Map(); let SRC = []; const ST = { checked: 0, t0: Date.now(), lastFetch: 0 };

// ---------- DB ----------
async function post(path, body) {
  if (!DB) return {};
  try { const r = await fetch(DB + path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }); return await r.json(); }
  catch (e) { console.log('db err', e.message); return {}; }
}
const q = (sql, params = []) => post('/sql', { sql, params });
const rows = j => {
  let r = Array.isArray(j) ? j : j.rows || j.data || j.result || (j.results && j.results[0] && (j.results[0].rows || j.results[0])) || [];
  if (!Array.isArray(r)) r = r.rows || [];
  const cols = j.columns || (j.results && j.results[0] && j.results[0].columns);
  return r.map(x => Array.isArray(x) && cols ? Object.fromEntries(cols.map((c, i) => [c.name || c, x[i]])) : x);
};
const batch = async a => {  // try {"batch":[...]}; if DB rejects it, fall back to one-by-one
  const j = await post('/sql', { batch: a.map(([sql, params]) => ({ sql, params })) });
  if (j && j.error) { console.log('batch failed, sequential fallback:', String(j.error).slice(0, 80)); for (const [sql, params] of a) await q(sql, params); }
};
const SCHEMA = `CREATE TABLE IF NOT EXISTS proxies(addr TEXT PRIMARY KEY,t TEXT,s TEXT,ms INTEGER,chk INTEGER,seen INTEGER);
CREATE TABLE IF NOT EXISTS sources(url TEXT PRIMARY KEY,name TEXT,t TEXT,enabled INTEGER);
CREATE TABLE IF NOT EXISTS keys(k TEXT PRIMARY KEY,label TEXT,created INTEGER,hits INTEGER);
CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY,v TEXT);`;
const R = 'https://raw.githubusercontent.com/';
const DEFAULT_SRC = [
  ['TheSpeedX http', R + 'TheSpeedX/PROXY-List/master/http.txt', 'http'],
  ['TheSpeedX socks4', R + 'TheSpeedX/PROXY-List/master/socks4.txt', 'socks4'],
  ['TheSpeedX socks5', R + 'TheSpeedX/PROXY-List/master/socks5.txt', 'socks5'],
  ['clarketm http', R + 'clarketm/proxy-list/master/proxy-list-raw.txt', 'http'],
  ['ShiftyTR http', R + 'ShiftyTR/Proxy-List/master/http.txt', 'http'],
  ['ShiftyTR socks4', R + 'ShiftyTR/Proxy-List/master/socks4.txt', 'socks4'],
  ['ShiftyTR socks5', R + 'ShiftyTR/Proxy-List/master/socks5.txt', 'socks5'],
  ['proxifly all', R + 'proxifly/free-proxy-list/main/proxies/all/data.txt', 'http'],
  ['VPSLab http', R + 'VPSLabCloud/VPSLab-Free-Proxy-List/main/http_all.txt', 'http'],
  ['VPSLab socks4', R + 'VPSLabCloud/VPSLab-Free-Proxy-List/main/socks4_all.txt', 'socks4'],
  ['VPSLab socks5', R + 'VPSLabCloud/VPSLab-Free-Proxy-List/main/socks5_all.txt', 'socks5'],
];
async function load() {
  await post('/sql', { script: SCHEMA });
  await q('DELETE FROM sources WHERE url=?', [R + 'VPSLabCloud/VPSLab-Free-Proxy-List/main/http.txt']);
  if (!rows(await q('SELECT url FROM sources')).length) for (const [name, url, t] of DEFAULT_SRC) await q('INSERT OR IGNORE INTO sources VALUES(?,?,?,1)', [url, name, t]);
  SRC = rows(await q('SELECT * FROM sources')).map(r => ({ ...r, n: 0 }));
  if (!SRC.length) SRC = DEFAULT_SRC.map(([name, url, t]) => ({ name, url, t, enabled: 1, n: 0 }));
  rows(await q('SELECT * FROM keys')).forEach(r => KEYS.set(r.k, r));
  if (!KEYS.size) newKey('default');
  for (const r of rows(await q('SELECT k,v FROM settings'))) { if (r.k === 'conc') CONC = +r.v; if (r.k === 'int') INT = +r.v; }
  for (const r of rows(await q('SELECT * FROM proxies'))) P.set(r.addr, { a: r.addr, t: r.t, s: r.s, alive: 1, ms: r.ms, chk: 0, fail: 0, seen: r.seen, dirty: 0 });
  console.log('loaded', P.size, 'proxies,', SRC.length, 'sources,', KEYS.size, 'keys');
}
function newKey(label) { const k = crypto.randomBytes(9).toString('hex'), o = { k, label, created: Date.now(), hits: 0 }; KEYS.set(k, o); q('INSERT INTO keys VALUES(?,?,?,0)', [k, label, o.created]); return o; }
async function flush() {
  const ops = [];
  for (const p of P.values()) if (p.dirty && p.alive) { ops.push(['INSERT OR REPLACE INTO proxies VALUES(?,?,?,?,?,?)', [p.a, p.t, p.s, p.ms, p.chk, p.seen]]); p.dirty = 0; }
  for (const a of DEL) ops.push(['DELETE FROM proxies WHERE addr=?', [a]]); DEL.clear();
  for (const k of KEYS.values()) if (k.hd) { ops.push(['UPDATE keys SET hits=? WHERE k=?', [k.hits, k.k]]); k.hd = 0; }
  for (let i = 0; i < ops.length; i += 100) await batch(ops.slice(i, i + 100));
}

// ---------- fetch sources ----------
const RE = /(?:([a-z0-9]+):\/\/)?(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})/gi;
const WORKER = E.WORKER_SCAN_URL || 'https://cloudflre-proxy.rambhai72hacker.workers.dev/scan?key=jaat';
async function pingWorker() {  // triggers your Cloudflare worker scan; it replies e.g. {"note":"scan already running"}
  if (!WORKER) return;
  try { const t = await (await fetch(WORKER, { signal: AbortSignal.timeout(20000) })).text(); ST.worker = t.slice(0, 120); }
  catch (e) { ST.worker = 'err: ' + e.message; }
}
async function fetchAll() {
  ST.lastFetch = Date.now(); let added = 0; pingWorker();
  await Promise.all(SRC.filter(s => s.enabled).map(async s => {
    try {
      const txt = await (await fetch(s.url, { signal: AbortSignal.timeout(30000) })).text(); let n = 0, m; RE.lastIndex = 0;
      while ((m = RE.exec(txt))) {
        let t = (m[1] || s.t).toLowerCase(); if (t === 'https') t = 'http'; if (!['http', 'socks4', 'socks5'].includes(t)) continue;
        const a = m[2] + ':' + m[3] + (t === 'http' ? '' : ''), key = t + '|' + a; n++;
        if (!P.has(key)) { P.set(key, { a, key, t, s: s.name, alive: 0, ms: 0, chk: 0, fail: 0, seen: Date.now(), dirty: 0 }); added++; }
      }
      s.n = n; s.err = '';
    } catch (e) { s.err = e.message; }
  }));
  console.log('fetch done, new:', added, 'total:', P.size);
}
// loaded-from-DB rows have no .key; normalise
function fixKeys() { for (const [k, p] of [...P]) if (!k.includes('|')) { P.delete(k); p.key = p.t + '|' + p.a; P.set(p.key, p); } }

// ---------- checker ----------
function check(p) {
  return new Promise(res => {
    const [h, pt] = p.a.split(':'), t0 = Date.now(); let done = 0, st = 0;
    const s = net.connect({ host: h, port: +pt, timeout: TMO });
    const end = ok => { if (done) return; done = 1; s.destroy(); res(ok ? Date.now() - t0 : 0); };
    s.on('timeout', () => end(0)).on('error', () => end(0)).on('close', () => end(0));
    s.on('connect', () => {
      if (p.t === 'http') s.write('GET http://neverssl.com/ HTTP/1.1\r\nHost: neverssl.com\r\nConnection: close\r\n\r\n');
      else if (p.t === 'socks4') s.write(Buffer.from([4, 1, 0, 80, 1, 1, 1, 1, 0]));
      else s.write(Buffer.from([5, 1, 0]));
    });
    s.on('data', d => {
      if (p.t === 'http') return end(/^HTTP\/1\.[01] [23]\d\d/.test(d.toString('latin1', 0, 14)));
      if (p.t === 'socks4') return end(d[1] === 0x5a);
      if (st === 0) { if (d[0] !== 5 || d[1] !== 0) return end(0); st = 1; s.write(Buffer.from([5, 1, 0, 1, 1, 1, 1, 1, 0, 80])); }
      else end(d[0] === 5 && d[1] === 0);
    });
  });
}
async function checkLoop() {
  for (;;) {
    const cut = Date.now() - 30000;
    const todo = [...P.values()].filter(p => p.chk < cut).sort((a, b) => a.chk - b.chk).slice(0, CONC);
    if (!todo.length) { await new Promise(r => setTimeout(r, 5000)); continue; }
    await Promise.all(todo.map(async p => {
      const ms = await check(p); p.chk = Date.now(); ST.checked++; p.dirty = 1;
      if (ms) { p.alive = 1; p.ms = ms; p.fail = 0; } else { p.fail++; if (p.alive && p.fail >= 2) { p.alive = 0; DEL.add(p.a); } if (p.fail >= 4) P.delete(p.key); }
    }));
  }
}

// ---------- http ----------
const body = req => new Promise(r => { let b = ''; req.on('data', d => b += d); req.on('end', () => { try { r(JSON.parse(b || '{}')); } catch { r({}); } }); });
const J = (res, o, c = 200) => { res.writeHead(c, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)); };
const authed = req => { const m = /sid=([a-f0-9]+)/.exec(req.headers.cookie || ''); return m && m[1] === SIG('admin'); };
const alive = () => [...P.values()].filter(p => p.alive);
const fmt = p => p.t + '://' + p.a;

http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://x'), path = u.pathname;
  if (path === '/health') return J(res, { ok: 1, alive: alive().length });
  if (path === '/api/proxies') {
    const k = KEYS.get(u.searchParams.get('key')); if (!k) return J(res, { error: 'bad key' }, 401);
    k.hits++; k.hd = 1;
    const t = u.searchParams.get('type'), lim = +u.searchParams.get('limit') || 100;
    const l = alive().filter(p => !t || p.t === t).sort((a, b) => a.ms - b.ms).slice(0, lim);
    if (u.searchParams.get('format') === 'json') return J(res, l.map(p => ({ proxy: p.a, type: p.t, ms: p.ms, source: p.s })));
    res.writeHead(200, { 'content-type': 'text/plain' }); return res.end(l.map(p => t ? p.a : fmt(p)).join('\n'));
  }
  if (path === '/login' && req.method === 'POST') {
    const b = await body(req);
    if (b.password === PASS) { res.setHeader('set-cookie', `sid=${SIG('admin')}; HttpOnly; Path=/; Max-Age=2592000; SameSite=Lax`); return J(res, { ok: 1 }); }
    return J(res, { error: 'wrong' }, 401);
  }
  if (path === '/') { res.writeHead(200, { 'content-type': 'text/html' }); return res.end(authed(req) ? DASH : LOGIN); }
  if (!path.startsWith('/admin/') || !authed(req)) return J(res, { error: 'auth' }, 401);
  const b = req.method === 'POST' ? await body(req) : {};
  if (path === '/admin/state') {
    const a = alive(), by = t => ({ alive: a.filter(p => p.t === t).length, total: [...P.values()].filter(p => p.t === t).length });
    return J(res, { http: by('http'), socks4: by('socks4'), socks5: by('socks5'), total: P.size, alive: a.length, checked: ST.checked, perMin: Math.round(ST.checked / ((Date.now() - ST.t0) / 60000)), lastFetch: ST.lastFetch, worker: ST.worker || '-', conc: CONC, int: INT, src: SRC, keys: [...KEYS.values()], top: a.sort((x, y) => x.ms - y.ms).slice(0, 40).map(p => ({ p: fmt(p), ms: p.ms, s: p.s })) });
  }
  if (path === '/admin/key') { if (b.del) { KEYS.delete(b.del); q('DELETE FROM keys WHERE k=?', [b.del]); } else newKey(b.label || 'key'); return J(res, { ok: 1 }); }
  if (path === '/admin/source') {
    if (b.del) { SRC = SRC.filter(s => s.url !== b.del); q('DELETE FROM sources WHERE url=?', [b.del]); }
    else if (/^https?:\/\//.test(b.url || '')) { SRC.push({ name: b.name || b.url.slice(8, 40), url: b.url, t: b.t || 'http', enabled: 1, n: 0 }); q('INSERT OR REPLACE INTO sources VALUES(?,?,?,1)', [b.url, b.name || b.url.slice(8, 40), b.t || 'http']); }
    return J(res, { ok: 1 });
  }
  if (path === '/admin/fetch') { fetchAll(); return J(res, { ok: 1 }); }
  if (path === '/admin/settings') {
    if (b.conc) { CONC = Math.min(10000, Math.max(100, +b.conc)); q('INSERT OR REPLACE INTO settings VALUES(?,?)', ['conc', String(CONC)]); }
    if (b.int) { INT = Math.max(1, +b.int); q('INSERT OR REPLACE INTO settings VALUES(?,?)', ['int', String(INT)]); }
    return J(res, { ok: 1 });
  }
  if (path === '/admin/backup') { res.writeHead(200, { 'content-type': 'application/json', 'content-disposition': 'attachment; filename=proxyhub-backup.json' }); return res.end(JSON.stringify({ sources: SRC, keys: [...KEYS.values()], proxies: alive().map(p => ({ a: p.a, t: p.t, s: p.s, ms: p.ms })) })); }
  if (path === '/admin/restore') {
    (b.sources || []).forEach(s => { if (!SRC.find(x => x.url === s.url)) { SRC.push({ ...s, n: 0 }); q('INSERT OR IGNORE INTO sources VALUES(?,?,?,1)', [s.url, s.name, s.t]); } });
    (b.keys || []).forEach(k => { if (!KEYS.has(k.k)) { KEYS.set(k.k, k); q('INSERT OR IGNORE INTO keys VALUES(?,?,?,?)', [k.k, k.label, k.created, k.hits || 0]); } });
    (b.proxies || []).forEach(p => { const key = p.t + '|' + p.a; if (!P.has(key)) P.set(key, { ...p, key, alive: 0, chk: 0, fail: 0, seen: Date.now(), dirty: 0 }); });
    return J(res, { ok: 1 });
  }
  J(res, { error: 'nf' }, 404);
}).listen(PORT, () => console.log('port', PORT));

(async () => {
  await load(); fixKeys();
  let last = 0; setInterval(() => { if (Date.now() - last >= INT * 60000) { last = Date.now(); fetchAll(); } }, 10000);
  setInterval(flush, 60000); checkLoop();
  process.on('SIGTERM', async () => { await flush(); process.exit(0); });
})();

// ---------- UI ----------
const CSS = `<meta name=viewport content="width=device-width,initial-scale=1"><style>:root{color-scheme:dark}body{margin:0;font:14px system-ui;background:#0e1116;color:#e6e8eb;padding:12px;max-width:900px;margin:auto}h2{font-size:15px;margin:18px 0 8px;color:#8ab4ff}.g{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:8px}.c{background:#171b22;border-radius:10px;padding:10px}.c b{display:block;font-size:20px}input,select,button{background:#1f2530;color:#e6e8eb;border:1px solid #2d3542;border-radius:8px;padding:8px;font:inherit}button{background:#2d5bd6;border:0;cursor:pointer}button.x{background:#7a2a2a;padding:4px 8px}.r{display:flex;gap:6px;align-items:center;padding:6px 0;border-bottom:1px solid #222;word-break:break-all;flex-wrap:wrap}.r span{flex:1}small{color:#8b95a5}</style>`;
const LOGIN = `<!doctype html>${CSS}<h2>Proxy Hub</h2><input id=p type=password placeholder=Password><button onclick="fetch('/login',{method:'POST',body:JSON.stringify({password:p.value})}).then(r=>r.ok?location.reload():alert('Wrong'))">Login</button>`;
const DASH = `<!doctype html>${CSS}<h2>Proxy Hub</h2><div class=g id=st></div>
<h2>API keys</h2><div class=r><input id=kl placeholder="label"><button onclick="A('key',{label:kl.value})">New key</button></div><div id=keys></div>
<h2>Sources</h2><div class=r><input id=sn placeholder=name><input id=su placeholder="raw url" style="flex:1"><select id=stt><option>http<option>socks4<option>socks5</select><button onclick="A('source',{name:sn.value,url:su.value,t:stt.value})">Add</button></div><div id=src></div>
<h2>Settings</h2><div class=r>Concurrent checks <input id=cc size=5> Fetch every (min) <input id=ii size=3><button onclick="A('settings',{conc:cc.value,int:ii.value})">Save</button><button onclick="A('fetch')">Fetch now</button></div>
<h2>Backup</h2><div class=r><a href=/admin/backup><button>Download</button></a><input type=file id=rf onchange="rf.files[0].text().then(t=>A('restore',JSON.parse(t)))"></div>
<h2>Fastest alive</h2><div id=top></div>
<script>const A=(p,b)=>fetch('/admin/'+p,{method:'POST',body:JSON.stringify(b||{})}).then(L);
const O=location.origin;
function L(){fetch('/admin/state').then(r=>r.json()).then(s=>{
st.innerHTML=[['Alive',s.alive+'/'+s.total],['HTTP',s.http.alive],['SOCKS4',s.socks4.alive],['SOCKS5',s.socks5.alive],['Checked',s.checked],['Per min',s.perMin],['Worker',s.worker]].map(x=>'<div class=c><small>'+x[0]+'</small><b>'+x[1]+'</b></div>').join('');
keys.innerHTML=s.keys.map(k=>'<div class=r><span><b>'+k.label+'</b> ('+k.hits+' hits)<br><small>'+O+'/api/proxies?key='+k.k+'&type=http&limit=100</small></span><button class=x onclick="A(\\'key\\',{del:\\''+k.k+'\\'})">x</button></div>').join('');
src.innerHTML=s.src.map(x=>'<div class=r><span>'+x.name+' <small>['+x.t+'] '+x.n+' '+(x.err||'')+'</small></span><button class=x onclick="A(\\'source\\',{del:\\''+x.url+'\\'})">x</button></div>').join('');
top.innerHTML=s.top.map(x=>'<div class=r><span>'+x.p+'</span><small>'+x.ms+'ms</small></div>').join('');
if(document.activeElement!==cc){cc.value=s.conc;ii.value=s.int}})}
L();setInterval(L,10000)</script>`;
