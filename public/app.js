/* ═══════════════════════════════════════════════════════
   OSINT-X — Dashboard Frontend
   ═══════════════════════════════════════════════════════ */

// ─── AUTH CHECK ───────────────────────────────────────────────
const TOKEN = localStorage.getItem('osintx_token');
const USER  = JSON.parse(localStorage.getItem('osintx_user') || '{}');

if (!TOKEN) {
  window.location.href = '/index.html';
}

// Set username in header
if (USER.username) {
  document.getElementById('userName').textContent = USER.username.toUpperCase();
}

function logout() {
  localStorage.removeItem('osintx_token');
  localStorage.removeItem('osintx_user');
  window.location.href = '/index.html';
}

// ─── CLOCK ────────────────────────────────────────────────────
setInterval(() => {
  document.getElementById('clock').textContent =
    new Date().toTimeString().slice(0, 8);
}, 1000);

// ─── PARTICLES ────────────────────────────────────────────────
(function () {
  const canvas = document.getElementById('particles');
  const ctx = canvas.getContext('2d');
  let W, H;
  const particles = [];
  function resize() { W = canvas.width = window.innerWidth; H = canvas.height = window.innerHeight; }
  resize(); window.addEventListener('resize', resize);
  for (let i = 0; i < 55; i++) particles.push({ x: Math.random() * window.innerWidth, y: Math.random() * window.innerHeight, vx: (Math.random() - 0.5) * 0.25, vy: (Math.random() - 0.5) * 0.25, r: Math.random() * 1.2 + 0.3, a: Math.random() * 0.4 + 0.1 });
  function draw() { ctx.clearRect(0, 0, W, H); for (const p of particles) { ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2); ctx.fillStyle = `rgba(0,200,255,${p.a})`; ctx.fill(); p.x += p.vx; p.y += p.vy; if (p.x < 0 || p.x > W) p.vx *= -1; if (p.y < 0 || p.y > H) p.vy *= -1; } requestAnimationFrame(draw); }
  draw();
})();

// ─── STATE ────────────────────────────────────────────────────
let scanCount    = 0;
let totalModules = 0;
let doneModules  = 0;

// ─── DOM REFS ─────────────────────────────────────────────────
const terminal    = document.getElementById('terminal');
const progressBar = document.getElementById('progressBar');
const statusDot   = document.getElementById('statusDot');
const statusTxt   = document.getElementById('statusText');
const scanBtn     = document.getElementById('scanBtn');
const btnText     = scanBtn.querySelector('.btn-text');

// ─── LOGGER ───────────────────────────────────────────────────
function log(msg, type = 'info') {
  const el = document.createElement('div');
  el.className = `term-line ${type}`;
  el.textContent = msg;
  terminal.appendChild(el);
  terminal.scrollTop = terminal.scrollHeight;
}
function logSection(title) {
  log('', 'muted');
  log(`┌─── ${title} ${'─'.repeat(Math.max(0, 38 - title.length))}`, 'header');
}
function logRow(key, val) { log(`│  ${key.padEnd(18)} ${val}`, 'data'); }
function logClose()       { log(`└${'─'.repeat(44)}`, 'header'); }

// ─── STATUS ───────────────────────────────────────────────────
function setStatus(text, state = '') {
  statusTxt.textContent = text;
  statusDot.className = 'status-dot' + (state ? ' ' + state : '');
}
function updateProgress() {
  doneModules++;
  progressBar.style.width = totalModules > 0 ? (doneModules / totalModules * 100) + '%' : '0%';
}

// ─── TAB SWITCH ───────────────────────────────────────────────
function switchTab(tab) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.querySelector(`[data-tab="${tab}"]`).classList.add('active');
  document.getElementById(`tab-${tab}`).classList.add('active');
}

// ─── HELPERS ──────────────────────────────────────────────────
function selectAll()  { document.querySelectorAll('.module-card input').forEach(c => c.checked = true); }
function selectNone() { document.querySelectorAll('.module-card input').forEach(c => c.checked = false); }

function clearOutput() {
  terminal.innerHTML = `<div class="term-line success">[>] Output cleared. Ready for new scan.</div>`;
  document.getElementById('resultsGrid').innerHTML = `
    <div class="empty-state">
      <div class="empty-icon">◈</div>
      <div>No scan results yet</div>
      <div class="empty-sub">Run a scan to see structured output here</div>
    </div>`;
  progressBar.style.width = '0%';
  setStatus('READY');
}

// ─── API CALL WITH AUTH ───────────────────────────────────────
async function callAPI(endpoint, target) {
  try {
    const res = await fetch(`/api/${endpoint}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'authorization': TOKEN },
      body: JSON.stringify({ target })
    });
    if (res.status === 401) { logout(); return { error: 'Unauthorized' }; }
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (e) {
    return { error: e.message };
  }
}

// ─── RESULT CARD ──────────────────────────────────────────────
function addCard(title, badge, bodyHTML) {
  const grid = document.getElementById('resultsGrid');
  const empty = grid.querySelector('.empty-state');
  if (empty) empty.remove();
  const card = document.createElement('div');
  card.className = 'result-card';
  card.innerHTML = `
    <div class="result-card-header">
      <div class="result-card-title">${title}</div>
      <div class="result-card-badge">${badge}</div>
    </div>
    <div class="result-card-body">${bodyHTML}</div>`;
  grid.appendChild(card);
}

function row(key, val, cls = '') {
  return `<div class="result-row"><span class="result-key">${key}</span><span class="result-val ${cls}">${val || '—'}</span></div>`;
}

// ─── MODULE: WHOIS ────────────────────────────────────────────
async function runWhois(target) {
  logSection('WHOIS LOOKUP');
  const d = await callAPI('whois', target);
  if (d.error) { log(`│  ERROR: ${d.error}`, 'error'); logClose(); return; }
  logRow('DOMAIN', d.domain); logRow('REGISTRAR', d.registrar); logRow('TLD', d.tld); logRow('STATUS', d.status);
  logClose();
  addCard('WHOIS', '✓ DONE', `${row('Domain',d.domain)}${row('Registrar',d.registrar)}${row('TLD',d.tld)}${row('Created',d.created)}${row('Expires',d.expires)}${row('Status',d.status,'green')}${row('Note',d.note,'yellow')}`);
}

// ─── MODULE: DNS ──────────────────────────────────────────────
async function runDns(target) {
  logSection('DNS RECORDS');
  const d = await callAPI('dns', target);
  if (d.error) { log(`│  ERROR: ${d.error}`, 'error'); logClose(); return; }
  const r = d.records || {};
  logRow('A', (r.A||[]).join(', ')||'none'); logRow('MX', (r.MX||[]).map(m=>m.exchange).join(', ')||'none'); logRow('NS', (r.NS||[]).join(', ')||'none');
  logClose();
  addCard('DNS RECORDS', `A:${(r.A||[]).length}`, `${row('A Records',(r.A||[]).join('<br>')||'none')}${row('AAAA',(r.AAAA||[]).join('<br>')||'none')}${row('MX',(r.MX||[]).map(m=>`${m.exchange}(${m.priority})`).join('<br>')||'none')}${row('NS',(r.NS||[]).join('<br>')||'none')}${row('TXT Count',(r.TXT||[]).length)}`);
}

// ─── MODULE: IP ───────────────────────────────────────────────
async function runIp(target) {
  logSection('IP / GEO LOOKUP');
  const d = await callAPI('ip', target);
  if (d.error) { log(`│  ERROR: ${d.error}`, 'error'); logClose(); return; }
  const g = d.geo || {};
  logRow('IP', d.resolved_ip); logRow('COUNTRY', `${g.country}(${g.countryCode})`); logRow('CITY', g.city); logRow('ISP', g.isp);
  logClose();
  addCard('IP / GEO', d.resolved_ip||'IP', `${row('Resolved IP',d.resolved_ip)}${row('Country',`${g.country||'?'}(${g.countryCode||'?'})`)}${row('Region',g.regionName)}${row('City',g.city)}${row('ISP',g.isp)}${row('Org',g.org)}${row('Timezone',g.timezone)}${row('Lat/Lon',`${g.lat},${g.lon}`)}`);
}

// ─── MODULE: DORKS ────────────────────────────────────────────
async function runDorks(target) {
  logSection('GOOGLE DORKS');
  const d = await callAPI('dorks', target);
  if (d.error) { log(`│  ERROR: ${d.error}`, 'error'); logClose(); return; }
  d.dorks.forEach(dk => log(`│  [${dk.label}] ${dk.query}`, 'data'));
  logClose();
  addCard('GOOGLE DORKS', `${d.dorks.length} dorks`, d.dorks.map(dk => `<div class="dork-item"><span class="dork-label">${dk.label}: </span><a class="dork-link" href="https://google.com/search?q=${encodeURIComponent(dk.query)}" target="_blank">${dk.query}</a></div>`).join(''));
}

// ─── MODULE: USERNAME ─────────────────────────────────────────
async function runUsername(target) {
  logSection('USERNAME SEARCH');
  const d = await callAPI('username', target);
  if (d.error) { log(`│  ERROR: ${d.error}`, 'error'); logClose(); return; }
  d.platforms.forEach(p => log(`│  [${p.category.padEnd(12)}] ${p.name}`, 'data'));
  logClose();
  addCard('USERNAME SEARCH', `${d.platforms.length} platforms`, `<div class="result-link-list">${d.platforms.map(p=>`<a class="result-link" href="${p.url}" target="_blank">▸ ${p.name} <span class="result-link-cat">[${p.category}]</span></a>`).join('')}</div>`);
}

// ─── MODULE: PHONE ────────────────────────────────────────────
async function runPhone(target) {
  logSection('PHONE LOOKUP');
  const d = await callAPI('phone', target);
  if (d.error) { log(`│  ERROR: ${d.error}`, 'error'); logClose(); return; }
  logRow('NUMBER', d.number); logRow('COUNTRY', `${d.flag} ${d.country}`); logRow('OPERATOR', d.operator);
  logClose();
  addCard('PHONE LOOKUP', 'PHONE', `${row('Number',d.number)}${row('Cleaned',d.cleaned)}${row('Country',`${d.flag} ${d.country}`)}${row('Region',d.region)}${row('Operator',d.operator,'green')}${row('Note',d.note,'yellow')}`);
}

// ─── MODULE: SUBDOMAINS ───────────────────────────────────────
async function runSubdomains(target) {
  logSection('SUBDOMAIN SCANNER');
  log(`│  Scanning 30 common subdomains...`, 'muted');
  const d = await callAPI('subdomains', target);
  if (d.error) { log(`│  ERROR: ${d.error}`, 'error'); logClose(); return; }
  d.found.length ? d.found.forEach(s => log(`│  [FOUND] ${s.subdomain} → ${s.ip}`, 'success')) : log(`│  No subdomains found`, 'warn');
  logClose();
  addCard('SUBDOMAINS', `${d.found.length}/${d.checked}`, d.found.length ? d.found.map(s => row(s.subdomain, `${s.ip} ● ACTIVE`, 'green')).join('') : row('Result', 'No subdomains found', 'red'));
}

// ─── MODULE: HEADERS ──────────────────────────────────────────
async function runHeaders(target) {
  logSection('HTTP HEADERS');
  const d = await callAPI('headers', target);
  if (d.error) { log(`│  ERROR: ${d.error}`, 'error'); logClose(); return; }
  const s = d.security || {};
  logRow('URL', d.url); logRow('STATUS', d.status); logRow('HSTS', s.hsts ? '✓' : '✗'); logRow('CSP', s.csp ? '✓' : '✗');
  logClose();
  addCard('HTTP HEADERS', `HTTP ${d.status}`, `${row('URL',d.url)}${row('Status',d.status,d.status<400?'green':'red')}<div style="font-family:var(--mono);font-size:8px;color:var(--text-muted);letter-spacing:1px;margin:8px 0 5px">SECURITY HEADERS</div><div class="security-grid">${[['HSTS',s.hsts],['CSP',s.csp],['X-Frame',s.xframe],['X-Content',s.xcontent],['XSS Prot',s.xss],['Referrer',s.referrer]].map(([l,ok])=>`<div class="sec-item ${ok?'pass':'fail'}">${ok?'✓':'✗'} ${l}</div>`).join('')}</div>`);
}

// ─── MODULE: PORTS ────────────────────────────────────────────
async function runPorts(target) {
  logSection('PORT REFERENCE');
  const d = await callAPI('ports', target);
  if (d.error) { log(`│  ERROR: ${d.error}`, 'error'); logClose(); return; }
  log(`│  ${d.ports.length} common ports reference`, 'muted'); logClose();
  addCard('PORT REFERENCE', `${d.ports.length} ports`, `<div style="font-family:var(--mono);font-size:9px;color:var(--yellow);margin-bottom:8px">${d.note}</div><table class="port-table"><thead><tr><th>PORT</th><th>SERVICE</th><th>RISK</th></tr></thead><tbody>${d.ports.map(p=>`<tr><td>${p.port}</td><td>${p.service}</td><td class="risk-${p.risk}">${p.risk.toUpperCase()}</td></tr>`).join('')}</tbody></table>`);
}

// ─── MODULE: EMAIL ────────────────────────────────────────────
async function runEmail(target) {
  logSection('EMAIL FINDER');
  const d = await callAPI('email', target);
  if (d.error) { log(`│  ERROR: ${d.error}`, 'error'); logClose(); return; }
  d.patterns.forEach(e => log(`│  ${e}`, 'data')); logClose();
  addCard('EMAIL FINDER', d.domain, `<div style="font-family:var(--mono);font-size:8px;color:var(--yellow);margin-bottom:8px">${d.note}</div><div class="result-link-list">${d.patterns.map(e=>`<a class="result-link" href="mailto:${e}">📧 ${e}</a>`).join('')}</div>`);
}

// ─── MODULE MAP ───────────────────────────────────────────────
const MODULES = [
  { id: 'mod-whois',      fn: runWhois      },
  { id: 'mod-dns',        fn: runDns        },
  { id: 'mod-ip',         fn: runIp         },
  { id: 'mod-dorks',      fn: runDorks      },
  { id: 'mod-username',   fn: runUsername   },
  { id: 'mod-phone',      fn: runPhone      },
  { id: 'mod-subdomains', fn: runSubdomains },
  { id: 'mod-headers',    fn: runHeaders    },
  { id: 'mod-ports',      fn: runPorts      },
  { id: 'mod-email',      fn: runEmail      },
];

// ─── MAIN SCAN ────────────────────────────────────────────────
async function startScan() {
  const target = document.getElementById('target').value.trim();
  if (!target) { log('[!] ERROR: Please enter a target!', 'error'); return; }
  const selected = MODULES.filter(m => document.getElementById(m.id)?.checked);
  if (!selected.length) { log('[!] ERROR: Please select at least one module!', 'error'); return; }

  totalModules = selected.length; doneModules = 0;
  progressBar.style.width = '0%';
  scanBtn.classList.add('scanning');
  btnText.textContent = '⟳ SCANNING...';
  setStatus('SCANNING', 'scanning');

  log('', 'muted');
  log('╔══════════════════════════════════════════════╗', 'info');
  log('║         OSINT-X SCAN INITIATED               ║', 'info');
  log('╚══════════════════════════════════════════════╝', 'info');
  log(`[TARGET]   ${target}`, 'success');
  log(`[AGENT]    ${USER.username || 'Unknown'}`, 'info');
  log(`[MODULES]  ${selected.length} selected`, 'info');
  log(`[TIME]     ${new Date().toLocaleString()}`, 'muted');

  for (let i = 0; i < selected.length; i++) {
    log(`\n[${i+1}/${selected.length}] Running module...`, 'muted');
    await selected[i].fn(target);
    updateProgress();
  }

  log('', 'muted');
  log('╔══════════════════════════════════════════════╗', 'success');
  log(`║  SCAN COMPLETE ✓  ${selected.length} modules finished          ║`, 'success');
  log('╚══════════════════════════════════════════════╝', 'success');

  scanBtn.classList.remove('scanning');
  btnText.textContent = '▶ LAUNCH SCAN';
  setStatus('DONE', 'done');
  progressBar.style.width = '100%';
  scanCount++;
  document.getElementById('scanCount').textContent = scanCount;
  setTimeout(() => switchTab('results'), 700);
}
