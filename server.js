const express = require('express');
const cors    = require('cors');
const dns     = require('dns').promises;
const path    = require('path');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');

const app        = express();
const JWT_SECRET = 'osintx-super-secret-2024';

// ─── MIDDLEWARE ───────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── IN-MEMORY USER STORE ─────────────────────────────────────
const users = [];

// ─── AUTH MIDDLEWARE ──────────────────────────────────────────
function auth(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ error: 'No token. Please login.' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token.' });
  }
}

// ═══════════════════════════════════════════════════════════════
//  AUTH ROUTES
// ═══════════════════════════════════════════════════════════════

// SIGNUP
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password)
      return res.status(400).json({ error: 'All fields are required.' });
    if (username.length < 3)
      return res.status(400).json({ error: 'Username must be at least 3 characters.' });
    if (password.length < 6)
      return res.status(400).json({ error: 'Password must be at least 6 characters.' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
      return res.status(400).json({ error: 'Please enter a valid email address.' });
    if (users.find(u => u.email === email))
      return res.status(400).json({ error: 'Email already registered.' });
    if (users.find(u => u.username.toLowerCase() === username.toLowerCase()))
      return res.status(400).json({ error: 'Username already taken.' });
    const hashed = await bcrypt.hash(password, 12);
    const user   = { id: Date.now().toString(), username, email, password: hashed, createdAt: new Date().toISOString() };
    users.push(user);
    const token = jwt.sign({ id: user.id, username: user.username, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, user: { id: user.id, username: user.username, email: user.email } });
  } catch (err) {
    res.status(500).json({ error: 'Server error during signup.' });
  }
});

// LOGIN
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: 'Email and password are required.' });
    const user = users.find(u => u.email === email);
    if (!user)
      return res.status(400).json({ error: 'No account found with this email.' });
    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return res.status(400).json({ error: 'Incorrect password.' });
    const token = jwt.sign({ id: user.id, username: user.username, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, user: { id: user.id, username: user.username, email: user.email } });
  } catch (err) {
    res.status(500).json({ error: 'Server error during login.' });
  }
});

// VERIFY TOKEN
app.get('/api/auth/verify', auth, (req, res) => {
  res.json({ valid: true, user: req.user });
});

// ═══════════════════════════════════════════════════════════════
//  OSINT ROUTES (all protected with auth middleware)
// ═══════════════════════════════════════════════════════════════

// WHOIS
app.post('/api/whois', auth, async (req, res) => {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: 'No target provided' });
  const tld = target.split('.').pop();
  res.json({
    domain: target,
    registrar: 'GoDaddy / Namecheap / Cloudflare',
    tld: `.${tld}`,
    created: '2018-04-12',
    expires: '2026-04-12',
    updated: '2024-01-01',
    status: 'Active',
    note: 'For live WHOIS data → whoisxmlapi.com'
  });
});

// DNS
app.post('/api/dns', auth, async (req, res) => {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: 'No target provided' });
  try {
    const results = {};
    try { results.A    = await dns.resolve4(target);   } catch { results.A    = []; }
    try { results.AAAA = await dns.resolve6(target);   } catch { results.AAAA = []; }
    try { results.MX   = await dns.resolveMx(target);  } catch { results.MX   = []; }
    try { results.NS   = await dns.resolveNs(target);  } catch { results.NS   = []; }
    try { results.TXT  = await dns.resolveTxt(target); } catch { results.TXT  = []; }
    res.json({ domain: target, records: results });
  } catch (err) {
    res.json({ error: 'DNS resolution failed', details: err.message });
  }
});

// IP GEOLOCATION
app.post('/api/ip', auth, async (req, res) => {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: 'No target provided' });
  try {
    let ip = target;
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(target)) {
      const addrs = await dns.resolve4(target).catch(() => []);
      ip = addrs[0] || 'Unresolvable';
    }
    const response = await fetch(`http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query`);
    const data = await response.json();
    res.json({ resolved_ip: ip, geo: data });
  } catch (err) {
    res.json({ error: 'IP lookup failed', details: err.message });
  }
});

// GOOGLE DORKS
app.post('/api/dorks', auth, (req, res) => {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: 'No target provided' });
  res.json({
    target,
    dorks: [
      { label: 'All Pages',         query: `site:${target}` },
      { label: 'PDF Files',         query: `site:${target} filetype:pdf` },
      { label: 'Open Directories',  query: `site:${target} intitle:"index of"` },
      { label: 'Login Pages',       query: `site:${target} inurl:login` },
      { label: 'Admin Panels',      query: `site:${target} inurl:admin` },
      { label: 'Config Files',      query: `site:${target} filetype:env OR filetype:config` },
      { label: 'Backup Files',      query: `site:${target} filetype:bak OR filetype:backup` },
      { label: 'SQL Files',         query: `site:${target} filetype:sql` },
      { label: 'Exposed Emails',    query: `site:${target} intext:"@${target}"` },
      { label: 'Subdomains',        query: `site:*.${target}` },
      { label: 'WordPress',         query: `site:${target} inurl:wp-admin` },
      { label: 'Passwords',         query: `site:${target} intext:password filetype:txt` },
    ]
  });
});

// USERNAME SEARCH
app.post('/api/username', auth, (req, res) => {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: 'No target provided' });
  res.json({
    username: target,
    platforms: [
      { name: 'GitHub',      url: `https://github.com/${target}`,                    category: 'Dev'          },
      { name: 'GitLab',      url: `https://gitlab.com/${target}`,                    category: 'Dev'          },
      { name: 'Dev.to',      url: `https://dev.to/${target}`,                        category: 'Dev'          },
      { name: 'HackerNews',  url: `https://news.ycombinator.com/user?id=${target}`,  category: 'Dev'          },
      { name: 'Twitter/X',   url: `https://twitter.com/${target}`,                   category: 'Social'       },
      { name: 'Instagram',   url: `https://instagram.com/${target}`,                 category: 'Social'       },
      { name: 'Reddit',      url: `https://reddit.com/user/${target}`,               category: 'Social'       },
      { name: 'Facebook',    url: `https://facebook.com/${target}`,                  category: 'Social'       },
      { name: 'LinkedIn',    url: `https://linkedin.com/in/${target}`,               category: 'Professional' },
      { name: 'YouTube',     url: `https://youtube.com/@${target}`,                  category: 'Media'        },
      { name: 'TikTok',      url: `https://tiktok.com/@${target}`,                   category: 'Media'        },
      { name: 'Twitch',      url: `https://twitch.tv/${target}`,                     category: 'Media'        },
      { name: 'Telegram',    url: `https://t.me/${target}`,                          category: 'Messaging'    },
      { name: 'Pinterest',   url: `https://pinterest.com/${target}`,                 category: 'Creative'     },
      { name: 'Behance',     url: `https://behance.net/${target}`,                   category: 'Creative'     },
      { name: 'Dribbble',    url: `https://dribbble.com/${target}`,                  category: 'Creative'     },
    ]
  });
});

// PHONE LOOKUP
app.post('/api/phone', auth, (req, res) => {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: 'No target provided' });
  const clean = target.replace(/\D/g, '');
  let country = 'Unknown', region = 'Unknown', operator = 'Unknown', flag = '🌍';
  if (clean.startsWith('91'))  { country = 'India';        region = 'South Asia';    flag = '🇮🇳'; const pre = clean.substring(2,4); const map = {'98':'Airtel','99':'Jio','97':'Jio','96':'Airtel','70':'Idea/Vi','71':'Idea/Vi','80':'BSNL','81':'BSNL','90':'Vodafone','91':'Vodafone'}; operator = map[pre] || 'Indian Carrier'; }
  else if (clean.startsWith('1'))   { country = 'USA/Canada';  region = 'North America'; flag = '🇺🇸'; operator = 'AT&T / Verizon / T-Mobile'; }
  else if (clean.startsWith('44'))  { country = 'UK';          region = 'Europe';        flag = '🇬🇧'; operator = 'BT / EE / O2 / Vodafone'; }
  else if (clean.startsWith('61'))  { country = 'Australia';   region = 'Oceania';       flag = '🇦🇺'; operator = 'Telstra / Optus'; }
  else if (clean.startsWith('49'))  { country = 'Germany';     region = 'Europe';        flag = '🇩🇪'; operator = 'Deutsche Telekom / Vodafone'; }
  else if (clean.startsWith('33'))  { country = 'France';      region = 'Europe';        flag = '🇫🇷'; operator = 'Orange / SFR'; }
  else if (clean.startsWith('86'))  { country = 'China';       region = 'Asia';          flag = '🇨🇳'; operator = 'China Mobile / Unicom'; }
  else if (clean.startsWith('971')) { country = 'UAE';         region = 'Middle East';   flag = '🇦🇪'; operator = 'Etisalat / Du'; }
  else if (clean.startsWith('92'))  { country = 'Pakistan';    region = 'South Asia';    flag = '🇵🇰'; operator = 'Jazz / Telenor / Zong'; }
  else if (clean.startsWith('880')) { country = 'Bangladesh';  region = 'South Asia';    flag = '🇧🇩'; operator = 'Grameenphone / Robi'; }
  res.json({ number: target, cleaned: clean, country, region, operator, flag, note: 'For advanced lookup → numverify.com API' });
});

// SUBDOMAIN SCANNER
app.post('/api/subdomains', auth, async (req, res) => {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: 'No target provided' });
  const wordlist = ['www','mail','ftp','api','dev','staging','admin','blog','shop','app','cdn','static','portal','vpn','remote','secure','login','webmail','ns1','ns2','smtp','pop','imap','support','help','docs','test','beta','demo','old','new','mobile'];
  const found = [];
  await Promise.allSettled(wordlist.map(async (sub) => {
    try {
      const ips = await dns.resolve4(`${sub}.${target}`);
      found.push({ subdomain: `${sub}.${target}`, ip: ips[0], status: 'Active' });
    } catch { /* not found */ }
  }));
  res.json({ domain: target, found, checked: wordlist.length });
});

// HTTP HEADERS
app.post('/api/headers', auth, async (req, res) => {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: 'No target provided' });
  try {
    const url      = target.startsWith('http') ? target : `https://${target}`;
    const response = await fetch(url, { method: 'HEAD', signal: AbortSignal.timeout(8000) });
    const headers  = {};
    response.headers.forEach((val, key) => { headers[key] = val; });
    res.json({
      url, status: response.status, statusText: response.statusText, headers,
      security: {
        hsts:     !!headers['strict-transport-security'],
        csp:      !!headers['content-security-policy'],
        xframe:   !!headers['x-frame-options'],
        xcontent: !!headers['x-content-type-options'],
        xss:      !!headers['x-xss-protection'],
        referrer: !!headers['referrer-policy'],
      }
    });
  } catch (err) {
    res.json({ error: 'Header fetch failed', details: err.message });
  }
});

// PORT REFERENCE
app.post('/api/ports', auth, (req, res) => {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: 'No target provided' });
  res.json({
    target,
    note: 'Common ports reference. TCP scan needs direct server access.',
    ports: [
      { port: 21,    service: 'FTP',        risk: 'medium' },
      { port: 22,    service: 'SSH',        risk: 'medium' },
      { port: 23,    service: 'Telnet',     risk: 'high'   },
      { port: 25,    service: 'SMTP',       risk: 'low'    },
      { port: 53,    service: 'DNS',        risk: 'low'    },
      { port: 80,    service: 'HTTP',       risk: 'low'    },
      { port: 110,   service: 'POP3',       risk: 'medium' },
      { port: 143,   service: 'IMAP',       risk: 'medium' },
      { port: 443,   service: 'HTTPS',      risk: 'low'    },
      { port: 445,   service: 'SMB',        risk: 'high'   },
      { port: 3306,  service: 'MySQL',      risk: 'high'   },
      { port: 3389,  service: 'RDP',        risk: 'high'   },
      { port: 5432,  service: 'PostgreSQL', risk: 'high'   },
      { port: 6379,  service: 'Redis',      risk: 'high'   },
      { port: 8080,  service: 'HTTP-Alt',   risk: 'medium' },
      { port: 8443,  service: 'HTTPS-Alt',  risk: 'medium' },
      { port: 27017, service: 'MongoDB',    risk: 'high'   },
    ]
  });
});

// EMAIL FINDER
app.post('/api/email', auth, (req, res) => {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: 'No target provided' });
  const domain = target.replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0];
  res.json({
    domain,
    patterns: [
      `info@${domain}`, `contact@${domain}`, `admin@${domain}`,
      `support@${domain}`, `hello@${domain}`, `team@${domain}`,
      `security@${domain}`, `webmaster@${domain}`, `noreply@${domain}`,
      `mail@${domain}`, `hr@${domain}`, `careers@${domain}`,
    ],
    note: 'For real email discovery → hunter.io API'
  });
});

// ─── CATCH ALL ────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─── START ────────────────────────────────────────────────────
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`\n╔══════════════════════════════════════╗`);
  console.log(`║   OSINT-X Running!                   ║`);
  console.log(`║   Open: http://localhost:${PORT}        ║`);
  console.log(`╚══════════════════════════════════════╝\n`);
});
