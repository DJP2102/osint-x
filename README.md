# OSINT-X 🔍
### Open Source Intelligence Dashboard

## 📁 Project Structure
```
OSINT-X/
├── server.js            ← Backend (Node.js + Express + JWT Auth)
├── package.json         ← Dependencies
├── .gitignore
├── README.md
└── public/
    ├── index.html       ← Login + Signup Page
    ├── dashboard.html   ← Main OSINT Dashboard
    ├── style.css        ← Cyberpunk Dark Theme
    └── app.js           ← Frontend Logic
```

## 🚀 Run Locally
```bash
npm install
npm start
```
Open: http://localhost:5000

## ☁️ Deploy on Render
- Build Command: `npm install`
- Start Command: `node server.js`

## 🛠️ Features
- 🔐 Login & Signup with JWT Authentication
- 10 OSINT Modules (WHOIS, DNS, IP/GEO, Dorks, Username, Phone, Subdomains, Headers, Ports, Email)
- Real DNS Lookups
- IP Geolocation via ip-api.com
- Cyberpunk Dark UI
- Mobile Responsive

## ⚠️ For educational & authorized use only
