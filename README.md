# WattHub

Secure, self-hosted IoT control dashboard for the **MTTL-W01** (LG U+ / Jinheung) 4-outlet smart power strip.

One Python file, zero dependencies, full control.

| | |
|---|---|
| Server | `server.py` — stdlib-only Python, TCP 10086 + secure HTTP dashboard |
| Frontend | `frontend/` — Vanilla JS/CSS single-page app |
| Protocol | Strip's native `up:...` text protocol over TCP **10086** |
| No Cloud | No accounts, no subscriptions, no third-party services |

---

## ✨ Features

### 🔒 Security-First Design
- **Password-protected** dashboard with PBKDF2-hashed credentials
- **JWT authentication** with short-lived access tokens + refresh rotation
- **CSRF protection** via double-submit cookie pattern
- **Rate limiting** with exponential lockout on failed logins
- **Audit logging** of all actions (login, device control, physical buttons)
- **Optional HTTPS** via `--cert` / `--key` flags
- **Security headers** (X-Frame-Options, CSP, X-Content-Type-Options)
- **Input validation** on all endpoints with max body size limits

### ⚡ Full Device Control
- Individual outlet ON/OFF with optimistic UI
- Master ALL ON / ALL OFF toggle
- Real-time power monitoring (W, kWh, V, A)
- Temperature monitoring per outlet
- WiFi signal strength (RSSI) display
- Overload and overheat alerts
- Live power consumption chart
- Physical button event tracking

### 🎨 Premium Dashboard
- Dark theme with glassmorphism effects
- Responsive design (mobile, tablet, desktop)
- Smooth micro-animations and transitions
- Toast notifications for all actions
- Tab-based navigation (Dashboard, Chart, Guide, Audit, Settings)
- Connection guide with step-by-step instructions

---

## 📋 Requirements

- **Smart Strip**: MTTL-W01 (tested with firmware `0.1.54-1.0.66`)
- **Python**: 3.8+ (stdlib only — no pip install needed)
- **WiFi**: 2.4 GHz network (strip doesn't support 5 GHz)
- **Browser**: Any modern browser

---

## 🚀 Quick Start

### 1. Clone & Run

```bash
git clone https://github.com/ahmedmohsen2mz-serv/WattHub.git
cd WattHub
python server.py
```

On first run, you'll be prompted to create an admin account:

```
══════════════════════════════════════════════════════════════
  WattHub — First Time Setup
══════════════════════════════════════════════════════════════

  Username [admin]: admin
  Password (min 8 chars): ********
  Confirm password: ********

  ✓ Account 'admin' created successfully.
```

### 2. Provision the Strip

```bash
# Put strip in setup mode (hold button ~10s until LED blinks fast)
# Connect to the strip's WiFi: TONLY_TAP_XXXXXXX / LGU_XXXXXXX
python server.py provision --ip YOUR_SERVER_IP --ssid "HOME_WIFI" --password "WIFI_PW"
```

### 3. Open the Dashboard

Navigate to `http://YOUR_SERVER_IP:8080` and sign in.

---

## 🏗 Architecture

```
┌─────────────────┐    TCP 10086 (strip protocol)    ┌───────────────────────┐
│   MTTL-W01      │ ──────────────────────────────►   │    server.py          │
│   Smart Strip   │   up:bootinfo, up:getinfo, etc.   │                       │
│                 │ ◄──────────────────────────────    │  ┌─────────────────┐  │
│  4 outlets      │   up:onoff, up:getinfo:all         │  │ Hub (asyncio)   │  │
│  power sensors  │                                    │  │  Sessions       │  │
│  temp sensors   │                                    │  │  Devices        │  │
│  WiFi module    │                                    │  │  PowerHistory   │  │
└─────────────────┘                                    │  └────────┬────────┘  │
                                                       │           │           │
                                                       │  ┌────────▼────────┐  │
┌─────────────────┐    HTTP(S) :8080                   │  │ WebHandler      │  │
│   Browser /     │ ◄──────────────────────────────    │  │  JWT Auth       │  │
│   Mobile        │   REST API + Static Files          │  │  CSRF Check     │  │
│                 │ ──────────────────────────────►    │  │  Rate Limiter   │  │
│  frontend/      │   POST /api/onoff + JWT + CSRF     │  │  Audit Logger   │  │
│  app.js         │                                    │  └─────────────────┘  │
└─────────────────┘                                    └───────────────────────┘
```

### Security Flow

```
Login ──► POST /api/auth/login
          ├── Rate limit check (5 attempts / 60s window)
          ├── PBKDF2 password verification (100K iterations)
          ├── Issue JWT access token (1h expiry)
          ├── Issue JWT refresh token (24h expiry)
          ├── Set CSRF cookie (SameSite=Strict)
          └── Audit log entry

Control ──► POST /api/onoff
            ├── JWT validation (Authorization: Bearer)
            ├── CSRF double-submit check (cookie vs header)
            ├── Input validation (mac, outlet, on/off)
            ├── Device session lookup
            ├── Send command to strip via TCP
            ├── Wait for strip confirmation
            └── Audit log entry
```

---

## 🔧 Server Commands

### `serve` — Run the dashboard (default)

```bash
python server.py serve [OPTIONS]

  --web-port PORT   HTTP port (default: 8080)
  --port PORT       Strip TCP port (default: 10086, fixed by firmware)
  --ip IP           Server IP to display in the UI
  --cert FILE       TLS certificate for HTTPS
  --key FILE        TLS private key for HTTPS
  --no-auth         Disable authentication (LAN only!)
```

### `provision` — Configure a new strip

```bash
python server.py provision --ip SERVER_IP --ssid "WIFI_NAME" --password "WIFI_PW"

  --host HOST       Strip setup address (default: 192.168.1.1)
  --wait SECONDS    Wait for strip setup service (default: 20)
```

### `selftest` — Offline verification

```bash
python server.py selftest
```

---

## 🌐 API Reference

All endpoints (except auth) require `Authorization: Bearer <JWT>`.
All POST endpoints additionally require `X-CSRF-Token` header matching the CSRF cookie.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/auth/setup-status` | No | Check if initial setup is complete |
| POST | `/api/auth/setup` | No | Create initial admin account |
| POST | `/api/auth/login` | No | Authenticate and get tokens |
| POST | `/api/auth/refresh` | No | Refresh access token |
| POST | `/api/auth/logout` | JWT | Clear session |
| GET | `/api/auth/check` | JWT | Verify token validity |
| GET | `/api/state` | JWT | Get all device states |
| POST | `/api/onoff` | JWT+CSRF | Toggle outlet: `{mac, outlet, on}` |
| GET | `/api/history?mac=X&n=60` | JWT | Power consumption history |
| GET | `/api/audit?n=50` | JWT | Security audit log |
| GET | `/api/csrf` | JWT | Get fresh CSRF token |
| POST | `/api/auth/change-password` | JWT+CSRF | Update password |

---

## 🔐 Security Hardening Checklist

- [x] PBKDF2 password hashing (100K iterations, 16-byte salt)
- [x] JWT with HMAC-SHA256 signature
- [x] Short token expiry (1h access, 24h refresh)
- [x] CSRF double-submit cookie protection
- [x] Rate limiting (5 failures → 5 min lockout)
- [x] Max request body size (16 KB)
- [x] Security headers (X-Frame-Options, X-Content-Type-Options, etc.)
- [x] Directory traversal prevention in static file serving
- [x] Audit logging of all security events
- [x] Credential file locked to owner (chmod 600)
- [x] Session storage (not localStorage) for tokens
- [ ] HTTPS (use `--cert` / `--key` or reverse proxy)
- [ ] VPN/Tailscale for remote access (recommended)
- [ ] Fail2ban integration (use audit.log)

---

## 🏠 Deployment Options

### Local (Home Network)
```bash
python server.py serve
# Access at http://LOCAL_IP:8080
```

### VPS (Remote Access)
```bash
# Generate a random password-safe token
python server.py serve --ip VPS_PUBLIC_IP --web-port 7896

# Open ports:
#   10086/tcp — strip connection (required)
#   7896/tcp  — dashboard (protect with VPN or HTTPS)
```

### With HTTPS
```bash
# Using Let's Encrypt certificates
python server.py serve --cert /etc/letsencrypt/live/domain/fullchain.pem \
                       --key /etc/letsencrypt/live/domain/privkey.pem
```

### systemd Service
```ini
[Unit]
Description=WattHub
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory=/opt/WattHub
ExecStart=/usr/bin/python3 /opt/WattHub/server.py serve --ip YOUR_IP
Restart=always
RestartSec=3
User=<your_username>

[Install]
WantedBy=multi-user.target
```

---

## 📁 Project Structure

```
WattHub/
├── server.py              # Backend: TCP strip server + secure REST API
├── frontend/
│   ├── index.html         # HTML entry point
│   ├── style.css          # Design system & styles
│   └── app.js             # SPA application
├── .watthub-data/         # Auto-created at runtime
│   ├── credentials.json   # Hashed password + JWT secret (chmod 600)
│   └── audit.log          # Security audit trail
├── README.md
├── LICENSE
└── .gitignore
```

---

## 📝 About the MTTL-W01

| Spec | Value |
|------|-------|
| Manufacturer | LG U+ / Jinheung (Tonly) |
| Model | MTTL-W01 (LGU+-TAP-HW002) |
| Chip | Realtek RTL8711AF (ARM Cortex-M3) |
| Outlets | 4 individually controllable + master |
| Rating | 220-250V, 16A |
| WiFi | 2.4 GHz only |
| Protocol | Plain text over TCP 10086 |
| Sensors | Power (mW), Energy (Wh), Temperature (°C), Voltage (mV), Current (mA), WiFi RSSI |
| Firmware | Tested: 0.1.54 – 1.0.66 |

---

## 📜 License

MIT License — see [LICENSE](LICENSE).

---

## 🤝 Contributing

1. Fork the repo
2. Create a feature branch
3. Make your changes
4. Run `python server.py selftest` to verify
5. Submit a pull request
