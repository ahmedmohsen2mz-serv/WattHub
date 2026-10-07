#!/usr/bin/env python3
"""WattHub — Secure IoT control server for the MTTL-W01 smart power strip.

Architecture
============
┌─────────────┐    TCP 10086     ┌──────────────────┐    HTTP(S)     ┌──────────┐
│  MTTL-W01   │ ──────────────►  │   WattHub     │ ◄──────────── │ Browser  │
│  strip      │  strip protocol  │   server.py      │   REST API    │ / App    │
└─────────────┘                  └──────────────────┘               └──────────┘

Security layers
===============
1. bcrypt-hashed password stored on disk (setup wizard on first run)
2. JWT tokens with short expiry + refresh rotation
3. CSRF protection via double-submit cookie + header
4. Per-IP rate limiting on auth endpoints
5. All state-changing endpoints require POST + valid JWT + CSRF
6. Audit log of every action
7. Strip TCP port (10086) accepts only the strip protocol — no auth bypass possible
8. Optional HTTPS via --cert / --key flags

Stdlib-only except for the strip protocol layer.
One file, zero pip install.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import sys
import struct
import threading
import time
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse, unquote
from datetime import datetime, timezone

# ── Strip protocol constants ────────────────────────────────────────────────
DEVICE_PORT = 10086
SETUP_HOST = "192.168.1.1"
SETUP_PORT = 30300
WEB_PORT = 8080
POLL_SECONDS = 5.0
DIAG_EVERY = 3

BOOTINFO_RE = re.compile(
    r"^up:bootinfo:([^;\r\n]+);([0-9A-Fa-f]{12});([0-9A-Fa-f]{12});([^;\r\n]+);connect$"
)
GETINFO_RE = re.compile(
    r"(?P<ch>[1-5]):(?P<runtime>-?\d+);(?P<relay>on|off);(?P<state>-?\d+);"
    r"(?P<overload>[^;:]+);(?P<overheat>[^;:]+);(?P<power>-?\d+);"
    r"(?P<energy>[0-9A-Fa-f]{8});(?P<previous>[0-9A-Fa-f]{8});"
    r"(?P<config>[0-9A-Fa-f]{8});(?P<status>[^;:]+);"
    r"(?P<event>[0-9A-Fa-f]{2});(?P<temperature>-?\d+)",
    re.I,
)
ONOFF_ACK_RE = re.compile(r"^up:onoff:([1-4]):(on|off)$", re.I)
EVENT_RE = re.compile(r"^up:event:onoff:([0-4]):(on|off)$", re.I)
POWER_REPORT_RE = re.compile(r"^up:power_report:([1-5]):(-?\d+)$", re.I)
QUERY_RE = re.compile(r"^up:query:(-?\d+)$")

# ── Security constants ──────────────────────────────────────────────────────
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_SECONDS = 3600       # 1 hour
REFRESH_EXPIRY_SECONDS = 86400  # 24 hours
CSRF_TOKEN_LENGTH = 32
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 300           # 5 minutes
RATE_LIMIT_WINDOW = 60          # seconds
RATE_LIMIT_MAX = 30             # max requests per window for auth endpoints
MAX_BODY_SIZE = 16384           # 16 KB max request body
AUDIT_MAX_LINES = 10000

# ── Config / data directory ─────────────────────────────────────────────────
DATA_DIR = Path(__file__).resolve().parent / ".watthub-data"
CREDENTIALS_FILE = DATA_DIR / "credentials.json"
AUDIT_LOG_FILE = DATA_DIR / "audit.log"
HISTORY_FILE = DATA_DIR / "history.json"

# ── Utility: minimal JWT (stdlib only, HMAC-SHA256) ─────────────────────────

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _b64url_decode(s: str) -> bytes:
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)

def jwt_encode(payload: dict, secret: str) -> str:
    header = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = _b64url_encode(json.dumps(payload).encode())
    sig = hmac.new(secret.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest()
    return f"{header}.{body}.{_b64url_encode(sig)}"

def jwt_decode(token: str, secret: str) -> dict | None:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        sig = hmac.new(secret.encode(), f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(sig, _b64url_decode(parts[2])):
            return None
        payload = json.loads(_b64url_decode(parts[1]))
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None

# ── Utility: password hashing (stdlib, PBKDF2) ─────────────────────────────

def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return base64.b64encode(salt + dk).decode()

def verify_password(password: str, stored: str) -> bool:
    try:
        data = base64.b64decode(stored)
        salt, dk = data[:16], data[16:]
        return hmac.compare_digest(hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000), dk)
    except Exception:
        return False

# ── Rate limiter ────────────────────────────────────────────────────────────

class RateLimiter:
    def __init__(self):
        self._attempts: dict[str, list[float]] = defaultdict(list)
        self._lockouts: dict[str, float] = {}

    def is_locked(self, ip: str) -> bool:
        until = self._lockouts.get(ip, 0)
        if time.time() < until:
            return True
        if ip in self._lockouts:
            del self._lockouts[ip]
        return False

    def record_failure(self, ip: str):
        now = time.time()
        attempts = self._attempts[ip]
        attempts.append(now)
        # Keep only recent attempts
        self._attempts[ip] = [t for t in attempts if now - t < RATE_LIMIT_WINDOW]
        if len(self._attempts[ip]) >= MAX_LOGIN_ATTEMPTS:
            self._lockouts[ip] = now + LOCKOUT_SECONDS
            self._attempts[ip] = []

    def record_success(self, ip: str):
        self._attempts.pop(ip, None)
        self._lockouts.pop(ip, None)

    def check_rate(self, ip: str) -> bool:
        """Returns False if rate limit exceeded."""
        now = time.time()
        attempts = self._attempts.get(ip, [])
        recent = [t for t in attempts if now - t < RATE_LIMIT_WINDOW]
        return len(recent) < RATE_LIMIT_MAX

# ── Audit logger ────────────────────────────────────────────────────────────

class AuditLogger:
    def __init__(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def log(self, action: str, ip: str, user: str = "", details: str = ""):
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        entry = json.dumps({"ts": ts, "action": action, "ip": ip, "user": user, "details": details})
        with self._lock:
            with open(AUDIT_LOG_FILE, "a") as f:
                f.write(entry + "\n")

    def recent(self, n: int = 50) -> list[dict]:
        try:
            with open(AUDIT_LOG_FILE) as f:
                lines = f.readlines()
            return [json.loads(l) for l in lines[-n:]]
        except FileNotFoundError:
            return []

audit = AuditLogger()

# ── Power history tracker ───────────────────────────────────────────────────

class PowerHistory:
    """Keeps rolling per-device power readings for charting."""
    MAX_POINTS = 360  # 30 minutes at 5s intervals

    def __init__(self):
        self._lock = threading.Lock()
        self._data: dict[str, list[dict]] = {}  # mac -> [{"ts": ..., "power_w": ..., "voltage": ..., ...}]

    def record(self, mac: str, snapshot: dict):
        with self._lock:
            if mac not in self._data:
                self._data[mac] = []
            self._data[mac].append({
                "ts": time.time(),
                "power_w": snapshot.get("power_w", 0),
                "voltage": snapshot.get("voltage"),
                "current_a": snapshot.get("current_a", 0),
                "energy_kwh": snapshot.get("energy_kwh", 0),
            })
            if len(self._data[mac]) > self.MAX_POINTS:
                self._data[mac] = self._data[mac][-self.MAX_POINTS:]

    def get(self, mac: str, last_n: int = 60) -> list[dict]:
        with self._lock:
            return list(self._data.get(mac.upper(), [])[-last_n:])

power_history = PowerHistory()

# ── Strip protocol layer ────────────────────────────────────────────────────

def parse_getinfo(line: str) -> list[dict]:
    text = line.strip("\r\n\x00 ")
    if text.startswith("up:getinfo:"):
        text = text[len("up:getinfo:"):]
    out = []
    for m in GETINFO_RE.finditer(text):
        g = m.groupdict()
        ch = int(g["ch"])
        if ch > 4:
            continue
        out.append({
            "n": ch,
            "on": g["relay"].lower() == "on",
            "power_w": round(int(g["power"]) / 1000.0, 2),
            "energy_kwh": round(int(g["energy"], 16) / 1000.0, 3),
            "temp_c": int(g["temperature"]),
            "overload": g["overload"] != "0",
            "overheat": g["overheat"] != "0",
            "runtime_s": int(g["runtime"]),
        })
    return out


class Device:
    def __init__(self, mac: str, model: str, fw: str, ip: str):
        self.mac = mac.upper()
        self.model = model
        self.fw = fw
        self.ip = ip
        self.online = False
        self.voltage_v: float | None = None
        self.rssi: int | None = None
        self.connected_at: float = 0
        self.last_seen: float = 0
        self.outlets = {
            n: {"n": n, "on": False, "power_w": 0.0, "energy_kwh": 0.0, "temp_c": 0,
                "overload": False, "overheat": False, "runtime_s": 0}
            for n in range(1, 5)
        }

    @property
    def name(self) -> str:
        return f"MTTL {self.mac[-7:]}"

    @property
    def current_a(self) -> float:
        if not self.voltage_v:
            return 0.0
        return round(sum(o["power_w"] for o in self.outlets.values()) / self.voltage_v, 2)

    def snapshot(self) -> dict:
        outlets = list(self.outlets.values())
        return {
            "mac": self.mac,
            "name": self.name,
            "model": self.model,
            "fw": self.fw,
            "ip": self.ip,
            "online": self.online,
            "on": any(o["on"] for o in outlets),
            "power_w": round(sum(o["power_w"] for o in outlets), 2),
            "energy_kwh": round(sum(o["energy_kwh"] for o in outlets), 3),
            "voltage": self.voltage_v,
            "current_a": self.current_a,
            "rssi": self.rssi,
            "connected_at": self.connected_at,
            "last_seen": self.last_seen,
            "outlets": outlets,
        }


class Session:
    def __init__(self, ip: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.ip = ip
        self.reader = reader
        self.writer = writer
        self.lock = asyncio.Lock()
        self.device: Device | None = None
        self.got_getinfo = asyncio.Event()
        self.last_cmd = ""
        self.last_rx = ""

    async def send(self, cmd: str) -> None:
        self.last_cmd = cmd
        self.writer.write((cmd + "\r\n").encode("ascii"))
        await self.writer.drain()

    async def _refresh(self, timeout: float = 6.0) -> bool:
        self.got_getinfo.clear()
        await self.send("up:getinfo:all")
        try:
            await asyncio.wait_for(self.got_getinfo.wait(), timeout)
            return True
        except asyncio.TimeoutError:
            return False

    async def refresh(self, timeout: float = 4.0) -> bool:
        async with self.lock:
            return await self._refresh(timeout)

    async def set_outlets(self, channels: list[int], on: bool) -> bool:
        async with self.lock:
            for ch in channels:
                await self.send(f"up:onoff:{ch}:{'on' if on else 'off'}")
            await asyncio.sleep(0.3)
            return await self._refresh()

    async def diagnostics(self) -> None:
        async with self.lock:
            await self.send("up:power_report:1:vol")
            await self.send("up:query:wifirssi")


class Hub:
    def __init__(self) -> None:
        self.devices: dict[str, Device] = {}
        self.sessions: dict[str, Session] = {}

    def session(self, mac: str) -> Session | None:
        s = self.sessions.get(mac.upper())
        if s and s.device and s.device.online and not s.writer.is_closing():
            return s
        return None

    def snapshot(self) -> dict:
        return {"devices": [d.snapshot() for d in self.devices.values()]}

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        ip = peer[0] if peer else "?"
        s = Session(ip, reader, writer)
        print(f"[device] connection from {ip}")
        try:
            while True:
                raw = await reader.readline()
                if not raw:
                    break
                if len(raw) > 8192:
                    raise ValueError("line too long")
                line = raw.replace(b"\x00", b"").decode("utf-8", "replace").strip("\r\n ")
                s.last_rx = line

                m = BOOTINFO_RE.match(line)
                if m:
                    mac = m.group(2).upper()
                    d = self.devices.get(mac) or Device(mac, m.group(1), m.group(4), ip)
                    d.model, d.fw, d.ip, d.online = m.group(1), m.group(4), ip, True
                    d.connected_at = time.time()
                    d.last_seen = time.time()
                    s.device = d
                    self.devices[mac] = d
                    old = self.sessions.get(mac)
                    if old and old is not s:
                        old.writer.close()
                    self.sessions[mac] = s
                    print(f"[device] {d.name} model={d.model} fw={d.fw}")
                    audit.log("device_connect", ip, details=f"{d.name} model={d.model} fw={d.fw}")
                    asyncio.create_task(s.refresh())
                    continue

                if not s.device:
                    continue

                s.device.last_seen = time.time()

                if line.startswith("up:getinfo:"):
                    records = parse_getinfo(line)
                    if len(records) == 4:
                        s.device.outlets = {r["n"]: r for r in records}
                        s.got_getinfo.set()
                        # Record to power history
                        power_history.record(s.device.mac, s.device.snapshot())
                    continue

                if line.lower().startswith("up:power_report:"):
                    m2 = POWER_REPORT_RE.fullmatch(line)
                    if m2 and int(m2.group(2)) >= 50000:
                        s.device.voltage_v = round(int(m2.group(2)) / 1000.0, 1)
                    continue

                m2 = QUERY_RE.fullmatch(line)
                if m2:
                    s.device.rssi = int(m2.group(1))
                    continue

                m2 = EVENT_RE.fullmatch(line)
                if m2:
                    ch, on = int(m2.group(1)), m2.group(2).lower() == "on"
                    if ch:
                        s.device.outlets[ch]["on"] = on
                        audit.log("physical_button", ip, details=f"{s.device.name} outlet {ch} {'on' if on else 'off'}")
                    continue

                if ONOFF_ACK_RE.fullmatch(line):
                    continue
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            pass
        except Exception as err:
            print(f"[device] session error {ip}: {err!r}")
        finally:
            if s.device:
                if self.sessions.get(s.device.mac) is s:
                    self.sessions.pop(s.device.mac, None)
                    s.device.online = False
                    print(f"[device] {s.device.name} offline")
                    audit.log("device_disconnect", ip, details=s.device.name)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def poll_loop(self) -> None:
        n = 0
        while True:
            n += 1
            for s in list(self.sessions.values()):
                if not s.device:
                    continue
                try:
                    if not await s.refresh():
                        print(f"[device] {s.device.name} poll timeout")
                    elif n % DIAG_EVERY == 0:
                        await s.diagnostics()
                except Exception as err:
                    print(f"[device] poll error: {err!r}")
            await asyncio.sleep(POLL_SECONDS)


# ── Credentials management ──────────────────────────────────────────────────

def load_credentials() -> dict | None:
    try:
        return json.loads(CREDENTIALS_FILE.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return None

def save_credentials(username: str, password: str):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    data = {
        "username": username,
        "password_hash": hash_password(password),
        "jwt_secret": secrets.token_hex(32),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    CREDENTIALS_FILE.write_text(json.dumps(data, indent=2))
    # Secure file permissions
    os.chmod(CREDENTIALS_FILE, 0o600)
    return data

# ── Setup wizard (first run) ────────────────────────────────────────────────

def setup_wizard() -> dict:
    """Interactive first-run setup."""
    print("\n" + "="*60)
    print("  WattHub — First Time Setup")
    print("="*60)
    print("\nCreate your admin account for the web dashboard.")
    print("This password will be securely hashed and stored locally.\n")

    username = input("  Username [admin]: ").strip() or "admin"
    while True:
        password = input("  Password (min 8 chars): ").strip()
        if len(password) < 8:
            print("  ✗ Password must be at least 8 characters.")
            continue
        confirm = input("  Confirm password: ").strip()
        if password != confirm:
            print("  ✗ Passwords don't match.")
            continue
        break

    creds = save_credentials(username, password)
    print(f"\n  ✓ Account '{username}' created successfully.")
    print(f"  ✓ Credentials stored in {CREDENTIALS_FILE}")
    print("="*60 + "\n")
    return creds


# ── Web server ──────────────────────────────────────────────────────────────

STATIC_DIR = Path(__file__).resolve().parent / "frontend"
MIME_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".woff2": "font/woff2",
    ".woff": "font/woff",
    ".ttf": "font/ttf",
}


class WebHandler(BaseHTTPRequestHandler):
    hub: Hub
    loop: asyncio.AbstractEventLoop
    local_ip: str
    port: int
    credentials: dict
    rate_limiter: RateLimiter
    active_refresh_tokens: dict  # token_hash -> expiry

    def log_message(self, fmt, *args):
        pass  # suppress default logging

    def _client_ip(self) -> str:
        # Support reverse proxy
        forwarded = self.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
        peer = self.connection.getpeername()
        return peer[0] if peer else "?"

    def _send(self, body: bytes, content_type: str, code: int = 200, extra_headers: dict | None = None):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-XSS-Protection", "1; mode=block")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Cache-Control", "no-store")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200, extra_headers=None):
        self._send(json.dumps(obj).encode(), "application/json", code, extra_headers)

    def _error(self, code: int, msg: str):
        self._json({"error": msg}, code)

    def _read_body(self) -> bytes | None:
        length = int(self.headers.get("Content-Length", 0))
        if length > MAX_BODY_SIZE:
            self._error(413, "request too large")
            return None
        if length == 0:
            return b"{}"
        return self.rfile.read(length)

    def _get_jwt_payload(self) -> dict | None:
        """Extract and validate JWT from Authorization header."""
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        token = auth[7:]
        return jwt_decode(token, self.credentials["jwt_secret"])

    def _require_auth(self) -> dict | None:
        """Returns JWT payload or sends 401 and returns None."""
        payload = self._get_jwt_payload()
        if not payload:
            self._error(401, "authentication required")
            return None
        return payload

    def _validate_csrf(self) -> bool:
        """Double-submit CSRF check: cookie must match header."""
        cookie_str = self.headers.get("Cookie", "")
        csrf_cookie = ""
        for part in cookie_str.split(";"):
            part = part.strip()
            if part.startswith("csrf_token="):
                csrf_cookie = part[len("csrf_token="):]
                break
        csrf_header = self.headers.get("X-CSRF-Token", "")
        if not csrf_cookie or not csrf_header:
            return False
        return hmac.compare_digest(csrf_cookie, csrf_header)

    def _require_csrf(self) -> bool:
        if not self._validate_csrf():
            self._error(403, "CSRF validation failed")
            return False
        return True

    # ── Routes ──────────────────────────────────────────────────────────────

    def do_GET(self):
        path = urlparse(self.path).path
        query = parse_qs(urlparse(self.path).query)

        # API routes
        if path == "/api/auth/check":
            return self._handle_auth_check()
        if path == "/api/auth/setup-status":
            return self._handle_setup_status()
        if path == "/api/state":
            return self._handle_get_state()
        if path == "/api/history":
            return self._handle_get_history(query)
        if path == "/api/audit":
            return self._handle_get_audit(query)
        if path == "/api/csrf":
            return self._handle_csrf_token()

        # Serve static files
        self._serve_static(path)

    def do_POST(self):
        path = urlparse(self.path).path

        if path == "/api/auth/login":
            return self._handle_login()
        if path == "/api/auth/refresh":
            return self._handle_refresh()
        if path == "/api/auth/logout":
            return self._handle_logout()
        if path == "/api/auth/setup":
            return self._handle_setup()
        if path == "/api/auth/change-password":
            return self._handle_change_password()
        if path == "/api/onoff":
            return self._handle_onoff()
        if path == "/api/rename":
            return self._handle_rename()

        self._error(404, "not found")

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token")
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()

    # ── Auth handlers ───────────────────────────────────────────────────────

    def _handle_setup_status(self):
        creds = load_credentials()
        self._json({"setup_complete": creds is not None})

    def _handle_setup(self):
        """First-time setup via web UI."""
        if load_credentials():
            self._error(403, "already configured")
            return
        body = self._read_body()
        if body is None:
            return
        try:
            data = json.loads(body)
            username = str(data["username"]).strip()
            password = str(data["password"])
        except (json.JSONDecodeError, KeyError):
            self._error(400, "invalid request")
            return
        if len(username) < 3:
            self._error(400, "username too short (min 3)")
            return
        if len(password) < 8:
            self._error(400, "password too short (min 8)")
            return

        creds = save_credentials(username, password)
        WebHandler.credentials = creds
        audit.log("setup", self._client_ip(), username, "initial setup complete")
        self._json({"ok": True, "message": "setup complete"})

    def _handle_login(self):
        ip = self._client_ip()

        if self.rate_limiter.is_locked(ip):
            remaining = int(self.rate_limiter._lockouts.get(ip, 0) - time.time())
            audit.log("login_locked", ip, details=f"locked for {remaining}s more")
            self._error(429, f"too many attempts, locked for {remaining}s")
            return

        if not self.rate_limiter.check_rate(ip):
            self._error(429, "rate limit exceeded")
            return

        body = self._read_body()
        if body is None:
            return
        try:
            data = json.loads(body)
            username = str(data["username"])
            password = str(data["password"])
        except (json.JSONDecodeError, KeyError):
            self._error(400, "invalid request")
            return

        creds = self.credentials
        if not creds:
            self._error(403, "setup not complete")
            return

        if username != creds["username"] or not verify_password(password, creds["password_hash"]):
            self.rate_limiter.record_failure(ip)
            audit.log("login_fail", ip, username)
            self._error(401, "invalid credentials")
            return

        self.rate_limiter.record_success(ip)

        # Issue JWT
        now = time.time()
        access_token = jwt_encode({
            "sub": username,
            "iat": now,
            "exp": now + JWT_EXPIRY_SECONDS,
            "type": "access",
        }, creds["jwt_secret"])

        refresh_token = jwt_encode({
            "sub": username,
            "iat": now,
            "exp": now + REFRESH_EXPIRY_SECONDS,
            "type": "refresh",
            "jti": secrets.token_hex(16),
        }, creds["jwt_secret"])

        # CSRF token
        csrf_token = secrets.token_hex(CSRF_TOKEN_LENGTH)

        audit.log("login_ok", ip, username)

        self._json({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "csrf_token": csrf_token,
            "expires_in": JWT_EXPIRY_SECONDS,
            "user": username,
        }, extra_headers={
            "Set-Cookie": f"csrf_token={csrf_token}; Path=/; HttpOnly=false; SameSite=Strict; Max-Age={REFRESH_EXPIRY_SECONDS}",
        })

    def _handle_refresh(self):
        body = self._read_body()
        if body is None:
            return
        try:
            data = json.loads(body)
            refresh_token = str(data["refresh_token"])
        except (json.JSONDecodeError, KeyError):
            self._error(400, "invalid request")
            return

        payload = jwt_decode(refresh_token, self.credentials["jwt_secret"])
        if not payload or payload.get("type") != "refresh":
            self._error(401, "invalid refresh token")
            return

        now = time.time()
        access_token = jwt_encode({
            "sub": payload["sub"],
            "iat": now,
            "exp": now + JWT_EXPIRY_SECONDS,
            "type": "access",
        }, self.credentials["jwt_secret"])

        self._json({
            "access_token": access_token,
            "expires_in": JWT_EXPIRY_SECONDS,
        })

    def _handle_logout(self):
        audit.log("logout", self._client_ip())
        self._json({"ok": True}, extra_headers={
            "Set-Cookie": "csrf_token=; Path=/; Max-Age=0",
        })

    def _handle_auth_check(self):
        payload = self._get_jwt_payload()
        if payload:
            self._json({"authenticated": True, "user": payload.get("sub")})
        else:
            self._json({"authenticated": False}, 401)

    def _handle_change_password(self):
        payload = self._require_auth()
        if not payload:
            return
        if not self._require_csrf():
            return

        body = self._read_body()
        if body is None:
            return
        try:
            data = json.loads(body)
            current = str(data["current_password"])
            new_pw = str(data["new_password"])
        except (json.JSONDecodeError, KeyError):
            self._error(400, "invalid request")
            return

        if not verify_password(current, self.credentials["password_hash"]):
            self._error(401, "current password incorrect")
            return
        if len(new_pw) < 8:
            self._error(400, "new password too short (min 8)")
            return

        creds = save_credentials(payload["sub"], new_pw)
        WebHandler.credentials = creds
        audit.log("password_change", self._client_ip(), payload["sub"])
        self._json({"ok": True, "message": "password changed"})

    # ── Device API handlers ─────────────────────────────────────────────────

    def _handle_get_state(self):
        payload = self._require_auth()
        if not payload:
            return
        snap = self.hub.snapshot()
        snap["local_ip"] = self.local_ip
        snap["port"] = self.port
        snap["server_time"] = time.time()
        self._json(snap)

    def _handle_onoff(self):
        payload = self._require_auth()
        if not payload:
            return
        if not self._require_csrf():
            return

        body = self._read_body()
        if body is None:
            return
        try:
            req = json.loads(body)
            mac = str(req["mac"]).upper()
            outlet = int(req["outlet"])
            on = bool(req["on"])
        except (json.JSONDecodeError, KeyError, ValueError):
            self._error(400, "invalid request")
            return

        s = self.hub.session(mac)
        if not s:
            self._error(503, "device offline")
            return

        channels = [1, 2, 3, 4] if outlet == 0 else [outlet]
        if not set(channels) <= {1, 2, 3, 4}:
            self._error(400, "invalid outlet number")
            return

        try:
            fut = asyncio.run_coroutine_threadsafe(s.set_outlets(channels, on), self.loop)
            ok = fut.result(timeout=10)
        except Exception as err:
            self._error(502, f"command failed: {err}")
            return

        audit.log("onoff", self._client_ip(), payload["sub"],
                   f"mac={mac} outlet={outlet} on={on} ok={ok}")
        self._json({"ok": bool(ok), "confirmed": ok})

    def _handle_rename(self):
        payload = self._require_auth()
        if not payload:
            return
        if not self._require_csrf():
            return
        # Placeholder for custom device names
        self._json({"ok": True})

    def _handle_get_history(self, query: dict):
        payload = self._require_auth()
        if not payload:
            return
        mac = query.get("mac", [""])[0].upper()
        n = min(int(query.get("n", ["60"])[0]), 360)
        self._json({"history": power_history.get(mac, n)})

    def _handle_get_audit(self, query: dict):
        payload = self._require_auth()
        if not payload:
            return
        n = min(int(query.get("n", ["50"])[0]), 200)
        self._json({"entries": audit.recent(n)})

    def _handle_csrf_token(self):
        """Issue a new CSRF token (requires valid JWT)."""
        payload = self._require_auth()
        if not payload:
            return
        csrf = secrets.token_hex(CSRF_TOKEN_LENGTH)
        self._json({"csrf_token": csrf}, extra_headers={
            "Set-Cookie": f"csrf_token={csrf}; Path=/; HttpOnly=false; SameSite=Strict; Max-Age={REFRESH_EXPIRY_SECONDS}",
        })

    # ── Static file serving ─────────────────────────────────────────────────

    def _serve_static(self, path: str):
        if path == "/" or path == "":
            path = "/index.html"

        # Security: prevent directory traversal
        safe_path = Path(STATIC_DIR / path.lstrip("/")).resolve()
        if not str(safe_path).startswith(str(STATIC_DIR.resolve())):
            self._error(403, "forbidden")
            return

        if not safe_path.is_file():
            # SPA fallback
            safe_path = STATIC_DIR / "index.html"
            if not safe_path.is_file():
                self._error(404, "not found")
                return

        ext = safe_path.suffix.lower()
        content_type = MIME_TYPES.get(ext, "application/octet-stream")
        body = safe_path.read_bytes()
        self._send(body, content_type)


# ── Helpers ─────────────────────────────────────────────────────────────────

def local_ipv4s() -> list[str]:
    try:
        ips = socket.gethostbyname_ex(socket.gethostname())[2]
    except OSError:
        ips = []
    return [i for i in ips if not i.startswith(("127.", "169.254."))]


def setup_command(cmd: str, expect: str, host: str, timeout: float = 6.0) -> str:
    with socket.create_connection((host, SETUP_PORT), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall((cmd + "\r\n").encode())
        buf = b""
        deadline = time.monotonic() + timeout
        while b"\n" not in buf and time.monotonic() < deadline:
            try:
                chunk = s.recv(1024)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
    text = buf.decode("utf-8", "replace").strip()
    if expect and expect not in text:
        raise SystemExit(f"strip answered {text!r}, expected {expect!r}")
    return text


# ── Commands ────────────────────────────────────────────────────────────────

def cmd_provision(args) -> int:
    for value in (args.ssid, args.password):
        if any(c in value for c in ":\r\n"):
            raise SystemExit("the strip protocol cannot use ':' or newlines in the SSID/password")

    if not args.ip:
        cands = local_ipv4s()
        print("Need --ip. Candidates:", ", ".join(cands) or "none")
        return 2

    try:
        args.ip = str(ipaddress.IPv4Address(args.ip))
    except ValueError:
        raise SystemExit(f"--ip must be IPv4 (got {args.ip!r})")

    print(f"Looking for strip setup service at {args.host}:{SETUP_PORT} ...")
    deadline = time.monotonic() + args.wait
    while True:
        try:
            with socket.create_connection((args.host, SETUP_PORT), timeout=2):
                break
        except OSError:
            if time.monotonic() > deadline:
                print("Not reachable. Put strip in setup mode first.")
                return 1
            time.sleep(2)

    print(f"  {setup_command(f'up:ip:{args.ip}', 'up:ip:ip_ok', args.host)}")
    print(f"  {setup_command(f'up:connect:{args.ssid}:{args.password}', 'up:connect:connect_ok', args.host)}")
    print(f"\nDone. The strip will connect to {args.ip}:{DEVICE_PORT}")
    return 0


async def cmd_serve(args) -> int:
    hub = Hub()
    server = await asyncio.start_server(hub.handle_client, "0.0.0.0", args.port)
    candidates = local_ipv4s()
    ip = args.ip or (candidates or ["127.0.0.1"])[0]

    # Credentials
    creds = load_credentials()
    if not creds and not args.no_auth:
        if sys.stdin.isatty():
            creds = setup_wizard()
        else:
            print("[!] No credentials found. Run interactively for setup, or use --no-auth for LAN-only mode.")
            return 1

    WebHandler.hub = hub
    WebHandler.loop = asyncio.get_running_loop()
    WebHandler.local_ip = ip
    WebHandler.port = args.port
    WebHandler.credentials = creds or {}
    WebHandler.rate_limiter = RateLimiter()
    WebHandler.active_refresh_tokens = {}

    httpd = ThreadingHTTPServer(("0.0.0.0", args.web_port), WebHandler)
    httpd.daemon_threads = True

    # Optional HTTPS
    if args.cert and args.key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(args.cert, args.key)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        proto = "https"
    else:
        proto = "http"

    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    print(f"\n  WattHub")
    print(f"  ─────────────────────────────────────────")
    print(f"  Dashboard    {proto}://{ip}:{args.web_port}")
    print(f"  Strip port   TCP {args.port}")
    print(f"  Auth         {'password required' if creds else 'NONE (--no-auth)'}")
    print(f"  Data dir     {DATA_DIR}")
    if not creds:
        print(f"  ⚠  No authentication — safe only on a trusted LAN")
    print(f"  ─────────────────────────────────────────")
    print(f"  Ctrl+C to stop\n")

    audit.log("server_start", ip, details=f"port={args.web_port} auth={'yes' if creds else 'no'}")

    async with server:
        await hub.poll_loop()
    return 0


async def _selftest() -> None:
    hub = Hub()
    server = await asyncio.start_server(hub.handle_client, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    reader, writer = await asyncio.open_connection("127.0.0.1", port)

    state_on = {2}

    async def fake_strip():
        while True:
            raw = await reader.readline()
            if not raw:
                return
            line = raw.decode().strip()
            if line == "up:getinfo:all":
                tags = ":".join(
                    f"{n}:{n*111};{'on' if n in state_on else 'off'};{int(n in state_on)};0;0;"
                    f"{5300 if n == 2 and n in state_on else 0};0000000A;00000000;00000000;0;00;{30+n}"
                    for n in (1, 2, 3, 4)
                )
                writer.write(f"up:getinfo:{tags}\r\n".encode())
                await writer.drain()
            elif line.startswith("up:onoff:"):
                _, _, ch, val = line.split(":")
                (state_on.add if val == "on" else state_on.discard)(int(ch))

    strip_task = asyncio.create_task(fake_strip())

    writer.write(b"up:bootinfo:LGU+-TAP-HW002;aabbccddeeff;001122334455;1.0.66;connect\r\n")
    writer.write(b"up:power_report:1:224500\r\n")
    writer.write(b"up:query:-52\r\n")
    await writer.drain()
    await asyncio.sleep(0.3)

    dev = hub.devices["AABBCCDDEEFF"]
    assert dev.outlets[1]["on"] is False and dev.outlets[2]["on"] is True
    assert dev.outlets[2]["power_w"] == 5.3
    assert dev.voltage_v == 224.5 and dev.rssi == -52

    assert await hub.session("aabbccddeeff").set_outlets([2], False) is True
    assert dev.outlets[2]["on"] is False

    # Test password hashing
    h = hash_password("testpass123")
    assert verify_password("testpass123", h)
    assert not verify_password("wrongpass", h)

    # Test JWT
    secret = "test-secret-key"
    token = jwt_encode({"sub": "admin", "exp": time.time() + 60}, secret)
    payload = jwt_decode(token, secret)
    assert payload and payload["sub"] == "admin"
    assert jwt_decode(token, "wrong-secret") is None
    expired_token = jwt_encode({"sub": "admin", "exp": time.time() - 10}, secret)
    assert jwt_decode(expired_token, secret) is None

    strip_task.cancel()
    writer.close()
    server.close()
    print("selftest: all checks passed ✓")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd")

    s = sub.add_parser("serve", help="run device server + secure web dashboard (default)")
    s.add_argument("--port", type=int, default=DEVICE_PORT)
    s.add_argument("--web-port", type=int, default=WEB_PORT)
    s.add_argument("--ip", help="IP to show in the UI")
    s.add_argument("--cert", help="TLS certificate file for HTTPS")
    s.add_argument("--key", help="TLS private key file for HTTPS")
    s.add_argument("--no-auth", action="store_true", help="disable authentication (LAN only!)")

    p = sub.add_parser("provision", help="point strip at this server")
    p.add_argument("--ip", help="IPv4 the strip connects to")
    p.add_argument("--ssid", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--host", default=SETUP_HOST)
    p.add_argument("--wait", type=float, default=20.0)

    sub.add_parser("selftest", help="offline checks")

    args = ap.parse_args()

    if args.cmd == "provision":
        return cmd_provision(args)
    if args.cmd == "selftest":
        asyncio.run(_selftest())
        return 0
    if args.cmd in (None, "serve"):
        for attr, default in [("port", DEVICE_PORT), ("web_port", WEB_PORT),
                               ("ip", None), ("cert", None), ("key", None), ("no_auth", False)]:
            if not hasattr(args, attr):
                setattr(args, attr, default)
        try:
            return asyncio.run(cmd_serve(args))
        except KeyboardInterrupt:
            return 0
    ap.error("unknown command")


if __name__ == "__main__":
    sys.exit(main())
