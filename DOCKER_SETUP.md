# WattHub Secure Docker Deployment Guide

We provide two flexible deployment options depending on your preference and current server setup. 

---

## 🚀 Option A: Standalone with Caddy (Default)

This is the default `docker-compose.yml` and is the easiest way to deploy if you have a fresh server. It uses **Caddy** to automatically handle SSL/HTTPS encryption.

### Step 1: Configure Environment Variables

```bash
cp .env.example .env
nano .env
```

1. **Admin Credentials**: Set your desired `ADMIN_USERNAME` and `ADMIN_PASSWORD`.
2. **Encryption Mode**:
   - **Self-Signed (No Domain):** Leave `DOMAIN=:443` and `TLS_EMAIL=internal`. *(Your browser will show a "Not Secure" warning which is normal, click "Proceed to site")*.
   - **Official SSL (Requires Domain):** Uncomment and set `DOMAIN=power.yourdomain.com` and `TLS_EMAIL=your-email@example.com`.

### Step 2: Start the Server

```bash
docker-compose up -d --build
```

---

## 🚀 Option B: Behind Nginx (Host Network Mode)

Use this method if you already have **Nginx** running on your server and want to use it as a reverse proxy, or if you prefer using Certbot manually.

### Step 1: Configure Environment Variables

```bash
cp .env.example .env
nano .env
```
Set your `ADMIN_USERNAME` and `ADMIN_PASSWORD`. (You can ignore the `DOMAIN` and `TLS_EMAIL` variables in this mode).

### Step 2: Start the Server

Use the alternative Docker Compose file:
```bash
docker-compose -f docker-compose.nginx.yml up -d --build
```

### Step 3: Configure Nginx

Proxy your domain to `http://127.0.0.1:8080`, and then run `certbot --nginx -d yourdomain.com` to secure it.

---

## 🔌 Provision Your Smart Strip (From your Laptop)

**CRITICAL:** You must run this command from a device that has a physical WiFi card (like your personal laptop or phone). You **cannot** run this from your cloud server (VPS).

1. Hold the physical button on the smart strip for ~10 seconds until the LED blinks fast.
2. From your **personal laptop**, connect to the WiFi network the strip broadcasts (e.g., `TONLY_TAP_...`).
3. Open a terminal on your laptop, navigate to your cloned `WattHub` repo, and run:
```bash
python server.py provision --ip YOUR_VPS_IP --ssid "YOUR_HOME_WIFI" --password "YOUR_HOME_WIFI_PASSWORD"
```

---

## 📊 Useful Commands

### View Logs
```bash
docker logs -f watthub
```

### Stop the Server
```bash
docker-compose down
```
