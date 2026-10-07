# WattHub Secure Docker Deployment Guide

This setup runs WattHub using Docker on the host network mode, allowing it to seamlessly integrate with your system's `Nginx` for HTTPS/SSL.

## Prerequisites
- Docker & Docker Compose installed
- Port `10086` open on your server's firewall (for the strip connection)
- Nginx installed and configured as a reverse proxy for port `8080` (for the dashboard)

---

## 🚀 Step 1: Configure Environment Variables

Create your `.env` file to set your admin credentials:
```bash
cp .env.example .env
nano .env
```

Edit the `.env` file to set your desired `ADMIN_USERNAME` and `ADMIN_PASSWORD`.
*(If you skip this, the defaults will be `admin` / `admin`)*.

---

## 🚀 Step 2: Start the Server

Run the following command in the WattHub directory:

```bash
docker-compose up -d --build
```

---

## 🔌 Step 3: Provision Your Smart Strip (From your Laptop)

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
