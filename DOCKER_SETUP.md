# WattHub Secure Docker Deployment Guide (HTTPS)

This setup uses **Caddy** to automatically handle SSL/HTTPS encryption. It supports two modes: Self-Signed (no domain needed) or Let's Encrypt (requires a domain).

## Prerequisites
- Docker & Docker Compose installed
- Ports `80`, `443`, and `10086` open on your server's firewall.

---

## 🚀 Step 1: Choose Your Encryption Mode

Rename the file `.env.example` to `.env`:
```bash
cp .env.example .env
```

Open the `.env` file and choose your mode:

### Mode 1: Self-Signed (No Domain - Default)
Leave the file as is:
```env
DOMAIN=:443
TLS_EMAIL=internal
```
*Note: Your browser will show a "Not Secure / Self-Signed" warning when you visit the page. This is normal because you don't have a domain. The traffic is still 100% encrypted. Just click "Advanced" -> "Proceed to site".*

### Mode 2: Official SSL (Requires a Domain)
Edit the file to look like this:
```env
DOMAIN=power.yourdomain.com
TLS_EMAIL=your-email@example.com
```
*Note: This will automatically generate a free, trusted Let's Encrypt certificate.*

---

## 🚀 Step 2: Start the Server

Run the following command:

```bash
docker-compose up -d --build
```

---

## 🛠️ Step 3: First-Time Setup (Create Admin Account)

1. Open your browser and navigate to **`https://YOUR_IP_OR_DOMAIN`**
2. You will be automatically redirected to the **Setup Screen**.
3. Enter your desired **Username** and a strong **Password**.
4. Click **Create Account**.

---

## 🔌 Step 4: Provision Your Smart Strip

To connect your MTTL-W01 smart strip, run the `provision` command from *inside* the container:

```bash
docker exec -it WattHub python3 server.py provision --ip YOUR_SERVER_IP --ssid "YOUR_WIFI_NAME" --password "YOUR_WIFI_PASSWORD"
```

---

## 📊 Useful Commands

### View Logs
```bash
docker-compose logs -f
```

### Stop the Server
```bash
docker-compose down
```
