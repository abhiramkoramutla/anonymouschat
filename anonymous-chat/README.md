# SecureChat — Anonymous E2EE Chat Platform

Anonymous, end-to-end encrypted real-time chat. The server **never** sees plaintext — it only relays encrypted blobs and public keys.

## Architecture

- **Backend**: FastAPI + Uvicorn + WebSockets (Python 3.10+)
- **Frontend**: Vanilla JS + Web Crypto API (ECDH P-256 + AES-256-GCM)
- **Encryption**: True E2EE — keys generated in browser, never touch the server

## Quick Start (Windows CMD)

### 1. Check Python version
```cmd
python --version
```
Requires Python 3.10 or higher.

### 2. Navigate to project folder
```cmd
cd anonymous-chat
```

### 3. Create virtual environment
```cmd
python -m venv venv
```

### 4. Activate virtual environment
```cmd
venv\Scripts\activate
```

### 5. Install dependencies
```cmd
pip install -r requirements.txt
```

### 6. Run the server (HTTP)
```cmd
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### 7. Open in browser
```
http://localhost:8000
```
Open **two browser tabs** to test — one for each user.

---

## HTTPS / WSS Setup (Self-Signed Certificate)

### Generate self-signed certificate
```cmd
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"
```
If openssl is not available, install it via: https://slproweb.com/products/Win32OpenSSL.html

### Run with HTTPS
```cmd
uvicorn app.main:app --host 0.0.0.0 --port 8443 --ssl-keyfile key.pem --ssl-certfile cert.pem
```

### Access
```
https://localhost:8443
```
Accept the browser's self-signed certificate warning.

---

## Testing Guide

### Test Random Mode
1. Open `http://localhost:8000` in Tab 1 → enter username "Alice" → Random Chat → Start
2. Open `http://localhost:8000` in Tab 2 → enter username "Bob" → Random Chat → Start
3. Both tabs match, perform ECDH key exchange, enable encrypted chat

### Test Session ID Mode
1. Tab 1: enter username → Session ID → enter "mysecretroom" → Start
2. Tab 2: enter username → Session ID → enter "mysecretroom" → Start
3. Both match via shared session ID

### Verify E2EE (DevTools)
1. Open DevTools → Network → WS tab
2. Click the WebSocket connection
3. Watch Messages tab — you'll see only base64 ciphertext payloads
4. The server **cannot** decrypt these — only the two browsers can

### Test Skip
- In Random Mode, click "Skip" — destroys keys, requeues, finds new partner

### Test Disconnect
- Close one tab — the other sees "Partner disconnected. Session erased."
- All keys and room data are destroyed in memory

---

## Security Properties

| Property | Implementation |
|---|---|
| Key Exchange | ECDH P-256 via Web Crypto API |
| Symmetric Encryption | AES-256-GCM |
| IV | 96-bit random per message |
| Server Knowledge | Zero — relays ciphertext only |
| Key Persistence | None — destroyed on disconnect |
| Data Storage | RAM only, wiped on disconnect |
| Rate Limiting | 10 messages per 5 seconds per connection |
| IP Throttling | 20 connections per 60 seconds per IP |

## Project Structure

```
anonymous-chat/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI app + WebSocket handler
│   ├── connection_manager.py # WebSocket connection registry
│   ├── room_manager.py      # Rooms, matching, relay
│   └── security.py          # Rate limiting + validation
├── static/
│   ├── css/style.css        # Dark theme UI
│   └── js/app.js            # E2EE + WebSocket client
├── templates/
│   ├── index.html           # Landing page
│   └── chat.html            # Chat interface
├── requirements.txt
└── README.md
```
