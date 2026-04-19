# 🔒 ShushChat — Secure P2P Messenger

A **serverless, end-to-end encrypted** peer-to-peer chat application written in Python.  
No central server. No data logging. No compromise.

---

## 🛠 Requirements

| Component | Version |
|-----------|---------|
| Python    | ≥ 3.8   |
| cryptography (pip) | ≥ 41.0 |
| tkinter   | included with standard Python |

---

## 📦 Installation

```bash
# 1. Clone / download the project folder
cd ShushChat

# 2. Install the only external dependency
pip install -r requirements.txt
```

> **Windows**: Tkinter is bundled with the official Python installer.  
> **Linux**:   `sudo apt install python3-tk`  
> **macOS**:   `brew install python-tk`

---

## 🚀 Running ShushChat

Start the application:

```bash
python main.py
```

---

## 💬 Demo: Two Instances Chatting Locally

Open **two terminals** in the ShushChat directory.

### Terminal 1 — Listener
```bash
python main.py
```
1. Select **"Listen for peer"** radio button  
2. Leave port as **5555**  
3. Click **⚡ Connect**  
4. The status bar shows: `◌ LISTENING…`

### Terminal 2 — Connector
```bash
python main.py
```
1. Select **"Connect to peer"** radio button  
2. IP Address: **127.0.0.1**  
3. Port: **5555**  
4. Click **⚡ Connect**

**Both windows** will show:
```
🔑 Key exchange complete — session key derived.
✅ Secure Connection Established 🔒 — All messages are end-to-end encrypted.
```

You can now type messages and they will appear in real-time on both sides, encrypted via AES-256-GCM over the wire.

---

## 🔐 Security Architecture

```
┌──────────────────────────────────────────────────┐
│                   Peer A                          │
│  X25519 private key  ──►  public key  ──► wire   │
└─────────────────────────────────────────┬─────────┘
                  TCP (plaintext handshake — no secret sent)
┌─────────────────────────────────────────┴─────────┐
│                   Peer B                          │
│  X25519 private key  ──►  public key  ──► wire   │
└──────────────────────────────────────────────────┘
           │                         │
           ▼                         ▼
     ECDH exchange             ECDH exchange
           │                         │
           └──────── shared secret ──┘
                          │
                     HKDF-SHA256
                          │
                    AES-256 session key
                          │
           ┌──────────────┴──────────────┐
           │   AES-256-GCM + HMAC-SHA256 │
           │   encrypts every message    │
           └─────────────────────────────┘
```

### Key Exchange
- Each peer generates a fresh **X25519** (Elliptic Curve Diffie-Hellman) key pair on startup.
- Public keys are exchanged in plaintext — **this is safe**: the shared secret cannot be computed without the private key, which never leaves either device.
- The raw DH output is fed through **HKDF-SHA256** to produce a proper 32-byte AES-256 key.

### Encryption
- Every message is encrypted with **AES-256-GCM** using a fresh 12-byte random nonce.
- GCM mode provides both **confidentiality** and **authenticated encryption** (built-in integrity tag).
- An additional **HMAC-SHA256** layer wraps the entire JSON envelope for defence-in-depth.

### Authentication
- Each peer's public key is hashed with **SHA-256** to produce a human-readable fingerprint.
- Fingerprints are displayed in both GUIs — users should **verbally compare** them (e.g., over a phone call) to verify they are talking to the right person and not a man-in-the-middle.

### Interception Test
If you capture the raw bytes on the wire (e.g., with Wireshark or `tcpdump`), you will see binary garbage — the AES-256-GCM ciphertext — not readable text.

---

## 📁 Code Structure

```
ShushChat/
├── main.py          Entry point — boots Tkinter, starts the app
├── gui.py           All UI logic: widgets, event handlers, display formatting
├── networking.py    TCP socket management, framed send/receive, threading
├── crypto.py        X25519 key generation, HKDF derivation, AES-256-GCM, HMAC
├── requirements.txt Python package dependencies
└── README.md        This file
```

---

## ⚠️ Limitations (Student Project Scope)

- Supports **one peer at a time** (1-to-1 chat only).
- No persistent message history — messages are in-memory only.
- No file transfer.
- No NAT traversal — both peers must be on the same local network, or port-forwarding must be configured for internet use.
- The handshake uses plain TCP (no TLS wrapping the ECDH exchange) — MITM during the handshake phase requires comparing fingerprints manually.

---

## 📜 License

Educational / personal use. No warranty.
