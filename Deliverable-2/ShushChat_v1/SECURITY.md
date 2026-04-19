# ShushChat — Security Implementation Summary

## Overview

ShushChat v3 has been hardened against a comprehensive set of attack vectors
while preserving 100% of its P2P mesh functionality.  The table below maps
every vulnerability class to the specific code that mitigates it.

---

## 1. Buffer-Overflow / Memory-Exhaustion Prevention

| Attack | Mitigation | File | Detail |
|---|---|---|---|
| Oversized frame injection | `MAX_MSG_SIZE = 512 KB` hard cap (down from 10 MB) | `networking.py` | `_validate_frame_length()` rejects length fields BEFORE allocating any buffer |
| Length-field read-before-validate | Length decoded from header, validated, THEN recv called | `networking.py` | `_recv_framed()` — prevents OOM via crafted big-endian length |
| Zero-length frame flood | `MIN_MSG_SIZE = 1` check | `networking.py` | Empty frames rejected on send and receive |
| Send-side oversized message | Outgoing length checked in `_send_framed()` | `networking.py` | Sender and receiver caps kept in sync |
| Plaintext too large before encrypt | `MAX_PLAINTEXT_LEN = 128 KB` enforced in `Session.encrypt()` | `crypto.py` | Prevents accidental/malicious memory exhaustion via huge strings |
| GCM ciphertext too short | `len(ct) >= GCM_TAG_LEN` check before decrypt | `crypto.py` | Prevents underlying C-lib crash on malformed input |
| Nonce wrong size | `len(nonce) == GCM_NONCE_LEN` checked before decrypt | `crypto.py` | Some OpenSSL backends segfault on wrong-size nonces |

---

## 2. Input Validation

| Input | Validation | File |
|---|---|---|
| IP address (UI + peer-list) | `ipaddress.ip_address()` — rejects hostnames and malformed strings | `networking.py`, `gui.py` |
| Port (UI + peer-list + handshake) | `1 ≤ port ≤ 65535` integer check | `networking.py`, `gui.py` |
| Peer public key (handshake) | Exactly 64 hex chars (= 32 raw bytes), all-zero rejected | `gui.py`, `crypto.py` |
| `msg_id` | UUID v4 regex — rejects crafted IDs that could bypass deduplication | `gui.py` |
| `pw_hash` in chat messages | Must be 64-char lowercase hex or empty string | `gui.py` |
| Room name | Stripped, control-chars removed, max 32 chars, safe-char regex | `gui.py` |
| Username | Stripped, control-chars removed, max 24 chars | `gui.py` |
| Message text | Printable chars + `\n`/`\t` only, max 4096 chars | `gui.py` |
| Handshake JSON | Must decode as UTF-8, must be a `dict`, all fields type-checked | `gui.py` |
| Peer-list entries | Each entry must be a `dict`; IP + port individually validated | `gui.py` |
| `listen_port` in handshake | Integer 1–65535 or `None`; rejects strings | `gui.py` |
| JSON envelope fields | All three fields must be `str`; missing/wrong types → `ValueError` | `crypto.py` |
| Base64 fields | `base64.b64decode(validate=True)` — rejects non-alphabet characters | `crypto.py` |

---

## 3. Replay-Attack Prevention

| Mechanism | Detail | File |
|---|---|---|
| **GCM nonce deduplication** | Every received nonce stored in a rolling set (max 8192 per session); duplicate nonce raises `ValueError` | `crypto.py` — `Session.decrypt()` |
| **Message-ID deduplication** | UUID-format `msg_id` stored in a `deque`-backed set (max 4096 per `GroupSession`); duplicate silently dropped | `crypto.py` — `GroupSession.is_duplicate()` |
| UUID v4 format enforcement | `msg_id` must match UUID v4 regex — prevents crafted "never-seen" IDs used to force re-delivery | `gui.py` |

---

## 4. DoS / Resource-Exhaustion Prevention

| Attack | Mitigation | File |
|---|---|---|
| Connection flood | `MAX_PEERS = 50` hard cap; new sockets rejected when at capacity | `networking.py` |
| Slow-read / Slowloris | `RECV_TIMEOUT_SEC = 30` idle receive timeout per socket | `networking.py` |
| Message flood (count) | Per-peer sliding-window rate limiter: max 30 messages / 5 seconds | `networking.py` — `_RateLimiter` |
| Bandwidth flood | Per-peer rate: max 256 KB / 5 seconds | `networking.py` — `_RateLimiter` |
| Duplicate dial storms | `_connecting` set deduplicates in-flight outbound connects | `networking.py` |
| Huge peer-list | Max 50 entries processed from any single peer-list message | `gui.py` |
| O(n) deque eviction CPU | Replaced `list.pop(0)` with `deque.popleft()` for O(1) eviction | `crypto.py` |

---

## 5. Cryptographic Security

| Property | Implementation |
|---|---|
| Key exchange | X25519 Diffie-Hellman (Curve25519) — forward-secrecy per session |
| Key derivation | HKDF-SHA256 with app-specific `info` tag |
| Symmetric encryption | AES-256-GCM — authenticated encryption (confidentiality + integrity) |
| Envelope MAC | HMAC-SHA256 over `iv + ct` — defence-in-depth against tag stripping |
| HMAC comparison | `hmac.compare_digest()` — constant-time, prevents timing attacks |
| Password comparison | `hmac.compare_digest()` on pw_hash strings — prevents timing-based hash oracle |
| Low-order point rejection | All-zero X25519 public key rejected before KDF | 
| Nonce generation | `os.urandom(12)` — cryptographically secure 96-bit GCM nonce |
| Key zeroing | `ctypes.memset` used to overwrite session key `bytearray` on `clear()` |
| Per-link keys | Each peer link has its own independently derived AES-256 key |

---

## 6. Protocol Security

| Property | Detail |
|---|---|
| No plaintext chat | All chat payloads encrypted before transmission; handshake is the only pre-crypto step |
| Handshake type gate | Only `"handshake"` and `"peer_list"` accepted pre-encryption; anything else discarded |
| Gossip after dedup | Messages are re-forwarded only after deduplication check, preventing amplification |
| Peer-list not secret | Peer-list intentionally plaintext (IP + pubkey); pubkey verified via handshake ECDH |

---

## 7. What Was NOT Changed

The following functionality is **identical** to the original:

- Multi-peer mesh gossip topology
- Room create / join / password flow
- WhatsApp-style GUI layout and dark theme
- X25519 + AES-256-GCM + HMAC-SHA256 wire protocol
- Per-peer independent crypto sessions
- Peer fingerprint display
- Disconnect/reconnect behaviour

---

## Requirements

```
cryptography>=41.0
```
(No new dependencies — all security additions use the Python standard library
and the existing `cryptography` package.)
