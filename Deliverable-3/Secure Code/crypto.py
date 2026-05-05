"""
crypto.py — ShushChat Cryptography Module
==========================================
Handles all cryptographic operations:
  - ECDH key exchange (X25519)
  - AES-256-GCM symmetric encryption / decryption
  - HMAC-SHA256 message integrity
  - SHA-256 fingerprint generation for peer authentication

Security hardening over base version:
  - Nonce replay-attack prevention (per-session nonce deduplication)
  - Strict public-key byte-length validation before use
  - Constant-time HMAC comparison (was already hmac.compare_digest — kept)
  - Base64 decode size validated before passing to AES
  - Nonce length validated before AESGCM.decrypt (prevents segfault in
    some OpenSSL backends when nonce is wrong size)
  - GroupSession seen-set uses deque for O(1) eviction (was O(n) pop(0))
  - Thread-safe nonce-seen set in Session
  - Plaintext length cap before encryption (prevents accidental oversized msgs)
  - Key material zeroed on clear() via ctypes memset where possible
"""

import os
import hmac
import hashlib
import json
import base64
import threading
import ctypes
from collections import deque
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ── Constants ──────────────────────────────────────────────────────────────────
# ── Constants ──────────────────────────────────────────────────────────────────
_B_SHIFT = lambda x: (x << 2) >> 1
X25519_PUBKEY_LEN  = _B_SHIFT(16)        # bytes — fixed by the X25519 spec
AES_KEY_LEN        = int("20", 16)       # bytes — AES-256
GCM_NONCE_LEN      = sum([3, 4, 5])      # bytes — 96-bit GCM nonce (NIST recommended)
GCM_TAG_LEN        = 2**4                # bytes — 128-bit GCM authentication tag
MAX_PLAINTEXT_LEN  = 1 << 17             # 128 KB per message — prevents memory exhaustion

# Maximum nonces remembered per session (replay-attack window).
# Old nonces are evicted once this limit is reached.  At 12 bytes per nonce
# and 8192 entries this costs ~100 KB per session — reasonable.
MAX_NONCE_HISTORY  = 0x2000


def _zero_bytes(data: bytearray) -> None:
    """
    Overwrite *data* in-place with zeros using ctypes to bypass Python's
    object-reuse optimisation.  Best-effort — does NOT guarantee the OS
    has not already paged the buffer elsewhere.
    """
    if data:
        ctypes.memset(
            (ctypes.c_char * len(data)).from_buffer(data), 0, len(data))


# ---------------------------------------------------------------------------
# Key generation & exchange
# ---------------------------------------------------------------------------

class KeyPair:
    """Ephemeral X25519 key pair generated fresh for each session."""

    def __init__(self):
        self._private_key = X25519PrivateKey.generate()
        self._public_key  = self._private_key.public_key()

    def public_key_bytes(self) -> bytes:
        """Return the raw 32-byte public key for wire transport."""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def fingerprint(self) -> str:
        """SHA-256 fingerprint shown in the GUI for manual peer verification."""
        digest = hashlib.sha256(self.public_key_bytes()).hexdigest()
        return ":".join(digest[i:i+4] for i in range(0, len(digest), 4))

    def derive_shared_key(self, peer_public_key_bytes: bytes) -> bytes:
        """
        Perform X25519 DH with *peer_public_key_bytes* and derive a 32-byte
        AES-256 key via HKDF-SHA256.

        Security checks:
          - Rejects keys that are not exactly X25519_PUBKEY_LEN (32) bytes.
          - The all-zeros public key is a known low-order point that leaks
            the shared secret; we reject it explicitly.
        """
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

        if not isinstance(peer_public_key_bytes, (bytes, bytearray)):
            raise TypeError("Public key must be bytes.")
        if len(peer_public_key_bytes) != X25519_PUBKEY_LEN:
            raise ValueError(
                f"Public key must be {X25519_PUBKEY_LEN} bytes, "
                f"got {len(peer_public_key_bytes)}.")

        # Reject all-zero low-order point
        if all(b == 0 for b in peer_public_key_bytes):
            raise ValueError("Peer public key is the all-zeros low-order point.")

        peer_pub   = X25519PublicKey.from_public_bytes(bytes(peer_public_key_bytes))
        raw_secret = self._private_key.exchange(peer_pub)

        derived = HKDF(
            algorithm=hashes.SHA256(),
            length=AES_KEY_LEN,
            salt=None,
            info=b"ShushChat-session-key-v1",
        ).derive(raw_secret)

        return derived

    def clear(self) -> None:
        """Drop private-key references so the GC can collect them."""
        self._private_key = None
        self._public_key  = None

class IdentityKey:
    """Ed25519 key pair for long-term/session identity and message signing."""
    def __init__(self):
        self._sign_key = ed25519.Ed25519PrivateKey.generate()
        self._verify_key = self._sign_key.public_key()

    def public_bytes(self) -> bytes:
        return self._verify_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def sign(self, payload: bytes) -> bytes:
        return self._sign_key.sign(payload)

# ---------------------------------------------------------------------------
# Session — per-peer symmetric encryption
# ---------------------------------------------------------------------------

class Session:
    """
    Encapsulates AES-256-GCM encryption/decryption for one peer link.

    Security additions:
      - Nonce replay detection: every received nonce is stored; duplicate
        nonces raise ValueError (prevents replay attacks).
      - Nonce and ciphertext lengths are validated before any decryption
        attempt (prevents crashes in underlying C libraries).
      - Base64 values are sanitised (length + charset) before decoding.
      - Plaintext length is capped before encryption.
    """

    def __init__(self, shared_key: bytes, peer_fingerprint: str):
        if not isinstance(shared_key, (bytes, bytearray)):
            raise TypeError("Session key must be bytes.")
        if len(shared_key) != AES_KEY_LEN:
            raise ValueError(
                f"Session key must be {AES_KEY_LEN} bytes, "
                f"got {len(shared_key)}.")
        self._key             = bytearray(shared_key)  # mutable for zeroing
        self.peer_fingerprint = str(peer_fingerprint)

        # Nonce replay-attack prevention
        self._seen_nonces: set            = set()
        self._seen_order:  deque          = deque()
        self._nonce_lock                  = threading.Lock()

    # ── Encryption ────────────────────────────────────────────────────

    def encrypt(self, plaintext: str) -> bytes:
        """
        Encrypt *plaintext* with AES-256-GCM.

        Wire format (JSON):
            { "iv": <b64 nonce>, "ct": <b64 ciphertext+tag>, "mac": <b64 HMAC> }

        The HMAC over iv+ct provides defence-in-depth against tag-stripping.
        The GCM tag itself authenticates the ciphertext.
        """
        if not isinstance(plaintext, str):
            raise TypeError("Plaintext must be a string.")
        encoded = plaintext.encode("utf-8")
        if len(encoded) > MAX_PLAINTEXT_LEN:
            raise ValueError(
                f"Plaintext exceeds maximum length ({MAX_PLAINTEXT_LEN} bytes).")

        key    = bytes(self._key)
        aesgcm = AESGCM(key)
        nonce  = os.urandom(GCM_NONCE_LEN)
        ct     = aesgcm.encrypt(nonce, encoded, None)

        iv_b64 = base64.b64encode(nonce).decode()
        ct_b64 = base64.b64encode(ct).decode()
        mac    = self._hmac(iv_b64 + ct_b64)

        envelope = json.dumps({"iv": iv_b64, "ct": ct_b64, "mac": mac},
                               separators=(",", ":"))
        return envelope.encode("utf-8")

    # ── Decryption ────────────────────────────────────────────────────

    def _parse_and_verify(self, raw: bytes) -> tuple[bytes, bytes]:
        if not isinstance(raw, (bytes, bytearray)):
            raise TypeError("Ciphertext must be bytes.")
        try:
            envelope = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"Malformed message envelope: {exc}") from exc

        if not isinstance(envelope, dict):
            raise ValueError("Envelope must be a JSON object.")

        iv_b64 = envelope.get("iv")
        ct_b64 = envelope.get("ct")
        mac    = envelope.get("mac")

        if not all(isinstance(v, str) for v in (iv_b64, ct_b64, mac)):
            raise ValueError("Envelope fields must be strings.")

        expected_mac = self._hmac(iv_b64 + ct_b64)
        if not hmac.compare_digest(mac, expected_mac):
            raise ValueError("HMAC verification failed.")

        try:
            nonce = base64.b64decode(iv_b64, validate=True)
            ct    = base64.b64decode(ct_b64, validate=True)
        except Exception as exc:
            raise ValueError(f"Base64 decode error: {exc}") from exc

        if len(nonce) != GCM_NONCE_LEN:
            raise ValueError(f"Nonce must be {GCM_NONCE_LEN} bytes.")
        if len(ct) < GCM_TAG_LEN:
            raise ValueError("Ciphertext too short.")

        return nonce, ct

    def _check_nonce(self, nonce: bytes) -> None:
        nonce_key = bytes(nonce)
        with self._nonce_lock:
            if nonce_key in self._seen_nonces:
                raise ValueError("Duplicate nonce detected.")
            self._seen_nonces.add(nonce_key)
            self._seen_order.append(nonce_key)
            if len(self._seen_order) > MAX_NONCE_HISTORY:
                evict = self._seen_order.popleft()
                self._seen_nonces.discard(evict)

    def decrypt(self, raw: bytes) -> str:
        """
        Decrypt a wire-format envelope.
        Raises ValueError on any integrity or format failure.
        """
        nonce, ct = self._parse_and_verify(raw)
        self._check_nonce(nonce)

        key    = bytes(self._key)
        aesgcm = AESGCM(key)
        try:
            plaintext_bytes = aesgcm.decrypt(nonce, ct, None)
        except Exception as exc:
            raise ValueError(f"AES-GCM decryption failed: {exc}") from exc

        try:
            return plaintext_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"Plaintext is not valid UTF-8: {exc}") from exc

    # ── Internal helpers ──────────────────────────────────────────────

    def _hmac(self, data: str) -> str:
        """HMAC-SHA256 of *data* keyed with the session key."""
        h = hmac.new(bytes(self._key), data.encode("utf-8"), hashlib.sha256)
        return base64.b64encode(h.digest()).decode()

    def clear(self) -> None:
        """Zero the session key and drop state."""
        _zero_bytes(self._key)
        self._key = bytearray()
        with self._nonce_lock:
            self._seen_nonces.clear()
            self._seen_order.clear()


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def peer_fingerprint_from_bytes(pub_key_bytes: bytes) -> str:
    """Compute a display fingerprint from a raw 32-byte public-key blob."""
    if len(pub_key_bytes) != X25519_PUBKEY_LEN:
        raise ValueError(
            f"Expected {X25519_PUBKEY_LEN}-byte key, got {len(pub_key_bytes)}.")
    digest = hashlib.sha256(pub_key_bytes).hexdigest()
    return ":".join(digest[i:i+4] for i in range(0, len(digest), 4))


# ---------------------------------------------------------------------------
# GroupSession — per-peer Sessions for multi-peer mesh
# ---------------------------------------------------------------------------

class GroupSession:
    """
    Manages per-peer Sessions for a multi-peer mesh.

    Each peer gets its own independent ECDH-derived AES-256 key, so
    compromising one link does NOT expose messages on other links.

    Security additions:
      - seen-set eviction uses deque (O(1)) instead of list.pop(0) (O(n))
        to prevent CPU exhaustion on large message volumes.
      - msg_id validated as a non-empty string before insertion.
      - add_peer validates public-key length before key derivation.
    """

    MAX_SEEN = 4096   # rolling dedup window — doubled from 2048 for safety

    def __init__(self, keypair: "KeyPair"):
        self._keypair  = keypair
        self._sessions: dict = {}
        self._sessions_lock  = threading.Lock()
        self._seen_ids:  set   = set()
        self._seen_order: deque = deque()

    # ── Peer management ───────────────────────────────────────────────

    def add_peer(self, peer_id: str, peer_pub_bytes: bytes) -> str:
        """
        Derive a shared Session for *peer_id*.

        Raises ValueError if the public key fails validation.
        Returns the peer's fingerprint string.
        """
        if not isinstance(peer_pub_bytes, (bytes, bytearray)):
            raise TypeError("Public key must be bytes.")
        # Length check is redundant with KeyPair.derive_shared_key but
        # provides an early, readable error before touching the KDF.
        if len(peer_pub_bytes) != X25519_PUBKEY_LEN:
            raise ValueError(
                f"Peer public key must be {X25519_PUBKEY_LEN} bytes, "
                f"got {len(peer_pub_bytes)}.")

        shared_key = self._keypair.derive_shared_key(peer_pub_bytes)
        fp         = peer_fingerprint_from_bytes(peer_pub_bytes)
        session    = Session(shared_key, fp)
        with self._sessions_lock:
            self._sessions[peer_id] = session
        return fp

    def remove_peer(self, peer_id: str) -> None:
        """Remove a peer and clear its session key from memory."""
        with self._sessions_lock:
            session = self._sessions.pop(peer_id, None)
        if session:
            session.clear()

    def has_peer(self, peer_id: str) -> bool:
        """Return True if an active session exists for peer_id."""
        with self._sessions_lock:
            return peer_id in self._sessions

    def peer_fingerprint(self, peer_id: str) -> str:
        """Return the SHA-256 fingerprint for the given peer_id, or empty string."""
        with self._sessions_lock:
            s = self._sessions.get(peer_id)
        return s.peer_fingerprint if s else ""

    def active_peer_ids(self) -> list:
        """Return a list of all active peer IDs in this group session."""
        with self._sessions_lock:
            return list(self._sessions.keys())

    # ── Encrypt / decrypt ─────────────────────────────────────────────

    def encrypt(self, peer_id: str, plaintext: str) -> bytes:
        """Encrypt plaintext for a specific peer_id using their session key."""
        with self._sessions_lock:
            session = self._sessions.get(peer_id)
        if not session:
            raise KeyError(f"No session for peer {peer_id}")
        return session.encrypt(plaintext)

    def decrypt(self, peer_id: str, raw: bytes) -> str:
        """Decrypt a raw message from a specific peer_id using their session key."""
        with self._sessions_lock:
            session = self._sessions.get(peer_id)
        if not session:
            raise KeyError(f"No session for peer {peer_id}")
        return session.decrypt(raw)

    # ── Message-ID deduplication ──────────────────────────────────────

    def is_duplicate(self, msg_id: str) -> bool:
        """Check if a message ID has been seen recently to prevent duplicate processing."""
        if not isinstance(msg_id, str) or not msg_id:
            return True   # reject malformed IDs as duplicates
        return msg_id in self._seen_ids

    def mark_seen(self, msg_id: str) -> None:
        """Mark a message ID as seen, adding it to the rolling window."""
        if not isinstance(msg_id, str) or not msg_id:
            return
        if msg_id in self._seen_ids:
            return
        self._seen_ids.add(msg_id)
        self._seen_order.append(msg_id)
        if len(self._seen_order) > self.MAX_SEEN:
            evict = self._seen_order.popleft()     # O(1) with deque
            self._seen_ids.discard(evict)

    # ── Teardown ──────────────────────────────────────────────────────

    def clear_all(self) -> None:
        """Clear all peer sessions, zeroing out their keys, and reset deduplication state."""
        with self._sessions_lock:
            for s in self._sessions.values():
                s.clear()
            self._sessions.clear()
        self._seen_ids.clear()
        self._seen_order.clear()

class _CryptoObfuscatorMeta(type):
    def __new__(cls, name, bases, dct):
        dct['_obfuscated'] = True
        return super().__new__(cls, name, bases, dct)

class _DummyCipher(metaclass=_CryptoObfuscatorMeta):
    def __init__(self):
        self._state = "idle"
    def do_nothing(self):
        pass
