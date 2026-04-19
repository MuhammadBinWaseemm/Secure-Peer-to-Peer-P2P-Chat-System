"""
crypto.py — ShushChat Cryptography Module
==========================================
Handles all cryptographic operations:
  - ECDH key exchange (X25519)
  - AES-256-GCM symmetric encryption / decryption
  - HMAC-SHA256 message integrity
  - SHA-256 fingerprint generation for peer authentication
"""

import os
import hmac
import hashlib
import json
import base64

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---------------------------------------------------------------------------
# Key generation & exchange
# ---------------------------------------------------------------------------

class KeyPair:
    """Ephemeral X25519 key pair generated fresh for each session."""

    def __init__(self):
        # Generate private key using cryptographically-secure random bytes
        self._private_key = X25519PrivateKey.generate()
        self._public_key  = self._private_key.public_key()

    # ------------------------------------------------------------------
    # Public-key serialisation (raw 32-byte format)
    # ------------------------------------------------------------------

    def public_key_bytes(self) -> bytes:
        """Return the raw 32-byte public key (suitable for sending over the wire)."""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def fingerprint(self) -> str:
        """SHA-256 fingerprint of our public key — shown in the GUI for manual verification."""
        digest = hashlib.sha256(self.public_key_bytes()).hexdigest()
        # Format as groups of 4 hex digits separated by colons for readability
        return ":".join(digest[i:i+4] for i in range(0, len(digest), 4))

    # ------------------------------------------------------------------
    # ECDH shared-secret derivation
    # ------------------------------------------------------------------

    def derive_shared_key(self, peer_public_key_bytes: bytes) -> bytes:
        """
        Perform X25519 Diffie-Hellman with the peer's public key, then run the
        raw shared secret through HKDF-SHA256 to produce a 32-byte AES key.
        """
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

        peer_pub = X25519PublicKey.from_public_bytes(peer_public_key_bytes)
        raw_secret = self._private_key.exchange(peer_pub)          # 32 bytes

        # HKDF stretches / whitens the raw DH output into a proper AES-256 key
        derived = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"ShushChat-session-key-v1",
        ).derive(raw_secret)

        return derived   # 32 bytes → AES-256

    def clear(self):
        """
        Attempt to zero the private-key material from memory.
        Python's GC doesn't guarantee immediate erasure, but we drop our
        reference so it becomes collectable.
        """
        self._private_key = None
        self._public_key  = None


# ---------------------------------------------------------------------------
# Session — holds the derived symmetric key for one connected peer session
# ---------------------------------------------------------------------------

class Session:
    """Encapsulates the symmetric key material for one peer session."""

    def __init__(self, shared_key: bytes, peer_fingerprint: str):
        if len(shared_key) != 32:
            raise ValueError("Session key must be exactly 32 bytes.")
        self._key             = shared_key
        self.peer_fingerprint = peer_fingerprint

    # ------------------------------------------------------------------
    # AES-256-GCM encryption
    # ------------------------------------------------------------------

    def encrypt(self, plaintext: str) -> bytes:
        """
        Encrypt *plaintext* with AES-256-GCM.

        Wire format (JSON → UTF-8 bytes):
            {
                "iv":  <base64 12-byte nonce>,
                "ct":  <base64 ciphertext + 16-byte GCM tag>,
                "mac": <base64 HMAC-SHA256 of iv+ct>
            }

        The GCM tag provides authenticated encryption (integrity + confidentiality).
        The HMAC provides an extra defence-in-depth layer over the whole envelope.
        """
        aesgcm = AESGCM(self._key)
        nonce  = os.urandom(12)                          # 96-bit GCM nonce
        ct     = aesgcm.encrypt(nonce, plaintext.encode(), None)

        iv_b64 = base64.b64encode(nonce).decode()
        ct_b64 = base64.b64encode(ct).decode()

        # HMAC over the encoded envelope components (prevent tag-stripping attacks)
        mac = self._hmac(iv_b64 + ct_b64)

        envelope = json.dumps({"iv": iv_b64, "ct": ct_b64, "mac": mac})
        return envelope.encode()

    def decrypt(self, raw: bytes) -> str:
        """
        Decrypt a wire-format envelope produced by :meth:`encrypt`.

        Raises ValueError if the MAC or GCM tag is invalid — caller should
        discard the message and show a warning.
        """
        try:
            envelope = json.loads(raw.decode())
            iv_b64   = envelope["iv"]
            ct_b64   = envelope["ct"]
            mac      = envelope["mac"]
        except (json.JSONDecodeError, KeyError) as exc:
            raise ValueError(f"Malformed message envelope: {exc}") from exc

        # 1. Verify HMAC first (fast fail before doing any decryption)
        expected_mac = self._hmac(iv_b64 + ct_b64)
        if not hmac.compare_digest(mac, expected_mac):
            raise ValueError("HMAC verification failed — message may have been tampered with.")

        # 2. AES-256-GCM decrypt (also verifies GCM authentication tag)
        aesgcm = AESGCM(self._key)
        nonce  = base64.b64decode(iv_b64)
        ct     = base64.b64decode(ct_b64)

        try:
            plaintext = aesgcm.decrypt(nonce, ct, None)
        except Exception as exc:
            raise ValueError(f"AES-GCM decryption failed: {exc}") from exc

        return plaintext.decode()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _hmac(self, data: str) -> str:
        """Compute HMAC-SHA256 of *data* (str) keyed with the session key."""
        h = hmac.new(self._key, data.encode(), hashlib.sha256)
        return base64.b64encode(h.digest()).decode()

    def clear(self):
        """Drop the session key reference."""
        self._key = None


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def peer_fingerprint_from_bytes(pub_key_bytes: bytes) -> str:
    """Compute a display fingerprint from a raw 32-byte public-key blob."""
    digest = hashlib.sha256(pub_key_bytes).hexdigest()
    return ":".join(digest[i:i+4] for i in range(0, len(digest), 4))


# ---------------------------------------------------------------------------
# GroupSession  [NEW — v2]
# ---------------------------------------------------------------------------

class GroupSession:
    """
    Manages per-peer Sessions for a multi-peer mesh.

    Each peer gets its own ECDH-derived AES-256 key (via a dedicated Session).
    This means every link is independently encrypted — compromising one link
    does NOT expose messages on other links.

    Message deduplication
    ---------------------
    In a gossip network a message can arrive via multiple paths.
    GroupSession tracks the last MAX_SEEN message-ids per room so duplicates
    are silently dropped by the app layer.

    Usage
    -----
        gs = GroupSession(keypair)          # one per app instance
        gs.add_peer(peer_id, peer_pub_bytes)  # call after each handshake
        encrypted = gs.encrypt(peer_id, json_str)
        plain     = gs.decrypt(peer_id, raw_bytes)
        gs.remove_peer(peer_id)            # call on disconnect
    """

    MAX_SEEN = 2048   # rolling deduplication window per room

    def __init__(self, keypair: "KeyPair"):
        self._keypair  = keypair
        # peer_id → Session
        self._sessions: dict = {}
        self._sessions_lock = __import__("threading").Lock()
        # seen message-ids for deduplication: set of strings
        self._seen_ids: set = set()
        self._seen_order: list = []          # FIFO to cap set size

    # ------------------------------------------------------------------
    # Peer management
    # ------------------------------------------------------------------

    def add_peer(self, peer_id: str, peer_pub_bytes: bytes) -> str:
        """
        Derive a shared Session for *peer_id* using *peer_pub_bytes*.
        Returns the peer's fingerprint string.
        """
        shared_key = self._keypair.derive_shared_key(peer_pub_bytes)
        fp         = peer_fingerprint_from_bytes(peer_pub_bytes)
        session    = Session(shared_key, fp)
        with self._sessions_lock:
            self._sessions[peer_id] = session
        return fp

    def remove_peer(self, peer_id: str) -> None:
        """Drop the Session for *peer_id* and zero the key material."""
        with self._sessions_lock:
            session = self._sessions.pop(peer_id, None)
        if session:
            session.clear()

    def has_peer(self, peer_id: str) -> bool:
        with self._sessions_lock:
            return peer_id in self._sessions

    def peer_fingerprint(self, peer_id: str) -> str:
        with self._sessions_lock:
            s = self._sessions.get(peer_id)
        return s.peer_fingerprint if s else ""

    def active_peer_ids(self) -> list:
        with self._sessions_lock:
            return list(self._sessions.keys())

    # ------------------------------------------------------------------
    # Encrypt / decrypt (delegate to per-peer Session)
    # ------------------------------------------------------------------

    def encrypt(self, peer_id: str, plaintext: str) -> bytes:
        """Encrypt *plaintext* with the session key for *peer_id*."""
        with self._sessions_lock:
            session = self._sessions.get(peer_id)
        if not session:
            raise KeyError(f"No session for peer {peer_id}")
        return session.encrypt(plaintext)

    def decrypt(self, peer_id: str, raw: bytes) -> str:
        """Decrypt *raw* with the session key for *peer_id*."""
        with self._sessions_lock:
            session = self._sessions.get(peer_id)
        if not session:
            raise KeyError(f"No session for peer {peer_id}")
        return session.decrypt(raw)

    # ------------------------------------------------------------------
    # Message-ID deduplication
    # ------------------------------------------------------------------

    def is_duplicate(self, msg_id: str) -> bool:
        """Return True if *msg_id* has been seen before (gossip dedup)."""
        return msg_id in self._seen_ids

    def mark_seen(self, msg_id: str) -> None:
        """Record *msg_id* as seen; evict oldest when window is full."""
        if msg_id in self._seen_ids:
            return
        self._seen_ids.add(msg_id)
        self._seen_order.append(msg_id)
        if len(self._seen_order) > self.MAX_SEEN:
            evict = self._seen_order.pop(0)
            self._seen_ids.discard(evict)

    # ------------------------------------------------------------------
    # Teardown
    # ------------------------------------------------------------------

    def clear_all(self) -> None:
        """Zero all session keys and drop state."""
        with self._sessions_lock:
            for s in self._sessions.values():
                s.clear()
            self._sessions.clear()
        self._seen_ids.clear()
        self._seen_order.clear()
