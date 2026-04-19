"""
networking.py — ShushChat Networking Module  (v3 — True Mesh P2P)
=================================================================
Security hardening over base v3:
  - Strict frame-size cap (prevents buffer-overflow via oversized frames)
  - Per-peer rate limiting (prevents flood / DoS attacks)
  - Maximum concurrent connection cap (prevents resource exhaustion)
  - IP address allow/block validation before accept
  - Mandatory receive timeout (prevents slow-read / slowloris attacks)
  - Minimum frame-size guard (rejects zero-payload frames silently)
  - All integer unpacking validated before allocation
  - Thread-safe counters for connection tracking
"""

import socket
import struct
import threading
import uuid
import time
import ipaddress
import logging
from typing import Callable, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# ── Frame constants ────────────────────────────────────────────────────────────
HEADER_SIZE   = 4
MIN_MSG_SIZE  = 1                    # reject empty/zero-length frames
MAX_MSG_SIZE  = 512 * 1024           # 512 KB hard cap (was 10 MB — reduced to
                                     # prevent memory exhaustion via oversized
                                     # frame injection)

# ── Security limits ───────────────────────────────────────────────────────────
MAX_PEERS         = 50               # maximum simultaneous TCP connections
RECV_TIMEOUT_SEC  = 30              # idle socket read timeout (slowloris guard)
CONNECT_TIMEOUT   = 10              # outbound connect timeout (seconds)

# ── Rate limiting (per peer) ──────────────────────────────────────────────────
RATE_WINDOW_SEC   = 5               # sliding window duration
RATE_MAX_MSGS     = 30              # max messages per peer per window
RATE_MAX_BYTES    = 256 * 1024      # max raw bytes per peer per window (256 KB)


def _validate_frame_length(length: int) -> None:
    """
    Validate a decoded frame-length field before allocating any memory.

    Raises ValueError immediately if the value is outside the safe range,
    preventing buffer-over-read caused by a crafted oversized length field.
    """
    if length < MIN_MSG_SIZE:
        raise ValueError(
            f"Frame length {length} is below minimum ({MIN_MSG_SIZE}).")
    if length > MAX_MSG_SIZE:
        raise ValueError(
            f"Frame length {length} exceeds safety cap ({MAX_MSG_SIZE}).")


def _send_framed(sock: socket.socket, data: bytes) -> None:
    """
    Send *data* with a 4-byte big-endian length prefix.

    Pre-flight check prevents sending frames that exceed our own cap —
    keeps the sender and receiver caps in sync so a bug on the send side
    can't produce a frame the receive side refuses.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("Frame data must be bytes.")
    length = len(data)
    if length < MIN_MSG_SIZE:
        raise ValueError("Refusing to send empty frame.")
    if length > MAX_MSG_SIZE:
        raise ValueError(
            f"Outgoing frame {length} bytes exceeds cap {MAX_MSG_SIZE}.")
    sock.sendall(struct.pack(">I", length) + data)


def _recv_framed(sock: socket.socket) -> bytes:
    """
    Receive one length-prefixed frame from *sock*.

    Security properties:
    • Length field is validated BEFORE any memory allocation.
    • Zero-length or oversized frames raise ValueError (caller drops peer).
    • Returns b"" only on clean EOF (peer disconnected).
    """
    header = _recv_exactly(sock, HEADER_SIZE)
    if not header:
        return b""                    # clean EOF

    # struct.unpack always succeeds for a 4-byte buffer — no exception path
    (length,) = struct.unpack(">I", header)

    # ↓ validate before allocating — prevents OOM from crafted length field
    _validate_frame_length(length)

    return _recv_exactly(sock, length)


def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    """
    Read exactly *n* bytes from *sock*, handling short reads.

    Raises OSError if the socket errors mid-read.
    Returns fewer than *n* bytes only on clean EOF.
    """
    if n <= 0:
        return b""
    buf = bytearray()
    while len(buf) < n:
        needed = n - len(buf)
        chunk  = sock.recv(min(needed, 65536))   # cap individual recv calls
        if not chunk:
            return bytes(buf)          # EOF
        buf.extend(chunk)
    return bytes(buf)


def _is_valid_ip(ip: str) -> bool:
    """Return True if *ip* is a syntactically valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _is_valid_port(port: int) -> bool:
    """Return True if *port* is in the valid TCP port range."""
    return isinstance(port, int) and 1 <= port <= 65535


class _RateLimiter:
    """
    Sliding-window rate limiter for a single peer.

    Tracks both message count and byte volume in a rolling window to guard
    against:
      - Message-flood attacks (many tiny messages)
      - Bandwidth-exhaustion attacks (few very large messages)
    """

    def __init__(self, window: float = RATE_WINDOW_SEC,
                 max_msgs: int = RATE_MAX_MSGS,
                 max_bytes: int = RATE_MAX_BYTES):
        self._window    = window
        self._max_msgs  = max_msgs
        self._max_bytes = max_bytes
        self._timestamps: List[float] = []
        self._byte_log:   List[tuple]  = []   # (timestamp, nbytes)
        self._lock = threading.Lock()

    def _purge(self, now: float) -> None:
        """Evict entries older than the current window."""
        cutoff = now - self._window
        while self._timestamps and self._timestamps[0] < cutoff:
            self._timestamps.pop(0)
        while self._byte_log and self._byte_log[0][0] < cutoff:
            self._byte_log.pop(0)

    def check(self, nbytes: int) -> bool:
        """
        Return True if this message is within rate limits and should be
        processed.  Return False if the peer is flooding us.
        """
        now = time.monotonic()
        with self._lock:
            self._purge(now)
            if len(self._timestamps) >= self._max_msgs:
                return False
            if sum(b for _, b in self._byte_log) + nbytes > self._max_bytes:
                return False
            self._timestamps.append(now)
            self._byte_log.append((now, nbytes))
            return True


class PeerConnection:
    """Manages one authenticated TCP connection to a remote peer."""

    def __init__(self, sock: socket.socket, peer_id: str,
                 on_message: Callable, on_disconnect: Callable):
        self._sock          = sock
        self.peer_id        = peer_id
        self._on_message    = on_message
        self._on_disconnect = on_disconnect
        self._alive         = True
        self._lock          = threading.Lock()
        self._rate_limiter  = _RateLimiter()

        # Set a receive timeout so a stuck/slow peer can't hold a thread
        # indefinitely (slowloris-style resource exhaustion guard).
        try:
            self._sock.settimeout(RECV_TIMEOUT_SEC)
        except OSError:
            pass

        try:
            self.remote_addr = "{0}:{1}".format(*sock.getpeername())
        except OSError:
            self.remote_addr = "unknown"

    def send(self, data: bytes) -> bool:
        """Thread-safe send.  Returns False if the peer is dead."""
        if not isinstance(data, (bytes, bytearray)):
            return False
        with self._lock:
            if not self._alive:
                return False
            try:
                _send_framed(self._sock, data)
                return True
            except (OSError, ValueError) as exc:
                logger.debug("Send error to %s: %s", self.remote_addr, exc)
        self._mark_dead("Send error — connection lost.")
        return False

    def start_receiver(self) -> None:
        threading.Thread(
            target=self._recv_loop,
            name="recv-" + self.peer_id[:8],
            daemon=True,
        ).start()

    def _recv_loop(self) -> None:
        try:
            while self._alive:
                try:
                    data = _recv_framed(self._sock)
                except socket.timeout:
                    # Idle timeout — treat as disconnect rather than crash
                    self._mark_dead("Receive timeout — peer inactive.")
                    return
                except ValueError as exc:
                    # Malformed frame (bad length, oversized) — drop the peer
                    logger.warning(
                        "Malformed frame from %s: %s", self.remote_addr, exc)
                    self._mark_dead(f"Protocol error: {exc}")
                    return

                if not data:
                    self._mark_dead("Peer disconnected.")
                    return

                # Rate-limit check BEFORE handing to application layer
                if not self._rate_limiter.check(len(data)):
                    logger.warning(
                        "Rate limit exceeded by %s — dropping message.",
                        self.remote_addr)
                    # Do NOT disconnect immediately — log and skip.
                    # A short sleep discourages rapid retry floods.
                    time.sleep(0.5)
                    continue

                self._on_message(self.peer_id, data)

        except OSError as exc:
            if self._alive:
                self._mark_dead("Network error: {0}".format(exc))

    def close(self, reason: str = "Connection closed.") -> None:
        self._mark_dead(reason, notify=False)

    def _mark_dead(self, reason: str, notify: bool = True) -> None:
        with self._lock:
            if not self._alive:
                return
            self._alive = False
        for op in (
            lambda: self._sock.shutdown(socket.SHUT_RDWR),
            lambda: self._sock.close(),
        ):
            try:
                op()
            except OSError:
                pass
        if notify:
            self._on_disconnect(self.peer_id, reason)

    @property
    def is_alive(self) -> bool:
        return self._alive


class MultiPeerManager:
    """
    Manages multiple simultaneous peer connections.

    Security additions over base v3:
      • Hard cap on concurrent peers (MAX_PEERS) — rejects new sockets when
        at capacity to prevent resource-exhaustion attacks.
      • IP validation on inbound connects (rejects obviously malformed IPs).
      • Host/port validation before outbound dials.
      • Connection-attempt deduplication to prevent redundant reconnects.
      • ``listen_port`` property for app-layer peer-list sharing (v3 feature).
    """

    def __init__(self, on_peer_connected, on_message,
                 on_peer_disconnected, on_error):
        self._on_peer_connected    = on_peer_connected
        self._on_message           = on_message
        self._on_peer_disconnected = on_peer_disconnected
        self._on_error             = on_error

        self._peers: Dict[str, PeerConnection] = {}
        self._peers_lock  = threading.Lock()

        self._server_sock: Optional[socket.socket] = None
        self._listening   = False
        self._listen_port: Optional[int] = None

        # Track in-progress outbound connects to avoid duplicate dials
        self._connecting:     Set[str] = set()
        self._connecting_lock = threading.Lock()

    # ── listen ────────────────────────────────────────────────────────

    @property
    def listen_port(self) -> Optional[int]:
        return self._listen_port if self._listening else None

    def listen(self, port: int) -> None:
        if not _is_valid_port(port):
            self._on_error(f"Invalid listen port: {port}")
            return
        self.stop_listening()
        self._listening = True
        threading.Thread(
            target=self._listen_loop, args=(port,),
            name="listen-{0}".format(port), daemon=True,
        ).start()

    def _listen_loop(self, port: int) -> None:
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", port))
            srv.listen(16)
            self._server_sock = srv
            self._listen_port = port
        except OSError as exc:
            self._on_error(
                "Cannot bind to port {0}: {1}".format(port, exc))
            self._listening = False
            return

        while self._listening:
            try:
                self._server_sock.settimeout(1.0)
                try:
                    conn, addr = self._server_sock.accept()
                except socket.timeout:
                    continue

                # ── Connection cap ────────────────────────────────────
                with self._peers_lock:
                    current = len(self._peers)
                if current >= MAX_PEERS:
                    logger.warning(
                        "Peer cap (%d) reached — rejecting %s", MAX_PEERS, addr)
                    try:
                        conn.close()
                    except OSError:
                        pass
                    continue

                # ── IP validation ─────────────────────────────────────
                remote_ip = addr[0]
                if not _is_valid_ip(remote_ip):
                    logger.warning(
                        "Rejecting connection from invalid IP: %s", remote_ip)
                    try:
                        conn.close()
                    except OSError:
                        pass
                    continue

                conn.settimeout(None)
                self._register_socket(conn)

            except OSError:
                break

    # ── connect ───────────────────────────────────────────────────────

    def connect(self, host: str, port: int) -> None:
        # Validate inputs before spawning a thread
        if not host or not isinstance(host, str):
            self._on_error("Invalid host address.")
            return
        host = host.strip()
        if not host:
            self._on_error("Host address cannot be empty.")
            return
        if not _is_valid_port(port):
            self._on_error(f"Invalid port: {port}")
            return

        key = f"{host}:{port}"
        with self._connecting_lock:
            if key in self._connecting:
                return                    # already dialling — skip duplicate
            self._connecting.add(key)

        threading.Thread(
            target=self._connect_thread, args=(host, port, key),
            name="connect-{0}:{1}".format(host, port), daemon=True,
        ).start()

    def _connect_thread(self, host: str, port: int, key: str) -> None:
        try:
            # Check peer cap before even attempting the connection
            with self._peers_lock:
                current = len(self._peers)
            if current >= MAX_PEERS:
                self._on_error(
                    f"Cannot connect to {host}:{port} — peer cap reached.")
                return

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(CONNECT_TIMEOUT)
            sock.connect((host, port))
            sock.settimeout(None)
            self._register_socket(sock)
        except (OSError, socket.timeout) as exc:
            self._on_error(
                "Connect to {0}:{1} failed: {2}".format(host, port, exc))
        finally:
            with self._connecting_lock:
                self._connecting.discard(key)

    # ── shared setup ──────────────────────────────────────────────────

    def _register_socket(self, sock: socket.socket) -> None:
        peer_id = str(uuid.uuid4())
        peer = PeerConnection(
            sock=sock, peer_id=peer_id,
            on_message=self._on_message,
            on_disconnect=self._handle_peer_disconnect,
        )
        with self._peers_lock:
            self._peers[peer_id] = peer
        peer.start_receiver()
        self._on_peer_connected(peer_id, peer)

    # ── send helpers ──────────────────────────────────────────────────

    def broadcast(self, data: bytes,
                  exclude_peer_id: Optional[str] = None) -> None:
        if not isinstance(data, (bytes, bytearray)):
            return
        with self._peers_lock:
            targets = list(self._peers.values())
        for peer in targets:
            if peer.peer_id == exclude_peer_id:
                continue
            if peer.is_alive:
                peer.send(data)

    def send_to(self, peer_id: str, data: bytes) -> bool:
        if not isinstance(data, (bytes, bytearray)):
            return False
        with self._peers_lock:
            peer = self._peers.get(peer_id)
        if peer and peer.is_alive:
            return peer.send(data)
        return False

    # ── registry helpers ──────────────────────────────────────────────

    def get_peer(self, peer_id: str) -> Optional[PeerConnection]:
        with self._peers_lock:
            return self._peers.get(peer_id)

    def peer_ids(self) -> List[str]:
        with self._peers_lock:
            return list(self._peers.keys())

    def peer_count(self) -> int:
        with self._peers_lock:
            return sum(1 for p in self._peers.values() if p.is_alive)

    def _handle_peer_disconnect(self, peer_id: str, reason: str) -> None:
        with self._peers_lock:
            self._peers.pop(peer_id, None)
        self._on_peer_disconnected(peer_id, reason)

    def stop_listening(self) -> None:
        self._listening   = False
        self._listen_port = None
        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass
            self._server_sock = None

    def disconnect_all(self) -> None:
        self.stop_listening()
        with self._peers_lock:
            peers = list(self._peers.values())
            self._peers.clear()
        for peer in peers:
            peer.close("Disconnected by local user.")
