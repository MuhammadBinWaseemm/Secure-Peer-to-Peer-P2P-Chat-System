"""
networking.py — ShushChat Networking Module  (v3 — True Mesh P2P)
=================================================================
Key change vs v2: MultiPeerManager now exposes ``listen_port`` so the
app layer can include our reachable address in handshake peer-list
payloads.  Everything else is identical to v2.
"""

import socket
import struct
import threading
import uuid
from typing import Callable, Dict, List, Optional

HEADER_SIZE  = 4
MAX_MSG_SIZE = 10 * 1024 * 1024


def _send_framed(sock: socket.socket, data: bytes) -> None:
    if len(data) > MAX_MSG_SIZE:
        raise ValueError(f"Message too large ({len(data)} bytes).")
    sock.sendall(struct.pack(">I", len(data)) + data)


def _recv_framed(sock: socket.socket) -> bytes:
    header = _recv_exactly(sock, HEADER_SIZE)
    if not header:
        return b""
    length = struct.unpack(">I", header)[0]
    if length == 0:
        return b""
    if length > MAX_MSG_SIZE:
        raise ValueError(f"Incoming frame length {length} exceeds safety cap.")
    return _recv_exactly(sock, length)


def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return bytes(buf)
        buf.extend(chunk)
    return bytes(buf)


class PeerConnection:
    def __init__(self, sock, peer_id, on_message, on_disconnect):
        self._sock          = sock
        self.peer_id        = peer_id
        self._on_message    = on_message
        self._on_disconnect = on_disconnect
        self._alive         = True
        self._lock          = threading.Lock()
        try:
            self.remote_addr = "{0}:{1}".format(*sock.getpeername())
        except OSError:
            self.remote_addr = "unknown"

    def send(self, data: bytes) -> bool:
        with self._lock:
            if not self._alive:
                return False
            try:
                _send_framed(self._sock, data)
                return True
            except OSError:
                pass
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
                data = _recv_framed(self._sock)
                if not data:
                    self._mark_dead("Peer disconnected.")
                    return
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

    v3 addition: ``listen_port`` property so the app layer can include
    our address in the peer-list sent during handshake.
    """

    def __init__(self, on_peer_connected, on_message, on_peer_disconnected, on_error):
        self._on_peer_connected    = on_peer_connected
        self._on_message           = on_message
        self._on_peer_disconnected = on_peer_disconnected
        self._on_error             = on_error

        self._peers: Dict[str, PeerConnection] = {}
        self._peers_lock = threading.Lock()

        self._server_sock: Optional[socket.socket] = None
        self._listening   = False
        self._listen_port: Optional[int] = None   # NEW

    # ── listen ────────────────────────────────────────────────────────

    @property
    def listen_port(self) -> Optional[int]:
        """The TCP port we are currently listening on, or None."""
        return self._listen_port if self._listening else None

    def listen(self, port: int) -> None:
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
            self._listen_port = port          # record actual port
        except OSError as exc:
            self._on_error("Cannot bind to port {0}: {1}".format(port, exc))
            self._listening = False
            return

        while self._listening:
            try:
                self._server_sock.settimeout(1.0)
                try:
                    conn, _ = self._server_sock.accept()
                except socket.timeout:
                    continue
                conn.settimeout(None)
                self._register_socket(conn)
            except OSError:
                break

    # ── connect ───────────────────────────────────────────────────────

    def connect(self, host: str, port: int) -> None:
        threading.Thread(
            target=self._connect_thread, args=(host, port),
            name="connect-{0}:{1}".format(host, port), daemon=True,
        ).start()

    def _connect_thread(self, host: str, port: int) -> None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((host, port))
            sock.settimeout(None)
            self._register_socket(sock)
        except (OSError, socket.timeout) as exc:
            self._on_error("Connect to {0}:{1} failed: {2}".format(host, port, exc))

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

    def broadcast(self, data: bytes, exclude_peer_id: Optional[str] = None) -> None:
        with self._peers_lock:
            targets = list(self._peers.values())
        for peer in targets:
            if peer.peer_id == exclude_peer_id:
                continue
            if peer.is_alive:
                peer.send(data)

    def send_to(self, peer_id: str, data: bytes) -> bool:
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
        self._listening = False
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
