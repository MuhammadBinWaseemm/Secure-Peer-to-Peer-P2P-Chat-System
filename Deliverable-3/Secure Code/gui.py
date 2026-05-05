import json, uuid, datetime, hashlib, re, ipaddress, hmac, html
from typing import Dict, List, Optional, Set

from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QLabel, QLineEdit, QPushButton,
                             QRadioButton, QListWidget, QListWidgetItem,
                             QTextBrowser, QScrollArea, QFrame, QDialog, QMessageBox,
                             QGridLayout, QButtonGroup)
from PyQt6.QtGui import QFont, QColor, QCursor
from PyQt6.QtCore import Qt, pyqtSignal, QObject, QTimer

from networking import MultiPeerManager, PeerConnection, _is_valid_ip, _is_valid_port
from crypto import KeyPair, GroupSession, IdentityKey

# ─── Protocol constants ───────────────────────────────────────────────────────
MSG_HANDSHAKE      = "handshake"
MSG_PEER_LIST      = "peer_list"
MSG_PEER_LIST_ACK  = "peer_list_ack"
MSG_CHAT           = "chat"
MSG_ROOM_CREATE    = "room_create"
MSG_ROOM_JOIN      = "room_join"
MSG_ROOM_JOIN_OK   = "room_join_ok"
MSG_ROOM_JOIN_FAIL = "room_join_fail"
MSG_ROOM_HELLO     = "room_hello"
MSG_CONN_REQ       = "conn_req"
MSG_ROOM_INVITE    = "room_invite"
MSG_UPDATE_NAME    = "update_name"

DEFAULT_USER   = "anon"
MAX_USERNAME   = 24
MAX_ROOM_NAME  = 32
MAX_MSG_TEXT   = 4096          # characters — cap outgoing message length
MAX_MSG_ID_LEN = 64            # UUID is 36 chars; give a little slack

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

_SAFE_NAME_RE = re.compile(r"^[\w\s.\-]{1,}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")

# ─── Palette ──────────────────────────────────────────────────────────────────
C = {
    "bg":          "#08090e",
    "bg2":         "#0d0f17",
    "bg3":         "#111520",
    "bg4":         "#171d2e",
    "sidebar":     "#0b0e18",
    "panel":       "#0f1320",
    "input_bg":    "#141a28",
    "border":      "#1c2438",
    "border2":     "#222e46",
    "fg":          "#dce8f8",
    "fg2":         "#8090b0",
    "fg3":         "#40506a",
    "accent":      "#00cfff",
    "accent2":     "#7c3aed",
    "accent3":     "#10b981",
    "accent4":     "#f59e0b",
    "accent5":     "#ef4444",
    "accent6":     "#ec4899",
    "self_msg":    "#b8c8f0",
    "peer_msg":    "#dce8f8",
    "room_active": "#162040",
    "room_hover":  "#111828",
    "btn_primary": "#0ea5e9",
    "btn_danger":  "#dc2626",
    "btn_success": "#059669",
    "send_bg":     "#0ea5e9",
}

def _sanitise_name(raw: str, max_len: int) -> str:
    cleaned = "".join(ch for ch in raw if ch.isprintable())
    return cleaned.strip()[:max_len]

def _sanitise_text(raw: str, max_len: int) -> str:
    allowed_controls = {"\n", "\t"}
    cleaned = "".join(
        ch for ch in raw
        if ch.isprintable() or ch in allowed_controls
    )
    return cleaned[:max_len]

def _hash_password(pw: str) -> str:
    if not pw:
        return ""
    return hashlib.sha256(pw.encode("utf-8")).hexdigest()

def _is_valid_uuid(value: str) -> bool:
    return bool(_UUID_RE.match(value)) if isinstance(value, str) else False

def _is_valid_hex64(value: str) -> bool:
    return bool(_HEX64_RE.match(value)) if isinstance(value, str) else False

def _is_valid_pubkey_hex(value: str) -> bool:
    return (isinstance(value, str)
            and len(value) == 64
            and all(c in "0123456789abcdefABCDEF" for c in value))

class RoomState:
    def __init__(self, name: str, pw_hash: str = "", is_host: bool = False):
        self.name     = name
        self.pw_hash  = pw_hash
        self.is_host  = is_host
        self.messages: List[dict] = []
        self.unread   = 0
        self.members: Set[str] = set()

class AppSignals(QObject):
    peer_connected = pyqtSignal(str, object)
    raw_message = pyqtSignal(str, bytes)
    peer_disconnected = pyqtSignal(str, str)
    network_error = pyqtSignal(str)

class RoomWidget(QFrame):
    clicked = pyqtSignal(str)

    def __init__(self, name, icon, host_mark, last_text, unread, is_active, parent=None):
        super().__init__(parent)
        self.name = name
        self.is_active = is_active
        self.bg_color = C["room_active"] if is_active else C["sidebar"]
        self.hover_color = C["room_hover"]
        
        self.setStyleSheet(f"background-color: {self.bg_color};")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        strip_col = C["accent"] if is_active else self.bg_color
        strip = QFrame()
        strip.setFixedWidth(3)
        strip.setStyleSheet(f"background-color: {strip_col}; border: none;")
        layout.addWidget(strip)
        
        inner = QFrame()
        inner.setStyleSheet("background-color: transparent; border: none;")
        inner_layout = QVBoxLayout(inner)
        inner_layout.setContentsMargins(10, 9, 10, 9)
        inner_layout.setSpacing(2)
        
        top = QFrame()
        top.setStyleSheet("background-color: transparent; border: none;")
        top_layout = QHBoxLayout(top)
        top_layout.setContentsMargins(0, 0, 0, 0)
        
        name_lbl = QLabel(f"{icon}  {name}{host_mark}")
        name_lbl.setStyleSheet(f"color: {C['accent'] if is_active else C['fg']}; font-weight: bold; font-size: 11pt;")
        top_layout.addWidget(name_lbl)
        top_layout.addStretch()
        
        if unread > 0 and not is_active:
            ur_lbl = QLabel(f" {unread} ")
            ur_lbl.setStyleSheet(f"background-color: {C['accent6']}; color: white; border-radius: 4px; font-size: 9pt;")
            top_layout.addWidget(ur_lbl)
            
        inner_layout.addWidget(top)
        
        txt_lbl = QLabel(last_text)
        txt_lbl.setStyleSheet(f"color: {C['fg3']}; font-size: 9pt;")
        inner_layout.addWidget(txt_lbl)
        
        layout.addWidget(inner, 1)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self.name)

    def enterEvent(self, event):
        if not self.is_active:
            self.setStyleSheet(f"background-color: {self.hover_color};")

    def leaveEvent(self, event):
        if not self.is_active:
            self.setStyleSheet(f"background-color: {self.bg_color};")


class ShushChatApp(QMainWindow):

    def __init__(self):
        super().__init__()
        self.signals = AppSignals()
        self.signals.peer_connected.connect(self._ui_peer_connected)
        self.signals.raw_message.connect(self._ui_dispatch)
        self.signals.peer_disconnected.connect(self._ui_peer_disconnected)
        self.signals.network_error.connect(self._ui_network_error)

        self._username = DEFAULT_USER
        self._keypair: Optional[KeyPair]      = None
        self._identity_key = IdentityKey()
        self._group:   Optional[GroupSession] = None
        self._pending_hs: Set[str]            = set()

        self._net = MultiPeerManager(
            on_peer_connected    = self._on_peer_connected,
            on_message           = self._on_raw_message,
            on_peer_disconnected = self._on_peer_disconnected,
            on_error             = self._on_network_error,
        )

        self._rooms: Dict[str, RoomState] = {}
        self._active_room: Optional[str]  = None
        self._peer_display: Dict[str, str] = {}

        self._peer_addresses: Dict[str, tuple] = {}
        self._dialled: set = set()
        self._pending_joins: Dict[str, str] = {}

        self._setup_window()
        self._build_ui()
        self._generate_identity()
        self._add_global_room()

    def _setup_window(self):
        self.setWindowTitle("ShushChat v3 — Secure Encrypted Mesh Chat")
        self.setStyleSheet(f"background-color: {C['bg']}; color: {C['fg']};")
        self.setMinimumSize(900, 600)
        self.resize(1200, 750)

    def _build_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        self._build_titlebar(main_layout)
        
        center_frame = QFrame()
        center_layout = QHBoxLayout(center_frame)
        center_layout.setContentsMargins(0, 0, 0, 0)
        center_layout.setSpacing(0)
        
        self._build_left_column(center_layout)
        self._build_right_column(center_layout)
        
        main_layout.addWidget(center_frame, 1)
        self._build_statusbar(main_layout)

    def _build_titlebar(self, parent_layout):
        bar = QFrame()
        bar.setFixedHeight(52)
        bar.setStyleSheet(f"background-color: {C['panel']}; border-bottom: 1px solid {C['accent2']};")
        bar_layout = QHBoxLayout(bar)
        bar_layout.setContentsMargins(16, 6, 16, 6)

        lbl_icon = QLabel("🔒")
        lbl_icon.setStyleSheet(f"color: {C['accent']}; font-size: 18pt; border: none;")
        bar_layout.addWidget(lbl_icon)

        lbl_title = QLabel(" ShushChat")
        lbl_title.setStyleSheet(f"color: {C['accent']}; font-weight: bold; font-size: 16pt; border: none;")
        bar_layout.addWidget(lbl_title)

        lbl_sub = QLabel("  v3  ·  E2E Encrypted  ·  P2P Mesh")
        lbl_sub.setStyleSheet(f"color: {C['fg3']}; font-size: 10pt; border: none;")
        bar_layout.addWidget(lbl_sub)

        bar_layout.addStretch()

        self._conn_badge = QLabel("⬤  OFFLINE")
        self._conn_badge.setStyleSheet(f"color: {C['accent5']}; font-weight: bold; font-size: 12pt; border: none;")
        bar_layout.addWidget(self._conn_badge)

        parent_layout.addWidget(bar)

    def _build_left_column(self, parent_layout):
        self._left = QFrame()
        self._left.setStyleSheet(f"background-color: {C['sidebar']}; border-right: 1px solid {C['border']};")
        self._left.setMinimumWidth(290)
        left_layout = QVBoxLayout(self._left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(0)

        conn = QFrame()
        conn.setStyleSheet("border: none;")
        conn_layout = QGridLayout(conn)
        conn_layout.setContentsMargins(12, 10, 12, 10)
        conn_layout.setSpacing(8)

        lbl = QLabel("⚡  NETWORK")
        lbl.setStyleSheet(f"color: {C['fg3']}; font-weight: bold; font-size: 11pt; border: none;")
        conn_layout.addWidget(lbl, 0, 0, 1, 2)

        lbl = QLabel("Username")
        lbl.setStyleSheet(f"color: {C['fg3']}; font-size: 10pt; border: none;")
        conn_layout.addWidget(lbl, 1, 0, 1, 2)
        
        self._username_entry = self._mk_entry_widget()
        self._username_entry.setText(DEFAULT_USER)
        self._username_entry.returnPressed.connect(self._do_set_username)
        conn_layout.addWidget(self._username_entry, 2, 0)

        btn = self._mk_btn_widget("SET", self._do_set_username, C["accent2"])
        conn_layout.addWidget(btn, 2, 1)
        
        self._mode_group = QButtonGroup(self)
        rad_conn = QRadioButton("⟶ Connect")
        rad_conn.setStyleSheet(f"color: {C['fg2']}; font-size: 10pt; border: none;")
        rad_conn.setChecked(True)
        rad_list = QRadioButton("⟵ Listen")
        rad_list.setStyleSheet(f"color: {C['fg2']}; font-size: 10pt; border: none;")
        self._mode_group.addButton(rad_conn, 1)
        self._mode_group.addButton(rad_list, 2)
        
        mode_layout = QHBoxLayout()
        mode_layout.addWidget(rad_conn)
        mode_layout.addWidget(rad_list)
        mode_layout.addStretch()
        conn_layout.addLayout(mode_layout, 3, 0, 1, 2)
        
        lbl = QLabel("IP Address")
        lbl.setStyleSheet(f"color: {C['fg3']}; font-size: 10pt; border: none;")
        conn_layout.addWidget(lbl, 4, 0, 1, 2)
        self._ip_entry = self._mk_entry_widget()
        self._ip_entry.setText("127.0.0.1")
        conn_layout.addWidget(self._ip_entry, 5, 0, 1, 2)

        lbl = QLabel("Port")
        lbl.setStyleSheet(f"color: {C['fg3']}; font-size: 10pt; border: none;")
        conn_layout.addWidget(lbl, 6, 0, 1, 2)
        self._port_entry = self._mk_entry_widget()
        self._port_entry.setText("5555")
        conn_layout.addWidget(self._port_entry, 7, 0, 1, 2)

        self._connect_btn = self._mk_btn_widget("⚡  CONNECT / LISTEN", self._do_connect, C["btn_primary"])
        conn_layout.addWidget(self._connect_btn, 8, 0, 1, 2)

        self._disconnect_btn = self._mk_btn_widget("✕  DISCONNECT ALL", self._do_disconnect_all, C["btn_danger"])
        self._disconnect_btn.setEnabled(False)
        conn_layout.addWidget(self._disconnect_btn, 9, 0, 1, 2)
        
        left_layout.addWidget(conn)
        
        sep = QFrame()
        sep.setFixedHeight(1)
        sep.setStyleSheet(f"background-color: {C['border']}; border: none;")
        left_layout.addWidget(sep)
        
        rh = QFrame()
        rh.setStyleSheet("border: none;")
        rh_layout = QHBoxLayout(rh)
        rh_layout.setContentsMargins(12, 8, 12, 8)
        lbl = QLabel("💬  ROOMS")
        lbl.setStyleSheet(f"color: {C['fg3']}; font-weight: bold; font-size: 11pt; border: none;")
        rh_layout.addWidget(lbl)
        rh_layout.addStretch()
        btn_create = self._mk_btn_widget("+ Create", self._show_create_room_dialog, C["accent3"])
        btn_join = self._mk_btn_widget("→ Join", self._show_join_room_dialog, C["accent2"])
        rh_layout.addWidget(btn_create)
        rh_layout.addWidget(btn_join)
        left_layout.addWidget(rh)

        self._room_scroll = QScrollArea()
        self._room_scroll.setWidgetResizable(True)
        self._room_scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        self._room_inner = QFrame()
        self._room_inner.setStyleSheet(f"background-color: {C['sidebar']}; border: none;")
        self._room_inner_layout = QVBoxLayout(self._room_inner)
        self._room_inner_layout.setContentsMargins(0, 0, 0, 0)
        self._room_inner_layout.setSpacing(0)
        self._room_inner_layout.addStretch()
        self._room_scroll.setWidget(self._room_inner)
        left_layout.addWidget(self._room_scroll, 1)

        ff = QFrame()
        ff.setStyleSheet("border: none;")
        ff_layout = QVBoxLayout(ff)
        ff_layout.setContentsMargins(12, 6, 12, 6)
        
        sep2 = QFrame()
        sep2.setFixedHeight(1)
        sep2.setStyleSheet(f"background-color: {C['border']}; border: none;")
        ff_layout.addWidget(sep2)
        
        self._fp_lbl = QLabel("Fingerprint: generating…")
        self._fp_lbl.setStyleSheet(f"color: {C['fg3']}; font-size: 10pt; border: none;")
        self._fp_lbl.setWordWrap(True)
        ff_layout.addWidget(self._fp_lbl)
        
        left_layout.addWidget(ff)
        parent_layout.addWidget(self._left)

    def _build_right_column(self, parent_layout):
        self._right = QFrame()
        self._right.setStyleSheet(f"background-color: {C['bg']}; border: none;")
        right_layout = QVBoxLayout(self._right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)

        tb = QFrame()
        tb.setFixedHeight(46)
        tb.setStyleSheet(f"background-color: {C['panel']}; border-bottom: 1px solid {C['border2']};")
        tb_layout = QHBoxLayout(tb)
        tb_layout.setContentsMargins(16, 0, 16, 0)

        self._room_title_lbl = QLabel("Select or create a room")
        self._room_title_lbl.setStyleSheet(f"color: {C['fg']}; font-weight: bold; font-size: 12pt; border: none;")
        tb_layout.addWidget(self._room_title_lbl)

        self._room_lock_lbl = QLabel("")
        self._room_lock_lbl.setStyleSheet(f"color: {C['accent3']}; font-size: 10pt; border: none;")
        tb_layout.addWidget(self._room_lock_lbl)

        tb_layout.addStretch()

        self._room_members_lbl = QLabel("")
        self._room_members_lbl.setStyleSheet(f"color: {C['fg3']}; font-size: 10pt; border: none;")
        tb_layout.addWidget(self._room_members_lbl)

        self._invite_btn = self._mk_btn_widget("Invite", self._show_invite_dialog, C["accent2"])
        self._invite_btn.hide()
        tb_layout.addWidget(self._invite_btn)

        right_layout.addWidget(tb)

        # Middle area (Chat + Peer List)
        mid_layout = QHBoxLayout()
        mid_layout.setContentsMargins(0, 0, 0, 0)
        mid_layout.setSpacing(0)

        self._chat_display = QTextBrowser()
        self._chat_display.setStyleSheet(f"background-color: {C['bg']}; color: {C['fg']}; font-size: 13pt; border: none; padding: 10px;")
        self._chat_display.setOpenExternalLinks(False)
        self._chat_display.setOpenLinks(False)
        self._chat_display.anchorClicked.connect(self._handle_chat_link)
        mid_layout.addWidget(self._chat_display, 1)

        # Peer Sidebar
        self._peer_sidebar = QFrame()
        self._peer_sidebar.setFixedWidth(200)
        self._peer_sidebar.setStyleSheet(f"background-color: {C['sidebar']}; border-left: 1px solid {C['border']};")
        peer_sidebar_layout = QVBoxLayout(self._peer_sidebar)
        peer_sidebar_layout.setContentsMargins(10, 10, 10, 10)
        
        self._peer_count_lbl = QLabel("0 peers connected")
        self._peer_count_lbl.setStyleSheet(f"color: {C['fg3']}; font-weight: bold; font-size: 10pt; border: none;")
        peer_sidebar_layout.addWidget(self._peer_count_lbl)

        self._peer_list_ui = QListWidget()
        self._peer_list_ui.setStyleSheet(f"background-color: transparent; color: {C['fg2']}; border: none; font-size: 10pt;")
        self._peer_list_ui.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._peer_list_ui.customContextMenuRequested.connect(self._peer_list_context_menu)
        peer_sidebar_layout.addWidget(self._peer_list_ui, 1)
        
        mid_layout.addWidget(self._peer_sidebar)
        right_layout.addLayout(mid_layout, 1)

        sep = QFrame()
        sep.setFixedHeight(1)
        sep.setStyleSheet(f"background-color: {C['border2']}; border: none;")
        right_layout.addWidget(sep)

        inp = QFrame()
        inp.setStyleSheet(f"background-color: {C['panel']}; border: none;")
        inp_layout = QHBoxLayout(inp)
        inp_layout.setContentsMargins(12, 10, 12, 10)

        self._msg_entry = self._mk_entry_widget()
        self._msg_entry.returnPressed.connect(self._do_send)
        inp_layout.addWidget(self._msg_entry, 1)

        self._send_btn = self._mk_btn_widget("SEND  ▶", self._do_send, C["send_bg"])
        inp_layout.addWidget(self._send_btn)

        right_layout.addWidget(inp)
        parent_layout.addWidget(self._right, 1)

    def _build_statusbar(self, parent_layout):
        bar = QFrame()
        bar.setFixedHeight(22)
        bar.setStyleSheet(f"background-color: {C['bg2']}; border: none;")
        bar_layout = QHBoxLayout(bar)
        bar_layout.setContentsMargins(10, 0, 10, 0)

        self._status_lbl = QLabel("ShushChat v3  ·  No server. No logs. No leaks.")
        self._status_lbl.setStyleSheet(f"color: {C['fg3']}; font-size: 10pt; font-family: monospace; border: none;")
        bar_layout.addWidget(self._status_lbl)

        bar_layout.addStretch()

        lbl_algo = QLabel("AES-256-GCM  ·  X25519 ECDH  ·  HMAC-SHA256")
        lbl_algo.setStyleSheet(f"color: {C['fg3']}; font-size: 10pt; font-family: monospace; border: none;")
        bar_layout.addWidget(lbl_algo)

        parent_layout.addWidget(bar)

    def _mk_entry_widget(self):
        en = QLineEdit()
        en.setStyleSheet(f"background-color: {C['input_bg']}; color: {C['fg']}; border: 1px solid {C['border']}; border-radius: 4px; padding: 5px; font-size: 12pt;")
        return en

    def _mk_btn_widget(self, text, cmd, color):
        btn = QPushButton(text)
        btn.setStyleSheet(f"QPushButton {{ background-color: {color}; color: white; border: none; border-radius: 4px; padding: 6px 12px; font-weight: bold; font-size: 11pt; }} QPushButton:disabled {{ background-color: {C['bg4']}; color: {C['fg3']}; }}")
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.clicked.connect(cmd)
        return btn

    def _refresh_room_list(self):
        while self._room_inner_layout.count():
            item = self._room_inner_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
            elif item.spacerItem():
                pass

        if not self._rooms:
            lbl = QLabel("No rooms.\nCreate or join one!")
            lbl.setStyleSheet(f"color: {C['fg3']}; font-size: 10pt; padding: 20px; border: none;")
            self._room_inner_layout.addWidget(lbl)
            self._room_inner_layout.addStretch()
            return

        for name, room in self._rooms.items():
            is_active = (name == self._active_room)
            icon = "🔒" if room.pw_hash else "#"
            host_mark = " ★" if room.is_host else ""
            last_text = "No messages yet"
            if room.messages:
                m = room.messages[-1]
                preview = f"{m['user']}: {m['text']}"
                last_text = (preview[:34] + "…") if len(preview) > 36 else preview

            w = RoomWidget(name, icon, host_mark, last_text, room.unread, is_active)
            w.clicked.connect(self._switch_room)
            self._room_inner_layout.addWidget(w)
            
            sep = QFrame()
            sep.setFixedHeight(1)
            sep.setStyleSheet(f"background-color: {C['border']}; border: none;")
            self._room_inner_layout.addWidget(sep)
            
        self._room_inner_layout.addStretch()

    def _switch_room(self, name: str):
        if name not in self._rooms:
            return
        self._active_room = name
        room = self._rooms[name]
        room.unread = 0

        icon = "🔒 Password Protected" if room.pw_hash else "🌐 Open Room"
        host_note = "  [host]" if room.is_host else ""
        self._room_title_lbl.setText(f"# {name}{host_note}")
        self._room_lock_lbl.setText(f"  {icon}")
        self._room_members_lbl.setText(f"{len(room.members)+1} member(s)")

        self._chat_display.clear()

        if room.messages:
            self._chat_display.append(f"<div style='color:{C['fg3']}; font-family: monospace; text-align: center;'><br>── {name} ─────────────────────────────<br></div>")
            for m in room.messages:
                if m.get("system"):
                    s_text = html.escape(m['text'])
                    s_ts = html.escape(m['ts'])
                    self._chat_display.append(f"<div style='text-align: left; color:{C['accent4']}; font-size:10pt;'><br>[{s_ts}] {s_text}</div>")
                else:
                    sender = "self" if m.get("is_self") else "peer"
                    self._append_msg(m["user"], m["text"], m["ts"], sender)

        self._refresh_room_list()
        self._unlock_input()
        self._invite_btn.show() if name != "global" else self._invite_btn.hide()

    def _show_create_room_dialog(self):
        dlg = _RoomDialog(self, "Create Room", create_mode=True)
        if dlg.exec() == QDialog.DialogCode.Accepted and dlg.result_data:
            self._do_create_room(*dlg.result_data)

    def _show_join_room_dialog(self):
        dlg = _RoomDialog(self, "Join Room", create_mode=False, available_rooms=list(self._rooms.keys()))
        if dlg.exec() == QDialog.DialogCode.Accepted and dlg.result_data:
            self._do_join_room(*dlg.result_data)

    def _do_create_room(self, name: str, pw: str):
        name = _sanitise_name(name, MAX_ROOM_NAME)
        if not name:
            QMessageBox.critical(self, "Error", "Room name cannot be empty.")
            return
        if name in self._rooms:
            QMessageBox.critical(self, "Room Exists", f'Room "{name}" already exists.')
            return
        pw_hash = _hash_password(pw)
        self._rooms[name] = RoomState(name, pw_hash, is_host=True)
        self._switch_room(name)
        self._add_sys_to_room(
            name, f"🏠 Room \"{name}\" created "
            f"{'(password protected)' if pw_hash else '(open)'}")
        self._refresh_room_list()
        self._announce_room_presence(name)

    def _do_join_room(self, name: str, pw: str):
        name = _sanitise_name(name, MAX_ROOM_NAME)
        if not name:
            QMessageBox.critical(self, "Error", "Room name cannot be empty.")
            return
            
        if name in self._rooms:
            self._switch_room(name)
            return

        pw_hash = _hash_password(pw)
        
        if not self._group or not self._group.active_peer_ids():
            QMessageBox.warning(self, "Offline", "Not connected to any peers. Cannot join room.")
            return

        join_msg = json.dumps({
            "type": MSG_ROOM_JOIN,
            "room": name,
            "pw_hash": pw_hash
        }, separators=(",", ":"))
        
        self._broadcast_encrypted(join_msg)
        
        self._pending_joins[name] = pw_hash
        self._add_sys_to_active(f"⏳ Requesting to join room '{name}'...")
        
        QTimer.singleShot(3000, lambda: self._check_join_timeout(name))

    def _check_join_timeout(self, name: str):
        if name in self._pending_joins:
            del self._pending_joins[name]
            self._add_err_to_active(f"Room '{name}' not found or no response.")

    def _generate_identity(self):
        if self._keypair:
            self._keypair.clear()
        if self._group:
            self._group.clear_all()
        self._keypair = KeyPair()
        self._group   = GroupSession(self._keypair)
        self._pending_hs.clear()
        fp = self._keypair.fingerprint()
        self._fp_lbl.setText(f"🔑 {fp[:23]}…")

    def _add_global_room(self):
        self._rooms["global"] = RoomState("global", pw_hash="", is_host=True)
        self._switch_room("global")
        self._add_sys_to_room("global",
            "🔒 ShushChat v3  ·  Connect to peers, create/join rooms to chat securely.")

    def _do_set_username(self):
        raw = self._username_entry.text()
        name = _sanitise_name(raw, MAX_USERNAME)
        if not name:
            QMessageBox.critical(self, "Error", "Username cannot be empty.")
            return
        self._username = name
        if self._active_room:
            self._add_sys_to_room(
                self._active_room, f'👤 Username set to "{self._username}"')
                
        if self._group:
            update_msg = json.dumps({
                "type": MSG_UPDATE_NAME,
                "username": name
            }, separators=(",", ":")).encode("utf-8")
            for pid in self._group.active_peer_ids():
                try:
                    self._net.send_to(pid, update_msg)
                except Exception as exc:
                    self._add_err_to_active(f"Failed to send name update to {pid[:8]}: {exc}")

    def _do_connect(self):
        port_str = self._port_entry.text().strip()
        if not _is_valid_port(port_str):
            QMessageBox.critical(self, "Invalid Port", "Port must be 1–65535.")
            return
        port = int(port_str)

        mode = "connect" if self._mode_group.checkedId() == 1 else "listen"
        if mode == "connect":
            host = self._ip_entry.text().strip()
            if not host:
                QMessageBox.critical(self, "Invalid IP", "Enter a peer IP.")
                return
            if not _is_valid_ip(host):
                QMessageBox.critical(self, "Invalid IP", f'"{host}" is not a valid IP address.')
                return
            self._set_status(f"Connecting to {host}:{port}…")
            self._dialled.add(f"{host}:{port}")
            self._net.connect(host, port)
        else:
            self._set_status(f"Listening on port {port}…")
            self._net.listen(port)
            self._disconnect_btn.setEnabled(True)
            self._add_sys_to_active(f"👂 Listening on port {port}…")

    def _do_disconnect_all(self):
        self._net.disconnect_all()
        self._disconnect_btn.setEnabled(False)
        self._dialled.clear()

    def _peer_list_context_menu(self, pos):
        item = self._peer_list_ui.itemAt(pos)
        if not item:
            return
        
        from PyQt6.QtWidgets import QMenu
        menu = QMenu(self)
        menu.setStyleSheet(f"background-color: {C['panel']}; color: {C['fg']}; border: 1px solid {C['border']};")
        disconnect_action = menu.addAction("✕ Disconnect Peer")
        
        action = menu.exec(self._peer_list_ui.mapToGlobal(pos))
        if action == disconnect_action:
            pid = item.data(Qt.ItemDataRole.UserRole)
            self._net.disconnect(pid)
            self._add_sys_to_active(f"🪓 Manually disconnected from {item.text()}")

    def _do_send(self):
        if not self._active_room:
            return
        raw_text = self._msg_entry.text()
        text = _sanitise_text(raw_text, MAX_MSG_TEXT)
        if not text:
            return

        msg_id = str(uuid.uuid4())
        ts     = self._now()
        active_pw = (self._rooms[self._active_room].pw_hash
                     if self._active_room in self._rooms else "")
        core_payload = f"{msg_id}:{self._active_room}:{self._username}:{text}:{ts}"
        signature = self._identity_key.sign(core_payload.encode('utf-8'))
        
        payload = json.dumps({
            "type": MSG_CHAT, "msg_id": msg_id,
            "room": self._active_room, "username": self._username,
            "text": text, "ts": ts, "pw_hash": active_pw,
            "author_pubkey": self._identity_key.public_bytes().hex(),
            "signature": signature.hex()
        }, separators=(",", ":"))

        my_hash = self._identity_key.public_bytes().hex()[-4:].upper()
        display_name = f"{self._username}#{my_hash}"
        self._rooms[self._active_room].messages.append(
            {"user": display_name, "text": text, "ts": ts, "is_self": True})
        self._append_msg(display_name, text, ts, "self")
        self._msg_entry.setText("")
        self._refresh_room_list()

        if self._group and self._group.active_peer_ids():
            self._group.mark_seen(msg_id)
            self._broadcast_encrypted(payload)

    def _broadcast_encrypted(self, plain: str, exclude: str = None):
        failed = []
        if not self._group:
            return
        for pid in self._group.active_peer_ids():
            if pid == exclude:
                continue
            try:
                enc = self._group.encrypt(pid, plain)
                if not self._net.send_to(pid, enc):
                    failed.append(f"{pid[:8]}: send_to returned False")
            except Exception as e:
                failed.append(f"{pid[:8]}: {str(e)}")
        
        if failed:
            self._add_err_to_active(f"Delivery failed for {len(failed)} peer(s): " + " | ".join(failed))

    def _on_peer_connected(self, peer_id, peer):
        self.signals.peer_connected.emit(peer_id, peer)

    def _ui_peer_connected(self, peer_id, peer):
        self._pending_hs.add(peer_id)
        self._add_sys_to_active(f"🔗 TCP link [{peer.remote_addr}] — key exchange…")
        if not getattr(peer, 'is_incoming', False):
            self._send_handshake(peer_id)

    def _send_handshake(self, peer_id: str):
        signature = self._identity_key.sign(self._keypair.public_key_bytes())
        hs = json.dumps({
            "type": MSG_HANDSHAKE,
            "pubkey": self._keypair.public_key_bytes().hex(),
            "identity_pubkey": self._identity_key.public_bytes().hex(),
            "signature": signature.hex(),
            "listen_port": self._net.listen_port,
            "username": self._username
        }, separators=(",", ":")).encode("utf-8")
        self._net.send_to(peer_id, hs)

    def _on_raw_message(self, peer_id, raw):
        self.signals.raw_message.emit(peer_id, raw)

    def _ui_dispatch(self, peer_id, raw):
        if peer_id in self._pending_hs:
            self._handle_handshake(peer_id, raw)
        else:
            try:
                msg = json.loads(raw.decode("utf-8"))
                mtype = msg.get("type")
                if isinstance(msg, dict):
                    if mtype == MSG_PEER_LIST:
                        self._rx_peer_list(peer_id, msg)
                        return
                    elif mtype == MSG_UPDATE_NAME:
                        self._rx_update_name(peer_id, msg)
                        return
            except (UnicodeDecodeError, json.JSONDecodeError):
                pass
            self._handle_encrypted(peer_id, raw)

    def _on_peer_disconnected(self, peer_id, reason):
        self.signals.peer_disconnected.emit(peer_id, reason)

    def _ui_peer_disconnected(self, peer_id, reason):
        label = self._peer_display.pop(peer_id, peer_id[:8])
        self._peer_addresses.pop(peer_id, None)
        self._pending_hs.discard(peer_id)

        if self._group:
            self._group.remove_peer(peer_id)

        self._add_sys_to_active(f"🔌 {label} disconnected — {reason}")
        self._update_peer_count()

        if self._net.peer_count() == 0:
            self._set_conn_badge("offline")
            self._disconnect_btn.setEnabled(False)

    def _on_network_error(self, msg):
        self.signals.network_error.emit(msg)

    def _ui_network_error(self, msg):
        self._add_err_to_active(f"⚠ {msg}")
        if self._net.peer_count() == 0:
            self._set_conn_badge("offline")

    def _handle_handshake(self, peer_id: str, raw: bytes):
        try:
            try:
                msg = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError(f"Handshake parse error: {exc}") from exc

            if not isinstance(msg, dict):
                raise ValueError("Handshake payload must be a JSON object.")

            msg_type = msg.get("type")

            if msg_type == MSG_PEER_LIST:
                self._rx_peer_list(peer_id, msg)
                return

            if msg_type != MSG_HANDSHAKE:
                if self._group and self._group.has_peer(peer_id):
                    self._pending_hs.discard(peer_id)
                    self._handle_encrypted(peer_id, raw)
                return

            pubkey_hex = msg.get("pubkey", "")
            id_pubkey_hex = msg.get("identity_pubkey", "")
            sig_hex = msg.get("signature", "")
            if not _is_valid_pubkey_hex(pubkey_hex) or not id_pubkey_hex or not sig_hex:
                raise ValueError("Missing or invalid crypto fields.")

            peer_pub = bytes.fromhex(pubkey_hex)
            id_pubkey = bytes.fromhex(id_pubkey_hex)
            sig_bytes = bytes.fromhex(sig_hex)
            
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            try:
                author_key = Ed25519PublicKey.from_public_bytes(id_pubkey)
                author_key.verify(sig_bytes, peer_pub)
            except Exception as exc:
                raise ValueError(f"Handshake signature verification failed: {exc}")

            raw_port = msg.get("listen_port")
            peer_listen_port: Optional[int] = None
            if raw_port is not None:
                if not _is_valid_port(raw_port):
                    raise ValueError(f"Invalid listen_port: {repr(raw_port)}")
                peer_listen_port = int(raw_port)

            fp = self._group.add_peer(peer_id, peer_pub)
            self._pending_hs.discard(peer_id)

            peer_obj = self._net.get_peer(peer_id)
            addr  = peer_obj.remote_addr if peer_obj else "?"
            remote_ip = addr.split(":")[0] if ":" in addr else addr
            
            peer_username = msg.get("username", "Unknown")
            peer_username = f"{peer_username}#{id_pubkey_hex[-4:].upper()}"
            display_port = peer_listen_port if peer_listen_port else (addr.split(":")[1] if ":" in addr else "?")
            label = f"👤 {peer_username} ({remote_ip}:{display_port})"
            self._peer_display[peer_id] = label

            if peer_listen_port and _is_valid_ip(remote_ip):
                self._peer_addresses[peer_id] = (remote_ip, peer_listen_port, pubkey_hex)

            self._add_sys_to_active(f"🔑 Secure link ✅  [{addr}]  —  AES-256-GCM active")
            self._set_conn_badge("connected")
            self._unlock_input()
            self._disconnect_btn.setEnabled(True)
            self._update_peer_count()

            if peer_obj and getattr(peer_obj, 'is_incoming', False):
                self._send_handshake(peer_id)

        except Exception as exc:
            self._add_err_to_active(f"Handshake failed {peer_id[:8]}: {exc}")
            self._pending_hs.discard(peer_id)

    def _build_peer_list_for(self, exclude_peer_id: str) -> list:
        result = []
        for pid, (ip, port, pubkey_hex) in self._peer_addresses.items():
            if pid == exclude_peer_id:
                continue
            result.append({"ip": ip, "port": port, "pubkey": pubkey_hex})
        return result

    def _rx_peer_list(self, from_peer_id: str, msg: dict) -> None:
        peers = msg.get("peers", [])
        if not isinstance(peers, list):
            return

        MAX_PEER_LIST_ENTRIES = 50
        peers = peers[:MAX_PEER_LIST_ENTRIES]

        peer_obj = self._net.get_peer(from_peer_id)
        introducer_ip = ""
        if peer_obj and ":" in peer_obj.remote_addr:
            introducer_ip = peer_obj.remote_addr.split(":")[0]

        newly_dialling = 0
        for entry in peers:
            if not isinstance(entry, dict):
                continue
            try:
                ip   = str(entry.get("ip", "")).strip()
                port = entry.get("port")
            except (TypeError, ValueError):
                continue

            if not ip or not _is_valid_port(port):
                continue
            port = int(port)

            if ip == "self":
                ip = introducer_ip
            if not ip or not _is_valid_ip(ip):
                continue

            key = f"{ip}:{port}"
            if key in self._dialled:
                continue

            self._dialled.add(key)
            newly_dialling += 1
            self._add_sys_to_active(f"🔀 Mesh: dialling {key}…")
            self._net.connect(ip, port)

        if newly_dialling:
            self._add_sys_to_active(f"🕸 Mesh expanding — dialling {newly_dialling} new peer(s)")

    def _handle_encrypted(self, peer_id: str, raw: bytes):
        if not self._group or not self._group.has_peer(peer_id):
            return
        try:
            plain = self._group.decrypt(peer_id, raw)
        except ValueError as exc:
            self._add_err_to_active(f"🚫 Integrity FAILED {peer_id[:8]}: {exc}")
            return
        except Exception:
            return

        try:
            msg = json.loads(plain)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return

        if not isinstance(msg, dict):
            return

        mtype = msg.get("type", "")
        if   mtype == MSG_ROOM_CREATE:
            pass
        elif mtype == MSG_ROOM_JOIN:
            self._rx_room_join(peer_id, msg)
        elif mtype == MSG_ROOM_JOIN_OK:
            self._rx_room_join_ok(peer_id, msg)
        elif mtype == MSG_ROOM_JOIN_FAIL:
            self._rx_room_join_fail(peer_id, msg)
        elif mtype == MSG_ROOM_HELLO:
            self._rx_room_hello(peer_id, msg, plain)
        elif mtype == MSG_CONN_REQ:
            self._rx_conn_req(peer_id, msg, plain)
        elif mtype == MSG_ROOM_INVITE:
            self._rx_room_invite(peer_id, msg)
        elif mtype == MSG_CHAT:
            self._rx_chat(peer_id, msg, plain)

    def _rx_room_join(self, peer_id: str, msg: dict):
        room_name = msg.get("room", "")
        pw_hash = msg.get("pw_hash", "")
        
        if room_name in self._rooms:
            room = self._rooms[room_name]
            if room.pw_hash and not hmac.compare_digest(room.pw_hash, pw_hash):
                reply_type = MSG_ROOM_JOIN_FAIL
            else:
                reply_type = MSG_ROOM_JOIN_OK
                
            reply_msg = json.dumps({
                "type": reply_type,
                "room": room_name
            }, separators=(",", ":"))
            
            try:
                enc = self._group.encrypt(peer_id, reply_msg)
                self._net.send_to(peer_id, enc)
            except Exception as exc:
                self._add_err_to_active(f"Join reply error: {exc}")

    def _rx_room_join_ok(self, peer_id: str, msg: dict):
        room_name = msg.get("room", "")
        if room_name in self._pending_joins:
            pw_hash = self._pending_joins.pop(room_name)
            self._rooms[room_name] = RoomState(room_name, pw_hash, is_host=False)
            self._switch_room(room_name)
            self._add_sys_to_room(room_name, f"✅ Joined \"{room_name}\" locally.")
            self._refresh_room_list()
            self._announce_room_presence(room_name)

    def _rx_room_join_fail(self, peer_id: str, msg: dict):
        room_name = msg.get("room", "")
        if room_name in self._pending_joins:
            del self._pending_joins[room_name]
            self._add_err_to_active(f"Failed to join '{room_name}': Incorrect password.")
            QMessageBox.critical(self, "Join Failed", f"Incorrect password for room '{room_name}'.")

    def _rx_chat(self, peer_id: str, msg: dict, plain: str):
        required = {"msg_id", "room", "username", "text", "ts", "author_pubkey", "signature"}
        if required - msg.keys():
            return
            
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            author_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(msg["author_pubkey"]))
            core_payload = f'{msg["msg_id"]}:{msg["room"]}:{msg["username"]}:{msg["text"]}:{msg["ts"]}'.encode('utf-8')
            author_key.verify(bytes.fromhex(msg["signature"]), core_payload)
        except Exception:
            return

        msg_id = str(msg["msg_id"])
        if not _is_valid_uuid(msg_id):
            return

        if self._group.is_duplicate(msg_id):
            return
        self._group.mark_seen(msg_id)

        self._gossip(peer_id, plain)

        room_name = _sanitise_name(str(msg["room"]), MAX_ROOM_NAME)
        username  = _sanitise_name(str(msg["username"]), MAX_USERNAME)
        username  = f'{username}#{msg["author_pubkey"][-4:].upper()}'
        text      = _sanitise_text(str(msg["text"]), MAX_MSG_TEXT)
        ts        = str(msg["ts"])[:8]

        if not room_name or not username or not text:
            return

        raw_pw = msg.get("pw_hash", "")
        if raw_pw and not _is_valid_hex64(str(raw_pw)):
            return
        msg_pw = str(raw_pw) if raw_pw else ""

        if room_name not in self._rooms:
            return

        room = self._rooms[room_name]

        if room.pw_hash:
            if not hmac.compare_digest(room.pw_hash, msg_pw):
                return

        room.messages.append(
            {"user": username, "text": text, "ts": ts, "is_self": False})

        if room_name == self._active_room:
            self._append_msg(username, text, ts, "peer")
        else:
            room.unread += 1

        self._refresh_room_list()

    def _rx_room_hello(self, peer_id: str, msg: dict, plain: str):
        msg_id = str(msg.get("msg_id", ""))
        if not _is_valid_uuid(msg_id) or self._group.is_duplicate(msg_id):
            return
        self._group.mark_seen(msg_id)
        
        # Gossip this discovery further
        self._gossip(peer_id, plain)

        room_name = str(msg.get("room", ""))
        if room_name not in self._rooms:
            return

        ip = msg.get("ip")
        port = msg.get("port")
        if not (ip and port):
            return
            
        try:
            port = int(port)
        except ValueError:
            return

        my_addrs = self._get_local_ips()
        if ip in my_addrs and port == self._net.listen_port:
            return

        addr_key = f"{ip}:{port}"
        if addr_key in self._dialled:
            return
            
        self._dialled.add(addr_key)
        self._net.connect(ip, port)

    def _announce_room_presence(self, room_name: str):
        if not self._net.listen_port:
            return
            
        my_ips = self._get_local_ips()
        ip = my_ips[0] if my_ips else "127.0.0.1"
        
        msg_id = str(uuid.uuid4())
        hello_msg = json.dumps({
            "type": MSG_ROOM_HELLO,
            "msg_id": msg_id,
            "room": room_name,
            "ip": ip,
            "port": self._net.listen_port
        }, separators=(",", ":"))
        
        self._group.mark_seen(msg_id)
        self._broadcast_encrypted(hello_msg)

    def _get_local_ips(self) -> list:
        import socket
        try:
            return socket.gethostbyname_ex(socket.gethostname())[2]
        except OSError:
            return ["127.0.0.1"]

    def _gossip(self, source: str, plain: str):
        for pid in self._group.active_peer_ids():
            if pid == source:
                continue
            try:
                enc = self._group.encrypt(pid, plain)
                self._net.send_to(pid, enc)
            except Exception as exc:
                self._add_err_to_active(f"Gossip error: {exc}")

    def _set_conn_badge(self, state: str):
        mapping = {
            "offline":    ("⬤  OFFLINE",      C["accent5"]),
            "connecting": ("◌  CONNECTING…",  C["accent4"]),
            "connected":  ("⬤  SECURE MESH",  C["accent3"]),
        }
        t, c = mapping.get(state, mapping["offline"])
        self._conn_badge.setText(t)
        self._conn_badge.setStyleSheet(f"color: {c}; font-weight: bold; font-size: 12pt; border: none;")

    def _set_status(self, text: str):
        self._status_lbl.setText(text)

    def _unlock_input(self):
        self._msg_entry.setEnabled(True)
        self._msg_entry.setText("")
        self._send_btn.setEnabled(True)
        self._msg_entry.setFocus()

    def _lock_input(self):
        self._msg_entry.setEnabled(False)
        self._send_btn.setEnabled(False)

    def _update_peer_count(self):
        n   = len(self._peer_display)
        dot = "🟢" if n else "⬤"
        self._peer_count_lbl.setText(f"{dot} {n} peer{'s' if n != 1 else ''} connected")
        
        self._peer_list_ui.clear()
        for label in self._peer_display.values():
            self._peer_list_ui.addItem(label)

    def _rx_update_name(self, peer_id: str, msg: dict):
        new_name = msg.get("username", "Unknown")
        addr_info = self._peer_addresses.get(peer_id)
        if addr_info:
            remote_ip = addr_info[0]
            display_port = addr_info[1]
            label = f"👤 {new_name} ({remote_ip}:{display_port})"
            self._peer_display[peer_id] = label
            self._update_peer_count()

    def _now(self):
        return datetime.datetime.now().strftime("%H:%M")

    def _append_msg(self, username, text, ts, sender):
        is_self = (sender == "self")
        name_col = C["accent"] if is_self else C["accent3"]
        msg_col = C["self_msg"] if is_self else C["peer_msg"]
        ts_col = C["fg3"]

        s_text = html.escape(text).replace("\n", "<br>")
        s_user = html.escape(username)
        s_ts = html.escape(ts)

        if is_self:
            html_msg = f"<div style='text-align: left; margin-bottom: 5px;'><span style='color:{ts_col}; font-size:10pt;'>{s_ts}</span> <span style='color:{name_col}; font-weight:bold;'>{s_user}</span><br><span style='color:{msg_col}; margin-left: 20px;'>{s_text}</span></div>"
        else:
            html_msg = f"<div style='text-align: left; margin-bottom: 5px;'><span style='color:{name_col}; font-weight:bold;'>{s_user}</span> <a href='connect:{s_user}' style='color:{C['accent']}; text-decoration:none; font-size:9pt;'>[+]</a> <span style='color:{ts_col}; font-size:10pt;'>{s_ts}</span><br><span style='color:{msg_col}; margin-left: 20px;'>{s_text}</span></div>"

        self._chat_display.append(html_msg)
        self._chat_display.setAlignment(Qt.AlignmentFlag.AlignLeft)

    def _add_sys_to_room(self, room_name: str, text: str):
        ts = self._now()
        if room_name in self._rooms:
            self._rooms[room_name].messages.append(
                {"user": "•", "text": text, "ts": ts, "system": True})
        if room_name == self._active_room:
            s_text = html.escape(text)
            self._chat_display.append(f"<div style='text-align: left; color:{C['accent4']}; font-size:10pt;'><br>[{ts}] {s_text}</div>")
            self._chat_display.setAlignment(Qt.AlignmentFlag.AlignLeft)

    def _add_sys_to_active(self, text: str):
        if self._active_room:
            self._add_sys_to_room(self._active_room, text)

    def _add_err_to_active(self, text: str):
        ts = self._now()
        s_text = html.escape(text)
        self._chat_display.append(f"<div style='text-align: left; color:{C['accent5']}; font-size:10pt;'><br>[{ts}] ERROR: {s_text}</div>")
        self._chat_display.setAlignment(Qt.AlignmentFlag.AlignLeft)

    def _handle_chat_link(self, url):
        target = url.toString()
        if target.startswith("connect:"):
            target_user = target.split(":", 1)[1]
            if not self._net.listen_port:
                QMessageBox.warning(self, "Listen Required", "You must be listening on a port to send connect requests.")
                return
            reply = QMessageBox.question(self, "Connect Request", f"Send direct connection request to '{target_user}'?")
            if reply == QMessageBox.StandardButton.Yes:
                bind_ip = self._ip_entry.text().strip()
                if bind_ip == "0.0.0.0" or not bind_ip:
                    my_ips = self._get_local_ips()
                    ip = my_ips[0] if my_ips else "127.0.0.1"
                else:
                    ip = bind_ip
                
                req = json.dumps({
                    "type": MSG_CONN_REQ,
                    "msg_id": str(uuid.uuid4()),
                    "target": target_user,
                    "sender": self._username,
                    "ip": ip,
                    "port": self._net.listen_port
                }, separators=(",", ":"))
                self._broadcast_encrypted(req)
                self._add_sys_to_active(f"📡 Sent connect request to '{target_user}'.")

    def _rx_conn_req(self, peer_id: str, msg: dict, plain: str):
        msg_id = str(msg.get("msg_id", ""))
        if not _is_valid_uuid(msg_id) or self._group.is_duplicate(msg_id):
            return
        self._group.mark_seen(msg_id)
        self._gossip(peer_id, plain)

        target = msg.get("target")
        if target == self._username:
            sender = msg.get("sender", "Unknown")
            ip = msg.get("ip")
            port = msg.get("port")
            if not (ip and port): return
            
            try: port = int(port)
            except ValueError: return

            reply = QMessageBox.question(self, "Connection Request", f"User '{sender}' wants to connect directly. Accept?")
            if reply == QMessageBox.StandardButton.Yes:
                self._net.connect(ip, port)

    def _show_invite_dialog(self):
        if not self._active_room or self._active_room == "global": return
        
        dlg = QDialog(self)
        dlg.setWindowTitle("Invite Peers")
        dlg.resize(300, 400)
        dlg.setStyleSheet(f"background-color: {C['bg']}; color: {C['fg']};")
        layout = QVBoxLayout(dlg)
        
        lbl = QLabel(f"Invite to #{self._active_room}")
        lbl.setStyleSheet(f"font-size: 12pt; font-weight: bold; color: {C['accent']};")
        layout.addWidget(lbl)
        
        list_w = QListWidget()
        list_w.setStyleSheet(f"background-color: {C['bg2']}; border: 1px solid {C['border']};")
        for pid, label in self._peer_display.items():
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, pid)
            list_w.addItem(item)
        layout.addWidget(list_w)
        
        btn = QPushButton("Send Invite")
        btn.setStyleSheet(f"background-color: {C['accent2']}; color: white; padding: 6px; border-radius: 4px;")
        btn.clicked.connect(dlg.accept)
        layout.addWidget(btn)
        
        if dlg.exec() == QDialog.DialogCode.Accepted:
            sel = list_w.selectedItems()
            if not sel: return
            pid = sel[0].data(Qt.ItemDataRole.UserRole)
            room = self._rooms[self._active_room]
            inv = json.dumps({
                "type": MSG_ROOM_INVITE,
                "room": self._active_room,
                "pw_hash": room.pw_hash
            }, separators=(",", ":"))
            try:
                enc = self._group.encrypt(pid, inv)
                self._net.send_to(pid, enc)
                QMessageBox.information(self, "Sent", f"Invite sent to {sel[0].text()}!")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to send: {e}")

    def _rx_room_invite(self, peer_id: str, msg: dict):
        room = msg.get("room")
        pw_hash = msg.get("pw_hash", "")
        if not room or room in self._rooms: return
        
        sender_lbl = self._peer_display.get(peer_id, peer_id[:8])
        reply = QMessageBox.question(self, "Room Invite", f"Peer '{sender_lbl}' invites you to join room '{room}'. Join?")
        if reply == QMessageBox.StandardButton.Yes:
            self._rooms[room] = RoomState(room, pw_hash, is_host=False)
            self._switch_room(room)
            self._add_sys_to_room(room, f"✅ Joined \"{room}\" via invite.")
            self._refresh_room_list()
            self._announce_room_presence(room)

    def closeEvent(self, event):
        try:
            self._net.disconnect_all()
        except OSError:
            pass
        if self._group:
            self._group.clear_all()
        if self._keypair:
            self._keypair.clear()
        event.accept()

class _RoomDialog(QDialog):
    def __init__(self, parent, title, create_mode=True, available_rooms=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setStyleSheet(f"background-color: {C['bg']}; color: {C['fg']};")
        self.setFixedSize(420, 340 if (not create_mode and available_rooms) else 290)
        self.result_data = None
        self._create_mode = create_mode
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 14, 28, 14)
        
        lbl = QLabel(title)
        lbl.setStyleSheet(f"color: {C['accent']}; font-weight: bold; font-size: 15pt;")
        layout.addWidget(lbl)
        
        sep = QFrame()
        sep.setFixedHeight(1)
        sep.setStyleSheet(f"background-color: {C['border']}; border: none;")
        layout.addWidget(sep)
        
        if not create_mode and available_rooms:
            lbl2 = QLabel("Available rooms:")
            lbl2.setStyleSheet(f"color: {C['fg3']}; font-size: 11pt;")
            layout.addWidget(lbl2)
            self._lb = QListWidget()
            self._lb.setStyleSheet(f"background-color: {C['input_bg']}; color: {C['fg']}; border: 1px solid {C['border']};")
            self._lb.setFixedHeight(80)
            self._lb.addItems(available_rooms)
            self._lb.itemSelectionChanged.connect(self._on_sel)
            layout.addWidget(self._lb)
            
        lbl3 = QLabel("Room name:")
        lbl3.setStyleSheet(f"color: {C['fg3']}; font-size: 11pt;")
        layout.addWidget(lbl3)
        self._name_entry = QLineEdit()
        self._name_entry.setStyleSheet(f"background-color: {C['input_bg']}; color: {C['fg']}; border: 1px solid {C['border']}; padding: 5px;")
        layout.addWidget(self._name_entry)
        
        pw_lbl = "Set password (leave blank = open room):" if create_mode else "Password (leave blank if none):"
        lbl4 = QLabel(pw_lbl)
        lbl4.setStyleSheet(f"color: {C['fg3']}; font-size: 11pt;")
        layout.addWidget(lbl4)
        self._pw_entry = QLineEdit()
        self._pw_entry.setEchoMode(QLineEdit.EchoMode.Password)
        self._pw_entry.setStyleSheet(f"background-color: {C['input_bg']}; color: {C['fg']}; border: 1px solid {C['border']}; padding: 5px;")
        self._pw_entry.returnPressed.connect(self._submit)
        layout.addWidget(self._pw_entry)
        
        btn_layout = QHBoxLayout()
        act_txt = "Create Room" if create_mode else "Join Room"
        act_col = C["accent3"] if create_mode else C["accent2"]
        btn_ok = QPushButton(act_txt)
        btn_ok.setStyleSheet(f"background-color: {act_col}; color: white; border: none; padding: 8px; font-weight: bold; font-size: 12pt;")
        btn_ok.clicked.connect(self._submit)
        btn_cancel = QPushButton("Cancel")
        btn_cancel.setStyleSheet(f"background-color: {C['bg4']}; color: {C['fg2']}; border: none; padding: 8px; font-weight: bold; font-size: 12pt;")
        btn_cancel.clicked.connect(self.reject)
        
        btn_layout.addWidget(btn_ok)
        btn_layout.addWidget(btn_cancel)
        layout.addLayout(btn_layout)
        
    def _on_sel(self):
        items = self._lb.selectedItems()
        if items:
            self._name_entry.setText(items[0].text())
            
    def _submit(self):
        raw_name = self._name_entry.text()
        name = _sanitise_name(raw_name, MAX_ROOM_NAME)
        if not name:
            QMessageBox.critical(self, "Error", "Room name cannot be empty.")
            return
        if not _SAFE_NAME_RE.match(name):
            QMessageBox.critical(self, "Error", "Room name may only contain letters, digits, spaces, hyphens, and underscores.")
            return

        pw = self._pw_entry.text()
        if self._create_mode and pw:
            import re
            if len(pw) < 8 or not re.search(r"[a-z]", pw) or not re.search(r"[A-Z]", pw) or not re.search(r"\d", pw) or not re.search(r"[^a-zA-Z0-9]", pw):
                QMessageBox.critical(self, "Weak Password", "Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character.")
                return

        self.result_data = (name, pw)
        self.accept()
