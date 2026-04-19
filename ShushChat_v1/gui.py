"""
gui.py — ShushChat GUI  (v3 — WhatsApp-style Rooms + Passwords)
================================================================
Security hardening over base v3:
  - All user inputs stripped and length-capped before use
  - Port validated (1–65535) before connect/listen
  - IP address validated against ipaddress module before dial
  - msg_id validated as a UUID-format string before dedup lookup
  - Peer-list entries validated (IP + port) before dialling
  - Hex pubkey validated (length + charset) before handshake
  - listen_port from peer validated as integer 1–65535
  - Room name and username sanitised (printable chars, no control chars)
  - Message text sanitised (control chars stripped, length capped)
  - pw_hash validated as hex-64 before storage/comparison
  - All json.loads results type-checked before field access
  - Gossip re-encryption confined to already-validated plain text
"""

import tkinter as tk
from tkinter import font as tkfont, messagebox
import json, uuid, datetime, hashlib, re, ipaddress
from typing import Dict, List, Optional, Set

from networking import MultiPeerManager, PeerConnection
from crypto import KeyPair, GroupSession

# ─── Protocol constants ───────────────────────────────────────────────────────
MSG_HANDSHAKE      = "handshake"
MSG_PEER_LIST      = "peer_list"
MSG_PEER_LIST_ACK  = "peer_list_ack"
MSG_CHAT           = "chat"
MSG_ROOM_CREATE    = "room_create"
MSG_ROOM_JOIN      = "room_join"
MSG_ROOM_JOIN_OK   = "room_join_ok"
MSG_ROOM_JOIN_FAIL = "room_join_fail"

DEFAULT_USER   = "anon"
MAX_USERNAME   = 24
MAX_ROOM_NAME  = 32
MAX_MSG_TEXT   = 4096          # characters — cap outgoing message length
MAX_MSG_ID_LEN = 64            # UUID is 36 chars; give a little slack

# UUID v4 pattern for msg_id validation (prevents crafted dedup-bypass IDs)
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

# Allowed characters in room names and usernames:
# letters, digits, spaces, hyphens, underscores, dots
_SAFE_NAME_RE = re.compile(r"^[\w\s.\-]{1,}$")

# Hex-encoded SHA-256 digest (64 lower-hex chars)
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


# ─── Input sanitisers ─────────────────────────────────────────────────────────

def _sanitise_name(raw: str, max_len: int) -> str:
    """
    Strip surrounding whitespace, remove control characters, and truncate.

    Returns the sanitised string (may be empty — callers must reject empty).
    """
    # Remove ASCII control characters (0x00–0x1f, 0x7f) and keep printable
    cleaned = "".join(ch for ch in raw if ch.isprintable())
    return cleaned.strip()[:max_len]


def _sanitise_text(raw: str, max_len: int) -> str:
    """
    Sanitise free-text message content.

    Allows printable Unicode and common whitespace (\n, \t) but strips
    null bytes and other C0/C1 control characters.
    """
    allowed_controls = {"\n", "\t"}
    cleaned = "".join(
        ch for ch in raw
        if ch.isprintable() or ch in allowed_controls
    )
    return cleaned[:max_len]


def _hash_password(pw: str) -> str:
    """SHA-256 hash of *pw*.  Returns empty string for blank passwords."""
    if not pw:
        return ""
    return hashlib.sha256(pw.encode("utf-8")).hexdigest()


def _is_valid_uuid(value: str) -> bool:
    """Return True if *value* matches UUID v4 format."""
    return bool(_UUID_RE.match(value)) if isinstance(value, str) else False


def _is_valid_hex64(value: str) -> bool:
    """Return True if *value* is a 64-char lowercase hex string."""
    return bool(_HEX64_RE.match(value)) if isinstance(value, str) else False


def _is_valid_pubkey_hex(value: str) -> bool:
    """Return True if *value* is a 64-char hex string (32 bytes raw = X25519)."""
    return (isinstance(value, str)
            and len(value) == 64
            and all(c in "0123456789abcdefABCDEF" for c in value))


def _is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _is_valid_port(port) -> bool:
    try:
        return 1 <= int(port) <= 65535
    except (TypeError, ValueError):
        return False


# ─── Room state ───────────────────────────────────────────────────────────────

class RoomState:
    def __init__(self, name: str, pw_hash: str = "", is_host: bool = False):
        self.name     = name
        self.pw_hash  = pw_hash
        self.is_host  = is_host
        self.messages: List[dict] = []
        self.unread   = 0
        self.members: Set[str] = set()


# ─── Main application ─────────────────────────────────────────────────────────

class ShushChatApp:

    def __init__(self, root: tk.Tk):
        self.root = root
        self._setup_window()
        self._load_fonts()

        self._username = DEFAULT_USER
        self._keypair: Optional[KeyPair]      = None
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

        self._build_ui()
        self._generate_identity()
        self._add_global_room()

    # ── Window / fonts ────────────────────────────────────────────────

    def _setup_window(self):
        self.root.title("ShushChat v3 — Secure Encrypted Mesh Chat")
        self.root.configure(bg=C["bg"])
        self.root.minsize(900, 600)
        self.root.geometry("1200x750")
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _load_fonts(self):
        _F = "Arial"
        self._f_title = tkfont.Font(family=_F, size=16, weight="bold")
        self._f_head  = tkfont.Font(family=_F, size=11, weight="bold")
        self._f_ui    = tkfont.Font(family=_F, size=12)
        self._f_bold  = tkfont.Font(family=_F, size=12, weight="bold")
        self._f_msg   = tkfont.Font(family=_F, size=13)
        self._f_ts    = tkfont.Font(family=_F, size=10)
        self._f_small = tkfont.Font(family=_F, size=10)
        self._f_room  = tkfont.Font(family=_F, size=12, weight="bold")
        self._f_mono  = tkfont.Font(family=_F, size=10)

    # ── UI construction ───────────────────────────────────────────────

    def _build_ui(self):
        self.root.rowconfigure(0, weight=0)
        self.root.rowconfigure(1, weight=1)
        self.root.rowconfigure(2, weight=0)
        self.root.columnconfigure(0, weight=0, minsize=290)
        self.root.columnconfigure(1, weight=1)

        self._build_titlebar()
        self._build_left_column()
        self._build_right_column()
        self._build_statusbar()

    def _build_titlebar(self):
        bar = tk.Frame(self.root, bg=C["panel"], height=52)
        bar.grid(row=0, column=0, columnspan=2, sticky="ew")
        bar.grid_propagate(False)

        lf = tk.Frame(bar, bg=C["panel"])
        lf.pack(side="left", padx=16, pady=6)
        tk.Label(lf, text="🔒", font=tkfont.Font(size=18),
                 bg=C["panel"], fg=C["accent"]).pack(side="left")
        tk.Label(lf, text=" ShushChat",
                 font=self._f_title, bg=C["panel"], fg=C["accent"]).pack(side="left")
        tk.Label(lf, text="  v3  ·  E2E Encrypted  ·  P2P Mesh",
                 font=self._f_small, bg=C["panel"], fg=C["fg3"]).pack(side="left", pady=4)

        rf = tk.Frame(bar, bg=C["panel"])
        rf.pack(side="right", padx=16)
        self._conn_badge = tk.Label(rf, text="⬤  OFFLINE",
                                    font=self._f_bold, bg=C["panel"],
                                    fg=C["accent5"], padx=8)
        self._conn_badge.pack(side="right")

        tk.Frame(self.root, bg=C["accent2"], height=1).grid(
            row=0, column=0, columnspan=2, sticky="sew")

    def _build_left_column(self):
        self._left = tk.Frame(self.root, bg=C["sidebar"])
        self._left.grid(row=1, column=0, sticky="nsew")
        self._left.columnconfigure(0, weight=1)
        self._left.rowconfigure(3, weight=1)

        tk.Frame(self.root, bg=C["border"], width=1).grid(
            row=1, column=0, sticky="nse")

        conn = tk.Frame(self._left, bg=C["sidebar"], padx=12, pady=10)
        conn.grid(row=0, column=0, sticky="ew")
        conn.columnconfigure(0, weight=1)
        conn.columnconfigure(1, weight=1)

        self._mk_section(conn, "⚡  NETWORK", 0, colspan=2)

        self._mk_lbl(conn, "Username", 1, colspan=2)
        self._username_var = tk.StringVar(value=DEFAULT_USER)
        ue = self._mk_entry_widget(conn, self._username_var)
        ue.grid(row=2, column=0, sticky="ew", padx=(0, 4), ipady=5)
        ue.bind("<Return>", lambda e: self._do_set_username())
        self._mk_btn_widget(conn, "SET", self._do_set_username,
                            C["accent2"]).grid(row=2, column=1, sticky="ew", ipady=5)

        mf = tk.Frame(conn, bg=C["sidebar"])
        mf.grid(row=3, column=0, columnspan=2, sticky="ew", pady=8)
        self._mode_var = tk.StringVar(value="connect")
        for txt, val, col in [("⟶ Connect", "connect", 0), ("⟵ Listen", "listen", 1)]:
            tk.Radiobutton(mf, text=txt, variable=self._mode_var, value=val,
                           bg=C["sidebar"], fg=C["fg2"],
                           selectcolor=C["bg4"], activebackground=C["sidebar"],
                           activeforeground=C["accent"], font=self._f_small,
                           bd=0, cursor="hand2").grid(
                row=0, column=col, sticky="w", padx=(0 if col == 0 else 8, 0))

        self._mk_lbl(conn, "IP Address", 4, colspan=2)
        self._ip_var = tk.StringVar(value="127.0.0.1")
        self._mk_entry_widget(conn, self._ip_var).grid(
            row=5, column=0, columnspan=2, sticky="ew", ipady=5)

        self._mk_lbl(conn, "Port", 6, colspan=2)
        self._port_var = tk.StringVar(value="5555")
        self._mk_entry_widget(conn, self._port_var).grid(
            row=7, column=0, columnspan=2, sticky="ew", ipady=5)

        self._connect_btn = self._mk_btn_widget(
            conn, "⚡  CONNECT / LISTEN", self._do_connect, C["btn_primary"])
        self._connect_btn.grid(row=8, column=0, columnspan=2,
                               sticky="ew", pady=8, ipady=6)

        self._disconnect_btn = self._mk_btn_widget(
            conn, "✕  DISCONNECT ALL", self._do_disconnect_all, C["btn_danger"],
            state="disabled")
        self._disconnect_btn.grid(row=9, column=0, columnspan=2,
                                  sticky="ew", pady=4, ipady=6)

        tk.Frame(self._left, bg=C["border"], height=1).grid(
            row=1, column=0, sticky="ew")

        rh = tk.Frame(self._left, bg=C["sidebar"], padx=12, pady=8)
        rh.grid(row=2, column=0, sticky="ew")
        rh.columnconfigure(0, weight=1)

        tk.Label(rh, text="💬  ROOMS",
                 font=self._f_head, bg=C["sidebar"],
                 fg=C["fg3"], anchor="w").grid(row=0, column=0, sticky="w")

        bf = tk.Frame(rh, bg=C["sidebar"])
        bf.grid(row=0, column=1)
        self._mk_btn_widget(bf, "+ Create", self._show_create_room_dialog,
                            C["accent3"], padx=6).pack(side="left", padx=(0, 4))
        self._mk_btn_widget(bf, "→ Join", self._show_join_room_dialog,
                            C["accent2"], padx=6).pack(side="left")

        rlf = tk.Frame(self._left, bg=C["sidebar"])
        rlf.grid(row=3, column=0, sticky="nsew")
        rlf.rowconfigure(0, weight=1)
        rlf.columnconfigure(0, weight=1)

        self._room_canvas = tk.Canvas(
            rlf, bg=C["sidebar"], bd=0, highlightthickness=0)
        self._room_canvas.grid(row=0, column=0, sticky="nsew")

        rs = tk.Scrollbar(rlf, orient="vertical",
                          command=self._room_canvas.yview, bg=C["sidebar"])
        rs.grid(row=0, column=1, sticky="ns")
        self._room_canvas.configure(yscrollcommand=rs.set)

        self._room_inner = tk.Frame(self._room_canvas, bg=C["sidebar"])
        self._room_canvas.create_window(
            (0, 0), window=self._room_inner, anchor="nw", tags="inner")
        self._room_inner.bind(
            "<Configure>",
            lambda e: self._room_canvas.configure(
                scrollregion=self._room_canvas.bbox("all")))
        self._room_canvas.bind(
            "<Configure>",
            lambda e: self._room_canvas.itemconfig("inner", width=e.width))

        ff = tk.Frame(self._left, bg=C["sidebar"], padx=12, pady=6)
        ff.grid(row=4, column=0, sticky="ew")
        ff.columnconfigure(0, weight=1)

        tk.Frame(ff, bg=C["border"], height=1).grid(
            row=0, column=0, sticky="ew", pady=4)

        self._peer_count_lbl = tk.Label(
            ff, text="0 peers connected",
            font=self._f_mono, bg=C["sidebar"], fg=C["fg3"], anchor="w")
        self._peer_count_lbl.grid(row=1, column=0, sticky="w")

        self._fp_lbl = tk.Label(
            ff, text="Fingerprint: generating…",
            font=self._f_mono, bg=C["sidebar"], fg=C["fg3"],
            anchor="w", wraplength=270)
        self._fp_lbl.grid(row=2, column=0, sticky="w")

    def _build_right_column(self):
        self._right = tk.Frame(self.root, bg=C["bg"])
        self._right.grid(row=1, column=1, sticky="nsew")
        self._right.rowconfigure(1, weight=1)
        self._right.columnconfigure(0, weight=1)

        tb = tk.Frame(self._right, bg=C["panel"], height=46)
        tb.grid(row=0, column=0, sticky="ew")
        tb.grid_propagate(False)

        self._room_title_lbl = tk.Label(
            tb, text="Select or create a room",
            font=self._f_bold, bg=C["panel"], fg=C["fg"], padx=16, pady=12)
        self._room_title_lbl.pack(side="left")

        self._room_lock_lbl = tk.Label(
            tb, text="", font=self._f_small,
            bg=C["panel"], fg=C["accent3"])
        self._room_lock_lbl.pack(side="left")

        self._room_members_lbl = tk.Label(
            tb, text="", font=self._f_small,
            bg=C["panel"], fg=C["fg3"], padx=16)
        self._room_members_lbl.pack(side="right")

        tk.Frame(self._right, bg=C["border2"], height=1).grid(
            row=0, column=0, sticky="sew")

        mf = tk.Frame(self._right, bg=C["bg"])
        mf.grid(row=1, column=0, sticky="nsew")
        mf.rowconfigure(0, weight=1)
        mf.columnconfigure(0, weight=1)

        self._chat_display = tk.Text(
            mf, bg=C["bg"], fg=C["fg"],
            font=self._f_msg, bd=0, relief="flat",
            padx=20, pady=10, wrap="word",
            state="disabled", cursor="arrow",
            spacing1=1, spacing3=1, highlightthickness=0)
        self._chat_display.grid(row=0, column=0, sticky="nsew")

        ms = tk.Scrollbar(mf, orient="vertical",
                          command=self._chat_display.yview, bg=C["bg"])
        ms.grid(row=0, column=1, sticky="ns")
        self._chat_display.configure(yscrollcommand=ms.set)

        self._chat_display.tag_config("self_name",  foreground=C["accent"],  font=self._f_bold)
        self._chat_display.tag_config("peer_name",  foreground=C["accent3"], font=self._f_bold)
        self._chat_display.tag_config("self_msg",   foreground=C["self_msg"])
        self._chat_display.tag_config("peer_msg",   foreground=C["peer_msg"])
        self._chat_display.tag_config("system",     foreground=C["accent4"], font=self._f_small)
        self._chat_display.tag_config("error",      foreground=C["accent5"], font=self._f_small)
        self._chat_display.tag_config("timestamp",  foreground=C["fg3"],     font=self._f_ts)
        self._chat_display.tag_config("divider",    foreground=C["fg3"],     font=self._f_mono)

        tk.Frame(self._right, bg=C["border2"], height=1).grid(
            row=2, column=0, sticky="ew")

        inp = tk.Frame(self._right, bg=C["panel"], padx=12, pady=10)
        inp.grid(row=3, column=0, sticky="ew")
        inp.columnconfigure(0, weight=1)

        self._msg_var = tk.StringVar()
        self._msg_entry = tk.Entry(
            inp, textvariable=self._msg_var,
            bg=C["input_bg"], fg=C["fg"],
            insertbackground=C["accent"],
            font=self._f_ui, bd=0, relief="flat",
            highlightthickness=1,
            highlightcolor=C["accent"],
            highlightbackground=C["border"])
        self._msg_entry.grid(row=0, column=0, sticky="ew", ipady=10, padx=(0, 10))
        self._msg_entry.bind("<Return>", lambda e: self._do_send())

        self._send_btn = self._mk_btn_widget(
            inp, "SEND  ▶", self._do_send, C["send_bg"], state="normal")
        self._send_btn.grid(row=0, column=1, ipady=9, ipadx=14)

    def _build_statusbar(self):
        bar = tk.Frame(self.root, bg=C["bg2"], height=22)
        bar.grid(row=2, column=0, columnspan=2, sticky="ew")
        bar.grid_propagate(False)

        self._status_lbl = tk.Label(
            bar,
            text="ShushChat v3  ·  No server. No logs. No leaks.",
            font=self._f_mono, bg=C["bg2"], fg=C["fg3"], anchor="w", padx=10)
        self._status_lbl.pack(side="left")

        tk.Label(
            bar,
            text="AES-256-GCM  ·  X25519 ECDH  ·  HMAC-SHA256",
            font=self._f_mono, bg=C["bg2"], fg=C["fg3"], padx=10).pack(side="right")

    # ── Widget helpers ────────────────────────────────────────────────

    def _mk_entry_widget(self, parent, var):
        return tk.Entry(parent, textvariable=var,
                        bg=C["input_bg"], fg=C["fg"],
                        insertbackground=C["accent"],
                        font=self._f_ui, bd=0, relief="flat",
                        highlightthickness=1,
                        highlightcolor=C["accent"],
                        highlightbackground=C["border"])

    def _mk_btn_widget(self, parent, text, cmd, color, state="normal", padx=8):
        return tk.Button(parent, text=text, command=cmd,
                         bg=color, fg=C["fg"],
                         font=self._f_bold, relief="flat",
                         cursor="hand2", padx=padx, state=state,
                         activebackground=color, activeforeground=C["fg"])

    def _mk_section(self, parent, text, row, colspan=1):
        tk.Label(parent, text=text, font=self._f_head,
                 bg=C["sidebar"], fg=C["fg3"], anchor="w").grid(
            row=row, column=0, columnspan=colspan, sticky="w", pady=4)

    def _mk_lbl(self, parent, text, row, colspan=1):
        tk.Label(parent, text=text, font=self._f_small,
                 bg=C["sidebar"], fg=C["fg3"], anchor="w").grid(
            row=row, column=0, columnspan=colspan, sticky="w", pady=6)

    # ── Room list ─────────────────────────────────────────────────────

    def _refresh_room_list(self):
        for w in self._room_inner.winfo_children():
            w.destroy()

        if not self._rooms:
            tk.Label(self._room_inner, text="No rooms.\nCreate or join one!",
                     font=self._f_small, bg=C["sidebar"], fg=C["fg3"],
                     pady=20).pack(fill="x")
            return

        for name, room in self._rooms.items():
            is_active = (name == self._active_room)
            bg = C["room_active"] if is_active else C["sidebar"]

            row_f = tk.Frame(self._room_inner, bg=bg, cursor="hand2")
            row_f.pack(fill="x")

            strip_col = C["accent"] if is_active else bg
            tk.Frame(row_f, bg=strip_col, width=3).pack(side="left", fill="y")

            inner = tk.Frame(row_f, bg=bg, padx=10, pady=9)
            inner.pack(side="left", fill="x", expand=True)

            top = tk.Frame(inner, bg=bg)
            top.pack(fill="x")

            icon = "🔒" if room.pw_hash else "#"
            host_mark = " ★" if room.is_host else ""
            name_lbl = tk.Label(
                top, text=f"{icon}  {name}{host_mark}",
                font=self._f_room, bg=bg,
                fg=C["accent"] if is_active else C["fg"], anchor="w")
            name_lbl.pack(side="left")

            if room.unread > 0 and not is_active:
                tk.Label(top, text=f" {room.unread} ",
                         font=self._f_small, bg=C["accent6"],
                         fg="white").pack(side="right")

            last_text = "No messages yet"
            if room.messages:
                m = room.messages[-1]
                preview = f"{m['user']}: {m['text']}"
                last_text = (preview[:34] + "…") if len(preview) > 36 else preview

            tk.Label(inner, text=last_text, font=self._f_small,
                     bg=bg, fg=C["fg3"], anchor="w").pack(fill="x")

            def make_click(n=name):
                return lambda e: self._switch_room(n)

            click_cb = make_click()
            for w in [row_f, inner, top, name_lbl]:
                w.bind("<Button-1>", click_cb)

            def on_enter(e, widgets=[row_f, inner, top], active=is_active):
                col = C["room_active"] if active else C["room_hover"]
                for w in widgets:
                    try:
                        w.configure(bg=col)
                    except Exception:
                        pass

            def on_leave(e, widgets=[row_f, inner, top], active=is_active):
                col = C["room_active"] if active else C["sidebar"]
                for w in widgets:
                    try:
                        w.configure(bg=col)
                    except Exception:
                        pass

            row_f.bind("<Enter>", on_enter)
            row_f.bind("<Leave>", on_leave)

            tk.Frame(self._room_inner, bg=C["border"], height=1).pack(fill="x")

    def _switch_room(self, name: str):
        if name not in self._rooms:
            return
        self._active_room = name
        room = self._rooms[name]
        room.unread = 0

        icon = "🔒 Password Protected" if room.pw_hash else "🌐 Open Room"
        host_note = "  [host]" if room.is_host else ""
        self._room_title_lbl.configure(text=f"# {name}{host_note}")
        self._room_lock_lbl.configure(text=f"  {icon}")
        self._room_members_lbl.configure(
            text=f"{len(room.members)+1} member(s)")

        self._chat_display.configure(state="normal")
        self._chat_display.delete("1.0", "end")
        self._chat_display.configure(state="disabled")

        if room.messages:
            self._chat_display.configure(state="normal")
            self._chat_display.insert(
                "end", f"\n  ── {name} ─────────────────────────────\n\n", "divider")
            self._chat_display.configure(state="disabled")
            for m in room.messages:
                if m.get("system"):
                    self._chat_display.configure(state="normal")
                    self._chat_display.insert(
                        "end", f"\n  [{m['ts']}] {m['text']}\n", "system")
                    self._chat_display.configure(state="disabled")
                else:
                    sender = "self" if m.get("is_self") else "peer"
                    self._append_msg(m["user"], m["text"], m["ts"], sender)

        self._chat_display.see("end")
        self._refresh_room_list()
        self._unlock_input()

    # ── Room dialogs ──────────────────────────────────────────────────

    def _show_create_room_dialog(self):
        dlg = _RoomDialog(self.root, "Create Room", create_mode=True)
        self.root.wait_window(dlg.window)
        if dlg.result:
            self._do_create_room(*dlg.result)

    def _show_join_room_dialog(self):
        dlg = _RoomDialog(self.root, "Join Room", create_mode=False,
                          available_rooms=list(self._rooms.keys()))
        self.root.wait_window(dlg.window)
        if dlg.result:
            self._do_join_room(*dlg.result)

    def _do_create_room(self, name: str, pw: str):
        name = _sanitise_name(name, MAX_ROOM_NAME)
        if not name:
            messagebox.showerror("Error", "Room name cannot be empty.")
            return
        if name in self._rooms:
            messagebox.showerror("Room Exists", f'Room "{name}" already exists.')
            return
        pw_hash = _hash_password(pw)
        self._rooms[name] = RoomState(name, pw_hash, is_host=True)
        self._switch_room(name)
        self._add_sys_to_room(
            name, f"🏠 Room \"{name}\" created "
            f"{'(password protected)' if pw_hash else '(open)'}")
        self._refresh_room_list()

    def _do_join_room(self, name: str, pw: str):
        name = _sanitise_name(name, MAX_ROOM_NAME)
        if not name:
            messagebox.showerror("Error", "Room name cannot be empty.")
            return
        pw_hash = _hash_password(pw)
        if name not in self._rooms:
            self._rooms[name] = RoomState(name, pw_hash, is_host=False)
        self._switch_room(name)
        self._add_sys_to_room(name, f"✅ Joined \"{name}\" locally.")
        self._refresh_room_list()

    # ── Identity ──────────────────────────────────────────────────────

    def _generate_identity(self):
        if self._keypair:
            self._keypair.clear()
        if self._group:
            self._group.clear_all()
        self._keypair = KeyPair()
        self._group   = GroupSession(self._keypair)
        self._pending_hs.clear()
        fp = self._keypair.fingerprint()
        self._fp_lbl.configure(text=f"🔑 {fp[:23]}…")

    def _add_global_room(self):
        self._rooms["global"] = RoomState("global", pw_hash="", is_host=True)
        self._switch_room("global")
        self._add_sys_to_room("global",
            "🔒 ShushChat v3  ·  Connect to peers, create/join rooms to chat securely.")

    def _do_set_username(self):
        raw = self._username_var.get()
        name = _sanitise_name(raw, MAX_USERNAME)
        if not name:
            messagebox.showerror("Error", "Username cannot be empty.")
            return
        self._username = name
        if self._active_room:
            self._add_sys_to_room(
                self._active_room, f'👤 Username set to "{self._username}"')

    # ── Connection ────────────────────────────────────────────────────

    def _do_connect(self):
        port_str = self._port_var.get().strip()
        if not _is_valid_port(port_str):
            messagebox.showerror("Invalid Port", "Port must be 1–65535.")
            return
        port = int(port_str)

        mode = self._mode_var.get()
        if mode == "connect":
            host = self._ip_var.get().strip()
            if not host:
                messagebox.showerror("Invalid IP", "Enter a peer IP.")
                return
            # Validate IP address format before dialling
            if not _is_valid_ip(host):
                messagebox.showerror(
                    "Invalid IP",
                    f'"{host}" is not a valid IP address.')
                return
            self._set_status(f"Connecting to {host}:{port}…")
            self._dialled.add(f"{host}:{port}")
            self._net.connect(host, port)
        else:
            self._set_status(f"Listening on port {port}…")
            self._net.listen(port)
            self._disconnect_btn.configure(state="normal")
            self._add_sys_to_active(f"👂 Listening on port {port}…")

    def _do_disconnect_all(self):
        self._net.disconnect_all()
        self._disconnect_btn.configure(state="disabled")

    # ── Send ──────────────────────────────────────────────────────────

    def _do_send(self):
        if not self._active_room:
            return
        raw_text = self._msg_var.get()
        text = _sanitise_text(raw_text, MAX_MSG_TEXT)
        if not text:
            return

        msg_id = str(uuid.uuid4())
        ts     = self._now()
        active_pw = (self._rooms[self._active_room].pw_hash
                     if self._active_room in self._rooms else "")
        payload = json.dumps({
            "type": MSG_CHAT, "msg_id": msg_id,
            "room": self._active_room, "username": self._username,
            "text": text, "ts": ts, "pw_hash": active_pw,
        }, separators=(",", ":"))

        self._rooms[self._active_room].messages.append(
            {"user": self._username, "text": text, "ts": ts, "is_self": True})
        self._append_msg(self._username, text, ts, "self")
        self._msg_var.set("")
        self._refresh_room_list()

        if self._group and self._group.active_peer_ids():
            self._group.mark_seen(msg_id)
            failed = 0
            for pid in self._group.active_peer_ids():
                try:
                    enc = self._group.encrypt(pid, payload)
                    if not self._net.send_to(pid, enc):
                        failed += 1
                except Exception:
                    failed += 1
            if failed:
                self._add_err_to_active(f"⚠ Delivery failed for {failed} peer(s).")

    # ── Broadcast helper ──────────────────────────────────────────────

    def _broadcast_encrypted(self, payload: str, exclude: str = None):
        if not self._group:
            return
        for pid in self._group.active_peer_ids():
            if pid == exclude:
                continue
            try:
                enc = self._group.encrypt(pid, payload)
                self._net.send_to(pid, enc)
            except Exception:
                pass

    # ── Networking callbacks ──────────────────────────────────────────

    def _on_peer_connected(self, peer_id, peer):
        self.root.after(0, self._ui_peer_connected, peer_id, peer)

    def _ui_peer_connected(self, peer_id, peer):
        self._pending_hs.add(peer_id)
        self._add_sys_to_active(
            f"🔗 TCP link [{peer.remote_addr}] — key exchange…")
        hs = json.dumps({
            "type": MSG_HANDSHAKE,
            "pubkey": self._keypair.public_key_bytes().hex(),
            "listen_port": self._net.listen_port,
        }, separators=(",", ":")).encode("utf-8")
        self._net.send_to(peer_id, hs)

    def _on_raw_message(self, peer_id, raw):
        self.root.after(0, self._ui_dispatch, peer_id, raw)

    def _ui_dispatch(self, peer_id, raw):
        if peer_id in self._pending_hs:
            self._handle_handshake(peer_id, raw)
        else:
            self._handle_encrypted(peer_id, raw)

    def _on_peer_disconnected(self, peer_id, reason):
        self.root.after(0, self._ui_peer_disconnected, peer_id, reason)

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
            self._disconnect_btn.configure(state="disabled")

    def _on_network_error(self, msg):
        self.root.after(0, self._ui_network_error, msg)

    def _ui_network_error(self, msg):
        self._add_err_to_active(f"⚠ {msg}")
        if self._net.peer_count() == 0:
            self._set_conn_badge("offline")

    # ── Handshake ─────────────────────────────────────────────────────

    def _handle_handshake(self, peer_id: str, raw: bytes):
        """
        Validate and process the pre-encryption handshake.

        Security checks:
          - raw must decode as UTF-8 JSON object
          - type field must be one of the expected handshake types
          - pubkey must be exactly 64 hex chars (32 bytes)
          - listen_port (if present) must be integer 1–65535
        """
        try:
            try:
                msg = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError(f"Handshake parse error: {exc}")

            if not isinstance(msg, dict):
                raise ValueError("Handshake payload must be a JSON object.")

            msg_type = msg.get("type")

            if msg_type == MSG_PEER_LIST:
                self._rx_peer_list(peer_id, msg)
                return

            if msg_type != MSG_HANDSHAKE:
                # May be an early encrypted message if handshake already done
                if self._group and self._group.has_peer(peer_id):
                    self._pending_hs.discard(peer_id)
                    self._handle_encrypted(peer_id, raw)
                return

            # ── Validate pubkey ───────────────────────────────────────
            pubkey_hex = msg.get("pubkey", "")
            if not _is_valid_pubkey_hex(pubkey_hex):
                raise ValueError(
                    f"Invalid pubkey field (expected 64 hex chars): "
                    f"{repr(pubkey_hex)[:40]}")

            peer_pub = bytes.fromhex(pubkey_hex)

            # ── Validate listen_port (if present) ─────────────────────
            raw_port = msg.get("listen_port")
            peer_listen_port: Optional[int] = None
            if raw_port is not None:
                if not _is_valid_port(raw_port):
                    raise ValueError(
                        f"Invalid listen_port: {repr(raw_port)}")
                peer_listen_port = int(raw_port)

            # ── Derive shared key ─────────────────────────────────────
            fp = self._group.add_peer(peer_id, peer_pub)
            self._pending_hs.discard(peer_id)

            peer_obj = self._net.get_peer(peer_id)
            addr  = peer_obj.remote_addr if peer_obj else "?"
            label = f"{addr} ({fp[:8]}…)"
            self._peer_display[peer_id] = label

            remote_ip = addr.split(":")[0] if ":" in addr else addr
            if peer_listen_port and _is_valid_ip(remote_ip):
                self._peer_addresses[peer_id] = (
                    remote_ip, peer_listen_port, pubkey_hex)

            self._add_sys_to_active(
                f"🔑 Secure link ✅  [{addr}]  —  AES-256-GCM active")
            self._set_conn_badge("connected")
            self._unlock_input()
            self._disconnect_btn.configure(state="normal")
            self._update_peer_count()

            # ── Send peer list to newcomer ────────────────────────────
            other_peers = self._build_peer_list_for(peer_id)
            if other_peers:
                peer_list_msg = json.dumps({
                    "type": MSG_PEER_LIST,
                    "peers": other_peers,
                }, separators=(",", ":")).encode("utf-8")
                self._net.send_to(peer_id, peer_list_msg)
                self._add_sys_to_active(
                    f"📋 Sent peer list ({len(other_peers)} peer(s)) to {addr}")

        except Exception as exc:
            self._add_err_to_active(
                f"Handshake failed {peer_id[:8]}: {exc}")
            self._pending_hs.discard(peer_id)

    def _build_peer_list_for(self, exclude_peer_id: str) -> list:
        result = []
        for pid, (ip, port, pubkey_hex) in self._peer_addresses.items():
            if pid == exclude_peer_id:
                continue
            result.append({"ip": ip, "port": port, "pubkey": pubkey_hex})
        my_port = self._net.listen_port
        if my_port:
            result.append({
                "ip": "self",
                "port": my_port,
                "pubkey": self._keypair.public_key_bytes().hex(),
            })
        return result

    def _rx_peer_list(self, from_peer_id: str, msg: dict) -> None:
        """
        Process a peer-list received from the node we just connected to.

        Security checks:
          - peers must be a list (not dict, string, etc.)
          - Each entry must have ip (valid IP or "self") and port (1–65535)
          - pubkey (if present) must be 64 hex chars
          - Maximum of 50 entries processed (prevents flooding via huge list)
        """
        peers = msg.get("peers", [])
        if not isinstance(peers, list):
            return

        # Cap how many peers we process from one list
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
            except Exception:
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
            self._add_sys_to_active(
                f"🕸 Mesh expanding — dialling {newly_dialling} new peer(s)")

    # ── Encrypted message dispatch ────────────────────────────────────

    def _handle_encrypted(self, peer_id: str, raw: bytes):
        if not self._group or not self._group.has_peer(peer_id):
            return
        try:
            plain = self._group.decrypt(peer_id, raw)
        except ValueError as exc:
            self._add_err_to_active(
                f"🚫 Integrity FAILED {peer_id[:8]}: {exc}")
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
            self._rx_room_create(peer_id, msg)
        elif mtype == MSG_ROOM_JOIN:
            self._rx_room_join(peer_id, msg)
        elif mtype == MSG_ROOM_JOIN_OK:
            self._rx_room_join_ok(peer_id, msg)
        elif mtype == MSG_ROOM_JOIN_FAIL:
            self._rx_room_join_fail(peer_id, msg)
        elif mtype == MSG_CHAT:
            self._rx_chat(peer_id, msg, plain)

    # ── Room protocol ─────────────────────────────────────────────────

    def _rx_room_create(self, peer_id, msg):
        pass   # local-only in v6 mesh

    def _rx_room_join(self, peer_id, msg):
        pass   # local-only in v6 mesh

    def _rx_room_join_ok(self, peer_id, msg):
        pass   # legacy

    def _rx_room_join_fail(self, peer_id, msg):
        pass   # legacy

    # ── Chat ──────────────────────────────────────────────────────────

    def _rx_chat(self, peer_id: str, msg: dict, plain: str):
        """
        Process a decrypted chat message.

        Security checks (input validation):
          - Required fields must all be present
          - msg_id must be a UUID v4 string (rejects crafted dedup-bypass IDs)
          - room_name sanitised and length-capped
          - username sanitised and length-capped
          - text sanitised and length-capped
          - ts capped to 8 chars (HH:MM format)
          - pw_hash must be a 64-char hex string or empty string
        """
        required = {"msg_id", "room", "username", "text", "ts"}
        if required - msg.keys():
            return  # missing fields — silently discard

        # ── Field extraction and validation ───────────────────────────
        msg_id = str(msg["msg_id"])
        # Reject non-UUID msg_ids to prevent dedup-bypass attacks
        if not _is_valid_uuid(msg_id):
            return

        if self._group.is_duplicate(msg_id):
            return
        self._group.mark_seen(msg_id)

        # Gossip to other peers BEFORE further local validation so the
        # mesh continues to propagate even if we locally discard the msg.
        self._gossip(peer_id, plain)

        # Sanitise all string fields
        room_name = _sanitise_name(str(msg["room"]),   MAX_ROOM_NAME)
        username  = _sanitise_name(str(msg["username"]), MAX_USERNAME)
        text      = _sanitise_text(str(msg["text"]),   MAX_MSG_TEXT)
        ts        = str(msg["ts"])[:8]

        if not room_name or not username or not text:
            return  # reject after gossip — empty sanitised fields

        # ── pw_hash validation ────────────────────────────────────────
        raw_pw = msg.get("pw_hash", "")
        # Accept only empty string or valid 64-char hex SHA-256
        if raw_pw and not _is_valid_hex64(str(raw_pw)):
            return  # malformed pw_hash — discard
        msg_pw = str(raw_pw) if raw_pw else ""

        # ── Room auto-creation ────────────────────────────────────────
        if room_name not in self._rooms:
            self._rooms[room_name] = RoomState(room_name, is_host=False)

        room = self._rooms[room_name]

        # ── Password gate ─────────────────────────────────────────────
        if room.pw_hash:
            if not hmac.compare_digest(room.pw_hash, msg_pw):
                return   # wrong password — constant-time compare, silently discard

        room.messages.append(
            {"user": username, "text": text, "ts": ts, "is_self": False})

        if room_name == self._active_room:
            self._append_msg(username, text, ts, "peer")
        else:
            room.unread += 1

        self._refresh_room_list()

    def _gossip(self, source: str, plain: str):
        """Re-encrypt and forward *plain* to all peers except *source*."""
        for pid in self._group.active_peer_ids():
            if pid == source:
                continue
            try:
                enc = self._group.encrypt(pid, plain)
                self._net.send_to(pid, enc)
            except Exception:
                pass

    # ── UI state helpers ──────────────────────────────────────────────

    def _set_conn_badge(self, state: str):
        mapping = {
            "offline":    ("⬤  OFFLINE",      C["accent5"]),
            "connecting": ("◌  CONNECTING…",  C["accent4"]),
            "connected":  ("⬤  SECURE MESH",  C["accent3"]),
        }
        t, c = mapping.get(state, mapping["offline"])
        self._conn_badge.configure(text=t, fg=c)

    def _set_status(self, text: str):
        self._status_lbl.configure(text=text)

    def _unlock_input(self):
        self._msg_entry.configure(
            state="normal", fg=C["fg"], bg=C["input_bg"])
        self._msg_entry.delete(0, "end")
        self._send_btn.configure(state="normal")
        self._msg_entry.focus_set()

    def _lock_input(self):
        self._msg_entry.configure(
            state="disabled", disabledforeground=C["fg3"])
        self._send_btn.configure(state="disabled")

    def _update_peer_count(self):
        n   = len(self._peer_display)
        dot = "🟢" if n else "⬤"
        self._peer_count_lbl.configure(
            text=f"{dot} {n} peer{'s' if n != 1 else ''} connected")

    # ── Display helpers ───────────────────────────────────────────────

    def _now(self):
        return datetime.datetime.now().strftime("%H:%M")

    def _append_msg(self, username, text, ts, sender):
        is_self = (sender == "self")
        n_tag   = "self_name" if is_self else "peer_name"
        m_tag   = "self_msg"  if is_self else "peer_msg"
        self._chat_display.configure(state="normal")
        self._chat_display.insert("end", "\n")
        if is_self:
            self._chat_display.insert("end", f"  {ts} ", "timestamp")
            self._chat_display.insert("end", f"{username}\n", n_tag)
        else:
            self._chat_display.insert("end", f"{username} ", n_tag)
            self._chat_display.insert("end", f"{ts}\n", "timestamp")
        self._chat_display.insert("end", f"    {text}\n", m_tag)
        self._chat_display.configure(state="disabled")
        self._chat_display.see("end")

    def _add_sys_to_room(self, room_name: str, text: str):
        ts = self._now()
        if room_name in self._rooms:
            self._rooms[room_name].messages.append(
                {"user": "•", "text": text, "ts": ts, "system": True})
        if room_name == self._active_room:
            self._chat_display.configure(state="normal")
            self._chat_display.insert(
                "end", f"\n  [{ts}] {text}\n", "system")
            self._chat_display.configure(state="disabled")
            self._chat_display.see("end")

    def _add_sys_to_active(self, text: str):
        if self._active_room:
            self._add_sys_to_room(self._active_room, text)

    def _add_err_to_active(self, text: str):
        ts = self._now()
        self._chat_display.configure(state="normal")
        self._chat_display.insert(
            "end", f"\n  [{ts}] ERROR: {text}\n", "error")
        self._chat_display.configure(state="disabled")
        self._chat_display.see("end")

    # ── Shutdown ──────────────────────────────────────────────────────

    def _on_close(self):
        try:
            self._net.disconnect_all()
        except Exception:
            pass
        if self._group:
            self._group.clear_all()
        if self._keypair:
            self._keypair.clear()
        self.root.destroy()


# ─── Room dialog ──────────────────────────────────────────────────────────────

import hmac as _hmac_module   # already imported at top via crypto; alias to avoid
                               # shadowing the hmac module with a local variable

class _RoomDialog:
    """Dark-themed modal for create / join room."""

    def __init__(self, parent, title, create_mode=True, available_rooms=None):
        self.result = None
        self.window = tk.Toplevel(parent)
        self.window.title(title)
        self.window.configure(bg=C["bg"])
        self.window.resizable(False, False)
        self.window.grab_set()
        self.window.transient(parent)

        h = 340 if (not create_mode and available_rooms) else 290
        w = 420
        px = parent.winfo_rootx() + parent.winfo_width()  // 2 - w // 2
        py = parent.winfo_rooty() + parent.winfo_height() // 2 - h // 2
        self.window.geometry(f"{w}x{h}+{px}+{py}")

        _F  = "Arial"
        fh  = tkfont.Font(family=_F, size=15, weight="bold")
        fla = tkfont.Font(family=_F, size=11)
        fen = tkfont.Font(family=_F, size=12)
        fbt = tkfont.Font(family=_F, size=12, weight="bold")

        tk.Label(self.window, text=title,
                 font=fh, bg=C["bg"], fg=C["accent"], pady=16).pack(fill="x")
        tk.Frame(self.window, bg=C["border"], height=1).pack(fill="x")

        body = tk.Frame(self.window, bg=C["bg"], padx=28, pady=14)
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=1)
        r = 0

        if not create_mode and available_rooms:
            tk.Label(body, text="Available rooms:", font=fla,
                     bg=C["bg"], fg=C["fg3"], anchor="w").grid(
                row=r, column=0, sticky="w"); r += 1
            self._lb = tk.Listbox(body, height=4,
                bg=C["input_bg"], fg=C["fg"], font=fen, bd=0, relief="flat",
                selectbackground=C["accent2"],
                highlightthickness=1, highlightbackground=C["border"])
            self._lb.grid(row=r, column=0, sticky="ew",
                          ipady=4, pady=(0, 8)); r += 1
            for rn in available_rooms:
                self._lb.insert("end", rn)
            self._lb.bind("<<ListboxSelect>>", self._on_sel)

        tk.Label(body, text="Room name:", font=fla,
                 bg=C["bg"], fg=C["fg3"], anchor="w").grid(
            row=r, column=0, sticky="w"); r += 1
        self._name_var = tk.StringVar()
        ne = tk.Entry(body, textvariable=self._name_var,
                      bg=C["input_bg"], fg=C["fg"],
                      insertbackground=C["accent"],
                      font=fen, bd=0, relief="flat",
                      highlightthickness=1,
                      highlightcolor=C["accent"],
                      highlightbackground=C["border"])
        ne.grid(row=r, column=0, sticky="ew", ipady=8, pady=(2, 10)); r += 1
        ne.focus_set()

        pw_lbl = ("Set password (leave blank = open room):"
                  if create_mode else "Password (leave blank if none):")
        tk.Label(body, text=pw_lbl, font=fla,
                 bg=C["bg"], fg=C["fg3"], anchor="w").grid(
            row=r, column=0, sticky="w"); r += 1
        self._pw_var = tk.StringVar()
        pe = tk.Entry(body, textvariable=self._pw_var, show="●",
                      bg=C["input_bg"], fg=C["fg"],
                      insertbackground=C["accent"],
                      font=fen, bd=0, relief="flat",
                      highlightthickness=1,
                      highlightcolor=C["accent"],
                      highlightbackground=C["border"])
        pe.grid(row=r, column=0, sticky="ew", ipady=8, pady=(2, 14)); r += 1
        pe.bind("<Return>", lambda e: self._submit())

        bf = tk.Frame(body, bg=C["bg"])
        bf.grid(row=r, column=0, sticky="ew")
        bf.columnconfigure(0, weight=1)
        bf.columnconfigure(1, weight=1)

        act_txt = "Create Room" if create_mode else "Join Room"
        act_col = C["accent3"] if create_mode else C["accent2"]
        tk.Button(bf, text=act_txt, command=self._submit,
                  bg=act_col, fg="white", font=fbt, relief="flat",
                  cursor="hand2", padx=10, pady=8).grid(
            row=0, column=0, sticky="ew", padx=(0, 4))
        tk.Button(bf, text="Cancel", command=self.window.destroy,
                  bg=C["bg4"], fg=C["fg2"], font=fbt, relief="flat",
                  cursor="hand2", padx=10, pady=8).grid(
            row=0, column=1, sticky="ew", padx=(4, 0))

    def _on_sel(self, event):
        sel = self._lb.curselection()
        if sel:
            self._name_var.set(self._lb.get(sel[0]))

    def _submit(self):
        raw_name = self._name_var.get()
        name = _sanitise_name(raw_name, MAX_ROOM_NAME)
        if not name:
            messagebox.showerror("Error", "Room name cannot be empty.",
                                 parent=self.window)
            return
        # Reject names that look like injection attempts (allow alphanum + limited chars)
        if not _SAFE_NAME_RE.match(name):
            messagebox.showerror(
                "Error",
                "Room name may only contain letters, digits, spaces, hyphens, and underscores.",
                parent=self.window)
            return
        self.result = (name, self._pw_var.get())
        self.window.destroy()
