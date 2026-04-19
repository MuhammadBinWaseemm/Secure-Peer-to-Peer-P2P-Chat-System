"""
main.py — ShushChat Entry Point  (v2 — Multi-Peer Mesh)
========================================================
Usage
-----
    python main.py

Local demo with 3 nodes
-----------------------
Terminal 1 (listener):
    python main.py
    → "Listen for peers", port 5555, click "Connect / Listen"

Terminal 2 (peer A):
    python main.py
    → "Connect to peer", 127.0.0.1:5555, click "Connect / Listen"

Terminal 3 (peer B):
    python main.py
    → "Connect to peer", 127.0.0.1:5555, click "Connect / Listen"

All three nodes can now chat in the "global" room.
Messages from Terminal 2 are forwarded by Terminal 1 to Terminal 3
and vice-versa — fully serverless gossip mesh.
"""

import sys
import tkinter as tk

if sys.version_info < (3, 8):
    print("ShushChat requires Python 3.8 or later.")
    sys.exit(1)

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey  # noqa
except ImportError:
    print(
        "\n[ERROR] The 'cryptography' package is not installed.\n"
        "Install it with:\n\n"
        "    pip install cryptography\n"
    )
    sys.exit(1)

from gui import ShushChatApp


def main():
    root = tk.Tk()
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    ShushChatApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
