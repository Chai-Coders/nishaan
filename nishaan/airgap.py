"""Air-gap guard: refuse every outbound connection that leaves the local machine / closed LAN.

Enabled by default for the CLI, the console and the demo (disable with NISHAAN_AIRGAP=0).
It wraps socket.connect, so any accidental dependency on an online service - a cloud KMS,
a public blockchain RPC, a time server, a CRL/OCSP URL, a font CDN - fails loudly instead
of silently reaching the internet.
"""
from __future__ import annotations

import ipaddress
import os
import socket

_installed = False
blocked: list[str] = []


def _allowed(host) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host in ("localhost",)
    return ip.is_loopback or ip.is_private or ip.is_link_local


def enforce() -> bool:
    global _installed
    if _installed or os.environ.get("NISHAAN_AIRGAP", "1") == "0":
        return _installed
    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex

    def check(addr):
        if isinstance(addr, tuple) and addr and isinstance(addr[0], str) and not _allowed(addr[0]):
            blocked.append(str(addr[0]))
            raise ConnectionRefusedError(f"air-gap guard: outbound connection to {addr[0]} blocked")

    def connect(self, addr):
        check(addr)
        return real_connect(self, addr)

    def connect_ex(self, addr):
        check(addr)
        return real_connect_ex(self, addr)

    socket.socket.connect = connect
    socket.socket.connect_ex = connect_ex
    _installed = True
    return True
