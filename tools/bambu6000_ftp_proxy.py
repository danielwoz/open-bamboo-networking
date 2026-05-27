#!/usr/bin/env python3
"""bambu6000_ftp_proxy.py - Plaintext FTP <-> Bambu printer TLS :6000 bridge.

Bambu P2S / N-series file browser uses BambuTunnelLocal on TCP/6000 (LIST_INFO,
FILE_DOWNLOAD, FILE_UPLOAD, FILE_DEL) — not FTPS. The FTPS proxy
(tools/bambu_ftp_proxy.py) cannot reach internal/eMMC storage on P2S.

This script accepts plaintext FTP on --listen-host:--listen-port (default
127.0.0.1:2122) and maps a virtual directory tree to :6000 wire commands.
One plaintext FTP client = one TLS :6000 session.

Virtual layout:
    /
    ├── external/
    │   ├── model/       USB stick — .3mf models
    │   ├── timelapse/
    │   └── video/
    └── internal/
        ├── model/       eMMC model cache
        ├── timelapse/
        └── video/

Credential modes (same as bambu_ftp_proxy.py):
  * access_code on CLI -> every client uses bblp + that code
  * omit access_code -> pass-through USER/PASS from the FTP client

Usage:
    python3 tools/bambu6000_ftp_proxy.py 10.13.1.30 ABCD1234 [-v]
    lftp -u bblp,ABCD1234 ftp://127.0.0.1:2122/
    lftp> cd /internal/model
    lftp> ls
    lftp> get foo.gcode.3mf

Limitations:
  * P2S / N-series first; A1/P1 storage labels may differ
  * No MLSD, REST, resume, MKD, rename
  * One in-flight :6000 RPC per session (serial, like Studio)
  * mem:/N preview paths are not exposed

Requires: Python 3.10+, stdlib only.
"""
from __future__ import annotations

import argparse
import logging
import os
import socket
import sys
import threading
from dataclasses import dataclass
from typing import Callable, Dict, Optional, Tuple

# Allow running as script from repo root or tools/
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bambu6000_client import (  # noqa: E402
    FileEntry,
    LocalCtrlSession,
    Printer6000Error,
    connect_tls,
    format_ls_line,
)

LOG = logging.getLogger("bambu6000_ftp_proxy")

PRINTER_PORT = 6000

DATA_COMMANDS = {"LIST", "NLST", "RETR", "STOR"}
PRELOGIN_COMMANDS = {"USER", "PASS", "QUIT", "FEAT", "OPTS", "SYST", "NOOP"}

VOLUME_EXTERNAL = "external"
VOLUME_INTERNAL = "internal"
FILE_TYPES = ("model", "timelapse", "video")
ROOT_CHILDREN = (VOLUME_EXTERNAL, VOLUME_INTERNAL)


@dataclass(frozen=True)
class VfsLeaf:
    volume: str
    file_type: str


@dataclass
class VfsState:
    path: str = "/"
    listing_cache: dict[str, FileEntry] | None = None


def normalize_vfs_path(path: str) -> str:
    if not path or path == "/":
        return "/"
    parts = [p for p in path.replace("\\", "/").split("/") if p and p != "."]
    out: list[str] = []
    for p in parts:
        if p == "..":
            if out:
                out.pop()
            continue
        out.append(p)
    return "/" + "/".join(out) if out else "/"


def parse_vfs_path(path: str) -> Tuple[str, Optional[VfsLeaf]]:
    """Return ('root'|'volume'|'leaf', leaf or None)."""
    norm = normalize_vfs_path(path)
    if norm == "/":
        return "root", None
    parts = norm.strip("/").split("/")
    if len(parts) == 1 and parts[0] in ROOT_CHILDREN:
        return "volume", None
    if len(parts) == 2 and parts[0] in ROOT_CHILDREN and parts[1] in FILE_TYPES:
        return "leaf", VfsLeaf(volume=parts[0], file_type=parts[1])
    return "invalid", None


def list_storages_for_leaf(leaf: VfsLeaf) -> list[str]:
    if leaf.volume == VOLUME_EXTERNAL:
        return ["udisk", ""]
    if leaf.file_type == "model":
        return ["internal", "emmc"]
    return ["internal"]


def delete_storage_for_leaf(leaf: VfsLeaf) -> str:
    return upload_storage_for_leaf(leaf)


def model_history_path(path: str) -> bool:
    return path.startswith("/userdata/model/")


def upload_storage_for_leaf(leaf: VfsLeaf) -> str:
    if leaf.volume == VOLUME_EXTERNAL:
        return "udisk"
    if leaf.file_type == "model":
        return "emmc"
    return "internal"


def virtual_directory_entries(kind: str, path: str) -> list[FileEntry]:
    norm = normalize_vfs_path(path)
    if kind == "root":
        return [
            FileEntry(name=name, path=f"/{name}/", size=4096)
            for name in ROOT_CHILDREN
        ]
    if kind == "volume":
        vol = norm.strip("/")
        return [
            FileEntry(name=ft, path=f"/{vol}/{ft}/", size=4096)
            for ft in FILE_TYPES
        ]
    return []


class Printer6000Client:
    """One TLS :6000 session per FTP client."""

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        *,
        serial: Optional[str] = None,
        verify_tls: bool = False,
        ca_file: Optional[str] = None,
        connect_timeout: float = 15.0,
    ) -> None:
        self.host = host
        self.username = username
        self.password = password
        self.serial = serial
        self.verify_tls = verify_tls
        self.ca_file = ca_file
        self.connect_timeout = connect_timeout
        self._session: Optional[LocalCtrlSession] = None
        self._lock = threading.Lock()

    def connect(self) -> None:
        if self._session is not None:
            return
        ssl_sock = connect_tls(
            self.host,
            PRINTER_PORT,
            serial=self.serial,
            verify_tls=self.verify_tls,
            ca_file=self.ca_file,
            timeout=self.connect_timeout,
        )
        session = LocalCtrlSession(ssl_sock, quiet=True)
        session.handshake(self.username, self.password)
        session.start()
        self._session = session
        LOG.info("logged in to %s:%d as %s", self.host, PRINTER_PORT, self.username)

    def close(self) -> None:
        if self._session is not None:
            self._session.close()
            self._session = None

    def _require(self) -> LocalCtrlSession:
        if self._session is None:
            raise Printer6000Error("not connected")
        return self._session

    def list_leaf(self, leaf: VfsLeaf) -> list[FileEntry]:
        with self._lock:
            session = self._require()
            return session.list_info_with_fallbacks(
                leaf.file_type, list_storages_for_leaf(leaf)
            )

    def download(self, entry: FileEntry) -> bytes:
        with self._lock:
            return self._require().download_entry(entry)

    def upload(self, data: bytes, leaf: VfsLeaf, remote_name: str) -> None:
        with self._lock:
            self._require().upload_bytes(
                data, upload_storage_for_leaf(leaf), remote_name
            )

    def delete_entry(self, entry: FileEntry, leaf: VfsLeaf) -> None:
        with self._lock:
            storage = "" if entry.path.startswith("/") else delete_storage_for_leaf(leaf)
            self._require().delete_entry(entry, storage)


class ProxySession:
    """One FTP client thread."""

    HANDLERS: Dict[str, Callable[["ProxySession", str], bool]] = {}

    def __init__(
        self,
        client_sock: socket.socket,
        peer_addr: Tuple[str, int],
        printer_host: str,
        cli_username: str,
        cli_password: Optional[str],
        listen_host: str,
        serial: Optional[str],
        verify_tls: bool,
        ca_file: Optional[str],
        connect_timeout: float,
        data_timeout: float,
    ) -> None:
        self.client = client_sock
        self.peer_addr = peer_addr
        self.printer_host = printer_host
        self.cli_username = cli_username
        self.cli_password = cli_password
        self.listen_host = listen_host
        self.serial = serial
        self.verify_tls = verify_tls
        self.ca_file = ca_file
        self.connect_timeout = connect_timeout
        self.data_timeout = data_timeout

        self.client.settimeout(300.0)
        self._buf = b""
        self.printer: Optional[Printer6000Client] = None
        self._pasv_listener: Optional[socket.socket] = None
        self._authed = False
        self._pending_user: Optional[str] = None
        self.vfs = VfsState()

    def reply(self, code: int, body: str = "") -> None:
        if not body:
            wire = f"{code}\r\n".encode("utf-8")
        else:
            lines = body.split("\n")
            if len(lines) == 1:
                wire = f"{code} {lines[0]}\r\n".encode("utf-8", errors="replace")
            else:
                pieces = []
                for i, ln in enumerate(lines):
                    if i == 0:
                        pieces.append(f"{code}-{ln}")
                    elif i == len(lines) - 1:
                        pieces.append(f"{code} {ln}")
                    else:
                        pieces.append(f" {ln}")
                wire = ("\r\n".join(pieces) + "\r\n").encode("utf-8", errors="replace")
        self.client.sendall(wire)
        LOG.debug(
            "[%s] -> %s", self.peer_addr, wire.rstrip(b"\r\n").decode(errors="replace")
        )

    def _read_command(self) -> Optional[str]:
        while b"\n" not in self._buf:
            try:
                chunk = self.client.recv(4096)
            except (OSError, socket.timeout) as exc:
                LOG.debug("[%s] client recv: %s", self.peer_addr, exc)
                return None
            if not chunk:
                return None
            self._buf += chunk
            if len(self._buf) > 8192:
                return None
        nl = self._buf.index(b"\n")
        line = self._buf[:nl]
        self._buf = self._buf[nl + 1:]
        if line.endswith(b"\r"):
            line = line[:-1]
        return line.decode("utf-8", errors="replace")

    def run(self) -> None:
        try:
            self._run()
        except Exception:
            LOG.exception("[%s] session crashed", self.peer_addr)
        finally:
            self._cleanup()

    def _connect_printer(self, username: str, password: str) -> None:
        if self.printer is not None:
            return
        client = Printer6000Client(
            self.printer_host,
            username,
            password,
            serial=self.serial,
            verify_tls=self.verify_tls,
            ca_file=self.ca_file,
            connect_timeout=self.connect_timeout,
        )
        client.connect()
        self.printer = client

    def _run(self) -> None:
        try:
            self.reply(
                220,
                f"bambu6000-ftp-proxy ready (printer {self.printer_host}:{PRINTER_PORT})",
            )
        except OSError:
            return

        while True:
            line = self._read_command()
            if line is None:
                return
            if not line.strip():
                continue
            parts = line.strip().split(" ", 1)
            cmd = parts[0].upper()
            arg = parts[1] if len(parts) > 1 else ""

            redact = cmd == "PASS"
            LOG.debug(
                "[%s] <- %s %s",
                self.peer_addr,
                cmd,
                "<redacted>" if redact else arg,
            )

            if not self._authed and cmd not in PRELOGIN_COMMANDS:
                self.reply(530, "Please log in with USER and PASS first")
                continue

            handler = self.HANDLERS.get(cmd)
            if handler is None:
                self.reply(502, f"Command not implemented: {cmd}")
                continue

            try:
                cont = handler(self, arg)
            except Printer6000Error as exc:
                LOG.warning("[%s] printer error: %s", self.peer_addr, exc)
                self.reply(421, f"Printer session lost: {exc}")
                return
            except OSError as exc:
                LOG.warning("[%s] socket error: %s", self.peer_addr, exc)
                return

            if not cont:
                return

    def _resolve_cwd_target(self, arg: str) -> str:
        if not arg:
            return self.vfs.path
        if arg.startswith("/"):
            return normalize_vfs_path(arg)
        base = self.vfs.path.rstrip("/")
        return normalize_vfs_path(f"{base}/{arg}")

    def _refresh_listing(self) -> list[FileEntry]:
        kind, leaf = parse_vfs_path(self.vfs.path)
        if kind == "invalid":
            raise Printer6000Error(f"not a directory: {self.vfs.path}")
        if kind in ("root", "volume"):
            entries = virtual_directory_entries(kind, self.vfs.path)
        else:
            assert leaf is not None
            if self.printer is None:
                raise Printer6000Error("not connected")
            entries = self.printer.list_leaf(leaf)
        self.vfs.listing_cache = {e.name: e for e in entries}
        return entries

    def _lookup_entry(self, name: str) -> Optional[FileEntry]:
        name = name.strip().rstrip("/")
        if self.vfs.listing_cache is None:
            self._refresh_listing()
        assert self.vfs.listing_cache is not None
        if name in self.vfs.listing_cache:
            return self.vfs.listing_cache[name]
        for entry in self.vfs.listing_cache.values():
            if entry.path.endswith("/" + name) or entry.path == name:
                return entry
        return None

    def _cmd_user(self, arg: str) -> bool:
        self._pending_user = arg if arg else None
        if self.cli_password is not None:
            self.reply(331, "Any password welcome (proxy uses preset creds)")
        else:
            self.reply(331, "Send the printer access code as PASS")
        return True

    def _cmd_pass(self, arg: str) -> bool:
        if self.cli_password is not None:
            user = self.cli_username
            pw = self.cli_password
        else:
            user = self._pending_user or self.cli_username
            pw = arg
            if not pw:
                self.reply(530, "Password required (printer access code)")
                return True
        try:
            self._connect_printer(user, pw)
        except Printer6000Error as exc:
            self.reply(530, f"Printer login failed: {exc}")
            return True
        self._authed = True
        self.reply(230, "Logged in via proxy")
        return True

    def _cmd_acct(self, arg: str) -> bool:
        self.reply(202, "ACCT not needed")
        return True

    def _cmd_syst(self, arg: str) -> bool:
        self.reply(215, "UNIX Type: L8")
        return True

    def _cmd_feat(self, arg: str) -> bool:
        self.reply(211, "Features:\n PASV\n EPSV\n UTF8\n SIZE\n TYPE\nEnd")
        return True

    def _cmd_opts(self, arg: str) -> bool:
        if arg.strip().upper().startswith("UTF8"):
            self.reply(200, "UTF8 OK")
        else:
            self.reply(501, "Unknown option")
        return True

    def _cmd_type(self, arg: str) -> bool:
        a = arg.strip().upper()
        if a in ("I", "L 8", "A", "A N"):
            self.reply(200, f"Type set to {a}")
        else:
            self.reply(504, f"Type not supported: {a}")
        return True

    def _cmd_pwd(self, arg: str) -> bool:
        self.reply(257, f'"{self.vfs.path}" is current directory')
        return True

    def _cmd_cwd(self, arg: str) -> bool:
        target = self._resolve_cwd_target(arg)
        kind, _leaf = parse_vfs_path(target)
        if kind == "invalid":
            self.reply(550, f"No such directory: {target}")
            return True
        self.vfs.path = target
        self.vfs.listing_cache = None
        self.reply(250, f"CWD {target}")
        return True

    def _cmd_cdup(self, arg: str) -> bool:
        return self._cmd_cwd("..")

    def _cmd_noop(self, arg: str) -> bool:
        self.reply(200, "OK")
        return True

    def _cmd_size(self, arg: str) -> bool:
        if not arg:
            self.reply(501, "Missing path")
            return True
        entry = self._lookup_entry(arg.strip())
        if entry is None:
            self.reply(550, "File not found")
            return True
        self.reply(213, str(entry.size))
        return True

    def _cmd_dele(self, arg: str) -> bool:
        if not arg:
            self.reply(501, "Missing path")
            return True
        kind, leaf = parse_vfs_path(self.vfs.path)
        if kind != "leaf" or leaf is None:
            self.reply(550, "DELE only in a file directory (e.g. /external/model)")
            return True
        entry = self._lookup_entry(arg.strip())
        if entry is None:
            self.reply(550, "File not found")
            return True
        if kind == "leaf" and leaf and leaf.file_type == "model" and model_history_path(entry.path):
            self.reply(
                550,
                "P2S internal model cache: download/delete via :6000 not supported "
                f"for {entry.path!r}; use Bambu Studio or printer screen "
                "(Print Files > Internal)",
            )
            return True
        assert self.printer is not None
        try:
            self.printer.delete_entry(entry, leaf)
        except Printer6000Error as exc:
            self.reply(550, str(exc))
            return True
        self.vfs.listing_cache = None
        self.reply(250, "DELE OK")
        return True

    def _cmd_quit(self, arg: str) -> bool:
        try:
            self.reply(221, "Goodbye")
        except OSError:
            pass
        return False

    def _open_pasv_listener(self) -> socket.socket:
        bind_host = self.listen_host or "0.0.0.0"
        family = socket.AF_INET6 if ":" in bind_host else socket.AF_INET
        listener = socket.socket(family, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((bind_host, 0))
        listener.listen(1)
        return listener

    def _advertised_local_ip(self) -> Optional[str]:
        if self.listen_host and self.listen_host not in ("0.0.0.0", "::", ""):
            ip = self.listen_host
        else:
            try:
                ip = self.client.getsockname()[0]
            except OSError:
                ip = "127.0.0.1"
        if ":" in ip or ip.count(".") != 3:
            return None
        return ip

    def _close_pasv_listener(self) -> None:
        if self._pasv_listener is not None:
            try:
                self._pasv_listener.close()
            except OSError:
                pass
            self._pasv_listener = None

    def _cmd_pasv(self, arg: str) -> bool:
        self._close_pasv_listener()
        try:
            listener = self._open_pasv_listener()
        except OSError as exc:
            self.reply(425, f"Can't open passive: {exc}")
            return True
        port = listener.getsockname()[1]
        local_ip = self._advertised_local_ip()
        if local_ip is None:
            listener.close()
            self.reply(425, "PASV needs an IPv4 listen address; use EPSV")
            return True
        h = local_ip.split(".")
        p1, p2 = port // 256, port % 256
        self._pasv_listener = listener
        self.reply(227, f"Entering Passive Mode ({h[0]},{h[1]},{h[2]},{h[3]},{p1},{p2}).")
        return True

    def _cmd_epsv(self, arg: str) -> bool:
        a = arg.strip().upper()
        if a == "ALL":
            self.reply(200, "Only EPSV from now on")
            return True
        self._close_pasv_listener()
        try:
            listener = self._open_pasv_listener()
        except OSError as exc:
            self.reply(425, f"Can't open passive: {exc}")
            return True
        port = listener.getsockname()[1]
        self._pasv_listener = listener
        self.reply(229, f"Entering Extended Passive Mode (|||{port}|).")
        return True

    def _data_cmd(self, cmd: str, arg: str) -> bool:
        if self._pasv_listener is None:
            self.reply(425, "Use PASV/EPSV first")
            return True
        listener = self._pasv_listener
        self._pasv_listener = None
        try:
            return self._do_data_transfer(cmd, arg, listener)
        finally:
            try:
                listener.close()
            except OSError:
                pass

    def _do_data_transfer(self, cmd: str, arg: str, listener: socket.socket) -> bool:
        if self.printer is None:
            self.reply(503, "Login first")
            return True

        self.reply(150, "Opening data connection")
        listener.settimeout(60.0)
        try:
            client_data, _ = listener.accept()
        except (socket.timeout, OSError) as exc:
            self.reply(425, f"Client data accept failed: {exc}")
            return True
        client_data.settimeout(self.data_timeout)

        try:
            if cmd in ("LIST", "NLST"):
                payload = self._build_listing_payload(cmd == "NLST")
            elif cmd == "RETR":
                payload = self._build_retr_payload(arg)
            elif cmd == "STOR":
                payload = self._handle_stor(client_data, arg)
                client_data.close()
                self.reply(226, "Transfer complete")
                return True
            else:
                payload = b""
        except Printer6000Error as exc:
            try:
                client_data.close()
            except OSError:
                pass
            self.reply(550, str(exc))
            return True
        except OSError:
            try:
                client_data.close()
            except OSError:
                pass
            raise

        try:
            if payload:
                client_data.sendall(payload)
        except OSError:
            pass
        try:
            client_data.close()
        except OSError:
            pass
        self.reply(226, "Transfer complete")
        return True

    def _build_listing_payload(self, names_only: bool) -> bytes:
        entries = self._refresh_listing()
        kind, _ = parse_vfs_path(self.vfs.path)
        lines: list[str] = []
        for entry in entries:
            is_dir = entry.name.endswith("/") or kind in ("root", "volume")
            if names_only:
                name = entry.name.rstrip("/")
                if name:
                    lines.append(name)
            else:
                lines.append(format_ls_line(entry, directory=is_dir))
        text = "\r\n".join(lines)
        if lines:
            text += "\r\n"
        return text.encode("utf-8", errors="replace")

    def _build_retr_payload(self, arg: str) -> bytes:
        name = arg.strip()
        if not name:
            raise Printer6000Error("RETR requires a filename")
        entry = self._lookup_entry(name)
        if entry is None:
            raise Printer6000Error(f"file not found: {name}")
        kind, leaf = parse_vfs_path(self.vfs.path)
        if (
            kind == "leaf"
            and leaf is not None
            and leaf.file_type == "model"
            and model_history_path(entry.path)
        ):
            raise Printer6000Error(
                "P2S internal model cache cannot be downloaded via :6000 "
                f"({entry.path}); use Bambu Studio or printer screen"
            )
        assert self.printer is not None
        return self.printer.download(entry)

    def _handle_stor(self, client_data: socket.socket, arg: str) -> bytes:
        name = arg.strip()
        if not name:
            raise Printer6000Error("STOR requires a filename")
        kind, leaf = parse_vfs_path(self.vfs.path)
        if kind != "leaf" or leaf is None:
            raise Printer6000Error("STOR only in a file directory (e.g. /external/model)")
        chunks: list[bytes] = []
        while True:
            try:
                block = client_data.recv(64 * 1024)
            except OSError:
                break
            if not block:
                break
            chunks.append(block)
        data = b"".join(chunks)
        assert self.printer is not None
        self.printer.upload(data, leaf, name)
        self.vfs.listing_cache = None
        return b""

    def _cleanup(self) -> None:
        self._close_pasv_listener()
        if self.printer is not None:
            try:
                self.printer.close()
            except Exception:
                pass
            self.printer = None
        try:
            self.client.close()
        except OSError:
            pass


ProxySession.HANDLERS.update(
    {
        "USER": ProxySession._cmd_user,
        "PASS": ProxySession._cmd_pass,
        "ACCT": ProxySession._cmd_acct,
        "SYST": ProxySession._cmd_syst,
        "FEAT": ProxySession._cmd_feat,
        "OPTS": ProxySession._cmd_opts,
        "TYPE": ProxySession._cmd_type,
        "PWD": ProxySession._cmd_pwd,
        "XPWD": ProxySession._cmd_pwd,
        "CWD": ProxySession._cmd_cwd,
        "XCWD": ProxySession._cmd_cwd,
        "CDUP": ProxySession._cmd_cdup,
        "XCUP": ProxySession._cmd_cdup,
        "NOOP": ProxySession._cmd_noop,
        "SIZE": ProxySession._cmd_size,
        "DELE": ProxySession._cmd_dele,
        "QUIT": ProxySession._cmd_quit,
        "PASV": ProxySession._cmd_pasv,
        "EPSV": ProxySession._cmd_epsv,
        "LIST": lambda self, arg: self._data_cmd("LIST", arg),
        "NLST": lambda self, arg: self._data_cmd("NLST", arg),
        "RETR": lambda self, arg: self._data_cmd("RETR", arg),
        "STOR": lambda self, arg: self._data_cmd("STOR", arg),
    }
)


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="bambu6000_ftp_proxy",
        description=(
            "Plaintext FTP server that proxies to a Bambu printer's "
            "TLS :6000 file browser (BambuTunnelLocal)."
        ),
    )
    p.add_argument("printer_ip", help="Printer LAN IP (e.g. 10.13.1.30)")
    p.add_argument(
        "access_code",
        nargs="?",
        default=None,
        help="Printer access code; omit for pass-through PASS from FTP client",
    )
    p.add_argument("--listen-host", default="127.0.0.1")
    p.add_argument("--listen-port", type=int, default=2122)
    p.add_argument("--username", default="bblp")
    p.add_argument("--serial", help="Printer serial for TLS SNI / verify")
    p.add_argument("--verify", action="store_true", help="Verify printer TLS")
    p.add_argument("--ca-file", help="CA bundle PEM for --verify")
    p.add_argument("--connect-timeout", type=float, default=15.0)
    p.add_argument("--data-timeout", type=float, default=300.0)
    p.add_argument("-v", "--verbose", action="count", default=0)
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    level = logging.WARNING
    if args.verbose >= 2:
        level = logging.DEBUG
    elif args.verbose == 1:
        level = logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )

    family = socket.AF_INET6 if ":" in args.listen_host else socket.AF_INET
    server = socket.socket(family, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((args.listen_host, args.listen_port))
    except OSError as exc:
        print(f"bind {args.listen_host}:{args.listen_port}: {exc}", file=sys.stderr)
        return 1
    server.listen(8)

    mode = "preset access code" if args.access_code else "pass-through PASS"
    print(
        f"Listening on ftp://{args.listen_host}:{args.listen_port}/ "
        f"-> printer {args.printer_ip}:{PRINTER_PORT} ({mode})",
        file=sys.stderr,
    )

    try:
        while True:
            try:
                client_sock, peer = server.accept()
            except KeyboardInterrupt:
                break
            except OSError as exc:
                LOG.warning("accept failed: %s", exc)
                continue
            LOG.info("client connected: %s", peer)
            sess = ProxySession(
                client_sock=client_sock,
                peer_addr=peer,
                printer_host=args.printer_ip,
                cli_username=args.username,
                cli_password=args.access_code,
                listen_host=args.listen_host,
                serial=args.serial,
                verify_tls=args.verify,
                ca_file=args.ca_file,
                connect_timeout=args.connect_timeout,
                data_timeout=args.data_timeout,
            )
            threading.Thread(target=sess.run, daemon=True).start()
    finally:
        server.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
