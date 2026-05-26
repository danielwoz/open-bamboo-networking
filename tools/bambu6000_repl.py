#!/usr/bin/env python3
"""Interactive TLS :6000 REPL for reverse-engineering Bambu printer file browser.

Stock libBambuSource (BambuTunnelLocal, P2S Device -> Files) uses:

  TCP/TLS :6000
    -> subchannel 0x01: 16-byte hdr + 16-byte login (user[8] + access_code[8])
    -> subchannel 0x02: StartStreamEx JSON (mtype 12291) + framed CTRL JSON (mtype 12289)

This is **not** the 80-byte 0x3000 auth from OpenBambuAPI/video.md (MJPEG camera on A1/P1).

Usage:
    python3 tools/bambu6000_repl.py 10.13.1.30 ABCD1234

Example LIST (External timelapse) — type one JSON line; framing is added automatically:
    {"cmdtype":1,"sequence":1,"req":{"type":"timelapse","api_version":2,"notify":"DETAIL"}}

REPL commands:
    /quit, /exit          — close session
    /ability              — REQUEST_MEDIA_ABILITY (cmdtype 7)
    /upload <local> <storage> <remote_name> — FILE_UPLOAD (cmdtype 5)
    /download <mem_path> <out_file>       — FILE_DOWNLOAD mem preview (cmdtype 4, e.g. mem:/26)
    /hex 404142...        — send raw bytes (even length hex string)
    /file path.bin        — send file contents
    /raw on|off           — send typed lines as raw bytes (no framing)
    /nl on|off            — append \\n to each typed line (default off)

Command history: Up/Down arrows (readline); persisted in ~/.bambu6000_repl_history

Requires: Python 3.10+, stdlib only.
"""
from __future__ import annotations

import argparse
import atexit
import json
import os
import sys

from bambu6000_client import (
    MAGIC_CTRL,
    MAGIC_LOGIN,
    MTYPE_CTRL_JSON,
    MTYPE_CTRL_SETUP,
    LocalCtrlSession,
    build_ctrl_setup_json,
    build_frame_header,
    build_login_payload,
    build_mjpeg_auth_packet,
    connect_tls,
    consume_frames,
    format_recv,
    parse_frames,
    split_text_and_binary,
    wrap_ctrl_json,
)

DEFAULT_HISTORY_FILE = os.path.expanduser("~/.bambu6000_repl_history")


def setup_readline(*, history_file: str | None = None, enabled: bool = True) -> None:
    if not enabled or not sys.stdin.isatty():
        return
    try:
        import readline
    except ImportError:
        return

    path = history_file or DEFAULT_HISTORY_FILE
    try:
        readline.read_history_file(path)
    except OSError:
        pass
    readline.set_history_length(1000)

    def _save_history() -> None:
        try:
            readline.write_history_file(path)
        except OSError:
            pass

    atexit.register(_save_history)


def run_interactive(repl: LocalCtrlSession) -> None:
    mode = "raw" if repl._send_raw else "framed JSON (mtype 12289)"
    print(f"Connected. Mode: {mode}.  /raw /hex /quit", flush=True)
    while not repl._stop.is_set():
        try:
            line = input(">> ")
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        cmd = line.strip()
        low = cmd.lower()
        if low in ("/quit", "/exit", "/q"):
            break
        if low.startswith("/raw "):
            arg = low.split(maxsplit=1)[-1]
            repl._send_raw = arg in ("on", "1", "true", "yes")
            print(f"raw mode: {repl._send_raw}", flush=True)
            continue
        if low.startswith("/nl "):
            arg = low.split(maxsplit=1)[-1]
            repl._append_nl = arg in ("on", "1", "true", "yes")
            print(f"append newline: {repl._append_nl}", flush=True)
            continue
        if low.startswith("/upload "):
            parts = cmd.split(maxsplit=3)
            if len(parts) < 4:
                print("usage: /upload <local_path> <storage> <remote_name>", flush=True)
                continue
            try:
                repl.send_upload(parts[1], parts[2], parts[3])
            except OSError as exc:
                print(f"upload failed: {exc}", flush=True)
            continue
        if low == "/ability":
            repl.send_ability()
            continue
        if low.startswith("/download "):
            parts = cmd.split(maxsplit=2)
            if len(parts) < 3:
                print("usage: /download <mem_path> <out_file>", flush=True)
                print("example: /download mem:/26 /tmp/preview.jpg", flush=True)
                continue
            try:
                repl.send_download_mem(parts[1], parts[2])
            except OSError as exc:
                print(f"download failed: {exc}", flush=True)
                print("hint: reconnect REPL after SSL errors (/quit, restart)", flush=True)
            continue
        if low.startswith("/hex "):
            hex_str = "".join(cmd.split(maxsplit=1)[1].split())
            try:
                payload = bytes.fromhex(hex_str)
            except ValueError as exc:
                print(f"bad hex: {exc}", flush=True)
                continue
            repl.send_bytes(payload)
            continue
        if low.startswith("/file "):
            path = cmd.split(maxsplit=1)[1]
            try:
                with open(path, "rb") as fh:
                    payload = fh.read()
            except OSError as exc:
                print(f"read failed: {exc}", flush=True)
                continue
            repl.send_bytes(payload)
            continue
        if repl._send_raw:
            payload = line.encode("utf-8")
            if repl._append_nl:
                payload += b"\n"
            repl.send_bytes(payload)
            continue
        if not cmd.startswith("{"):
            print("expected JSON line, /hex, or /raw on", flush=True)
            continue
        try:
            obj = json.loads(cmd)
        except json.JSONDecodeError as exc:
            print(f"bad json: {exc}", flush=True)
            continue
        if not isinstance(obj, dict):
            print("expected JSON object", flush=True)
            continue
        repl.send_ctrl_json(obj)


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Interactive TLS :6000 REPL (BambuTunnelLocal file browser)",
    )
    p.add_argument("host", help="printer LAN IP")
    p.add_argument("access_code", help="8-char printer access code")
    p.add_argument("--port", type=int, default=6000, help="TCP port (default 6000)")
    p.add_argument("--user", default="bblp", help="login username (default bblp)")
    p.add_argument("--serial", help="printer serial for TLS SNI / verify")
    p.add_argument("--verify", action="store_true", help="verify printer TLS")
    p.add_argument("--ca-file", help="BBL CA bundle PEM for --verify")
    p.add_argument(
        "--mjpeg-auth",
        action="store_true",
        help="send legacy 80-byte 0x3000 auth (MJPEG camera) instead of Local login",
    )
    p.add_argument(
        "--no-handshake",
        action="store_true",
        help="skip login + mtype-12291 setup (for /hex experiments)",
    )
    p.add_argument("--init-hex", help="hex bytes to send after handshake")
    p.add_argument("--init-file", help="file to send after handshake")
    p.add_argument("--append-nl", action="store_true", help="append newline in /raw mode")
    p.add_argument("--raw", action="store_true", help="start in raw byte mode (no JSON framing)")
    p.add_argument("--recv-hex-limit", type=int, default=512)
    p.add_argument("--no-history", action="store_true", help="disable readline history")
    p.add_argument(
        "--history-file",
        default=DEFAULT_HISTORY_FILE,
        help=f"readline history file (default {DEFAULT_HISTORY_FILE})",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        ssl_sock = connect_tls(
            args.host,
            args.port,
            serial=args.serial,
            verify_tls=args.verify,
            ca_file=args.ca_file,
        )
    except OSError as exc:
        print(f"connect failed: {exc}", file=sys.stderr)
        return 1

    print(f"TLS ok, cipher={ssl_sock.cipher()[0]}", flush=True)

    if args.mjpeg_auth:
        auth = build_mjpeg_auth_packet(args.user, args.access_code)
        ssl_sock.sendall(auth)
        print("sent 80-byte MJPEG auth (0x3000) — not the file-browser path", flush=True)
        repl = LocalCtrlSession(
            ssl_sock,
            send_raw=True,
            append_nl=args.append_nl,
            recv_hex_limit=args.recv_hex_limit,
        )
    else:
        repl = LocalCtrlSession(
            ssl_sock,
            send_raw=args.raw,
            append_nl=args.append_nl,
            recv_hex_limit=args.recv_hex_limit,
        )
        if not args.no_handshake:
            repl.handshake(args.user, args.access_code)

    repl.start()

    if args.init_hex:
        try:
            repl.send_bytes(bytes.fromhex("".join(args.init_hex.split())))
        except ValueError as exc:
            print(f"bad --init-hex: {exc}", file=sys.stderr)
            repl.close()
            return 1
    if args.init_file:
        try:
            with open(args.init_file, "rb") as fh:
                repl.send_bytes(fh.read())
        except OSError as exc:
            print(f"--init-file: {exc}", file=sys.stderr)
            repl.close()
            return 1

    try:
        setup_readline(
            history_file=args.history_file,
            enabled=not args.no_history,
        )
        run_interactive(repl)
    finally:
        repl.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
