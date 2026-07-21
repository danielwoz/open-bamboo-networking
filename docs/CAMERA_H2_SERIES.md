# H2-series (O1S) liveview: why the LAN fallback cannot work

Measured 2026-07-22 against a Bambu H2S (`O1S`, firmware `01.02.00.00`) and an
A1 (`N2S`, firmware `01.07.02.00`) on the same LAN, with OrcaSlicer 2.5.0-dev
driving `bambu_networking` 02.07.01.99 and our own `BambuSource.dll`.

## Summary

`bambu_network_get_camera_url` falls back to the printer's LAN URL
(`bambu:///local/<ip>?port=6000&...`) whenever no stream source claims the
device. On the A1 that URL streams MJPEG correctly. On the H2S the printer
**rejects the MJPEG video auth**, so the URL can never produce a frame — and
because `Bambu_GetStreamInfo` reports a hardcoded `1280x720@15` before any data
arrives, the slicer shows a confident `Playing...` over a black pane.

## Evidence

`tools/bs_probe` dials the tunnel outside DirectShow/GStreamer:

    bs_probe "bambu:///local/192.168.1.116?port=6000&user=bblp&passwd=<code>" BambuSource.dll
    A1  -> Bambu_Open 0, StartStream 0, RESULT: frames=8 bytes=1050883 errors=0

    bs_probe "bambu:///local/192.168.1.209?port=6000&user=bblp&passwd=<code>" BambuSource.dll
    H2S -> Bambu_Open 0, StartStream 0, "JPEG magic mismatch size=8", then EOF
           RESULT: frames=0

Raw exchange after the 80-byte auth packet (`payload=0x40`, `type=0x3000`,
user/passwd in the 32-byte fields, per OpenBambuAPI `video.md`):

| | reply header | payload |
| --- | --- | --- |
| A1  | `payload_size=130293 type=0x0` | `ff d8 ff e0 00 21 "AVI1"` — JPEG SOI + APP0 |
| H2S | `payload_size=8 type=0x0003013f` | `ff ff ff ff b8 e0 eb 9b`, then clean EOF |

The H2S completes the TLS handshake on `:6000` and its **CTRL/file-browser**
traffic on that same port works, so this is not a credential or reachability
problem: the video command specifically is answered with what looks like an
error record (`0xffffffff`) and the connection is dropped.

## The other two routes are closed as well

* **RTSP(S).** `print.ipcam.rtsp_url` is `"disable"` and TCP `322` is closed on
  the printer, so the `lv=rtsps` hint in `camera_url_for()` has nothing to reach.
  `ipcam.liveview` carries only `{"remote":"tutk"}` — no `local` key at all.
* **Cloud camera ticket.** `POST /v1/iot-service/api/user/ttcode` (note: POST,
  not GET as §6.12 of NETWORK_PLUGIN.md states; GET returns 405 `Allow: POST`)
  answers `200` with `{ttcode,authkey,passwd,region,type:"tutk"}` for the A1, but
  `403 {"code":8}` for both the H2S and the H2D. Tried with and without
  `X-BBL-Client-ID`, with `type` = `tutk|agora|brtc`, and with extra body fields;
  the 403 is per-device, not per-request-shape. `/user/agora`, `/user/brtc` and
  `/user/rtc` do not exist (502).

## Conclusion

For H2-class printers the liveview is tutk/brtc only, and the cloud declines to
issue this account a tutk ticket for them. Implementing `brtc` (the printer
advertises `ipcam.brtc_service = "enable"`) is the remaining avenue; nothing in
the current LAN fallback can be tuned into working.

`camera_ticket_url_for()` therefore treats the 403 as a normal outcome, logs it
at info, and leaves the LAN fallback in place.
