#!/usr/bin/env python3
# Reference solver for forensics/overshare.
# TCP reassembly -> pick the DLP-flagged WebSocket upload (of two look-alikes) ->
# rebuild the ChaCha20 key from /telemetry beacons -> decrypt -> reverse the
# self-describing OVSH1 container (xorshift32 + 4-byte word swap) -> recover the
# aCropalypse leftover past IEND -> read the pixel-painted flag.
# Usage: python3 solve.py <capture.pcap|.zip>
from __future__ import annotations
import base64, json, re, struct, sys, zipfile, zlib
from collections import defaultdict
from pathlib import Path

import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from scapy.all import rdpcap, TCP, IP, Raw

# 5x7 bitmap font, packed: 35 bits/glyph left-aligned into 5 bytes, base64.
GLYPH_W, GLYPH_H = 5, 7
_CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789{}_-.:/! '
_FONT_B64 = 'dGP4xiD0Y+jHwHRhCEXA9GMYx8D8IehD4Pwh6EIAdGF4xcCMY/jGIPkIQhPgOIQpSYCMqYpKIIQhCEPgjutYxiCOazjGIHRjGMXA9GPoQgB0YxrJoPRj6kogfCDgh8D5CEIQgIxjGMXAjGMYqICMY1rVQIxURUYgjFRCEID4RERD4AAcF8XghC2Yx8AAHQhFwAhbOMXgAB0fwcAyUcQhAAPjF4XAhC2YxiAgGEIRwBAMIUmAhCVMUkBhCEIRwAA1WsYgAC2YxiAAHRjFwAA9H0IAAB83hCAALZhCAAAfBwfAQjiEJMAAIxjNoAAjGKiAACMa1UAAIqIqIAAjF4XAAD4iI+B0Z1zFwCMIQhHAdEIiI+D4iCDFwBGVL4hA/DwQxcAyIejFwPhERCEAdGLoxcB0YvCJgDIRhCDAYIQxCYAAAAAD4AAB8AAAAAAAMYADGAYwAAhEREIAIQhCAIAAAAAAAA=='
_fr = base64.b64decode(_FONT_B64)
BITS_TO_CHAR = {
    tuple(((int.from_bytes(_fr[i * 5:i * 5 + 5], "big") >> 5) >> (34 - k)) & 1 for k in range(35)): ch
    for i, ch in enumerate(_CHARSET)
}
TOK_SCALE, TOK_X, TOK_UP = 2, 224, 150
TOK_CELL = (GLYPH_W + 1) * TOK_SCALE
TOK_THR = (sum((122, 255, 168)) + sum((12, 14, 18))) // 2

FLAG_RE = re.compile(r"GEMASTIK19\{[\x20-\x7e]+\}")
SYNC, MAGIC = b"\x00\x00\xff\xff", b"\x89PNG\r\n\x1a\n"
CONTAINER_MAGIC = b"OVSH1\x00"
TELEMETRY_RE = re.compile(rb"GET /telemetry\?([^\s]*) HTTP")


def read_token(rec, max_chars=80):
    """OCR the fixed-layout token painted into the recovered bottom scanlines."""
    y0, out = rec.shape[0] - TOK_UP, []
    for i in range(max_chars):
        bits = []
        for r in range(GLYPH_H):
            for c in range(GLYPH_W):
                yy = y0 + r * TOK_SCALE + TOK_SCALE // 2
                xx = TOK_X + i * TOK_CELL + c * TOK_SCALE + TOK_SCALE // 2
                if not (0 <= yy < rec.shape[0] and xx < rec.shape[1]):
                    return "".join(out)
                bits.append(1 if int(rec[yy, xx].sum()) > TOK_THR else 0)
        ch = BITS_TO_CHAR.get(tuple(bits))
        if ch is None:
            out.append("?"); break
        out.append(ch)
        if ch == "}":
            break
    return "".join(out)


def load_pcap(path: Path) -> Path:
    if path.suffix == ".zip" or zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            data = z.read(next(n for n in z.namelist() if n.endswith((".pcap", ".pcapng"))))
        import tempfile
        tmp = Path(tempfile.mkstemp(suffix=".pcap")[1]); tmp.write_bytes(data)
        return tmp
    return path


def reassemble_streams(pcap_path):
    """Rebuild each TCP half-stream (keyed by connection + sender) by sequence."""
    dirs = defaultdict(list)
    for p in rdpcap(str(pcap_path)):
        if TCP in p and Raw in p:
            a, b = (p[IP].src, p[TCP].sport), (p[IP].dst, p[TCP].dport)
            dirs[(frozenset((a, b)), a)].append((int(p[TCP].seq), bytes(p[Raw].load)))
    streams = defaultdict(dict)
    for (key, a), segs in dirs.items():
        segs.sort(key=lambda s: s[0])
        base, buf = segs[0][0], bytearray()
        for seq, load in segs:
            off = seq - base
            if off < 0:
                continue
            if off + len(load) > len(buf):
                buf.extend(b"\x00" * (off + len(load) - len(buf)))
            buf[off:off + len(load)] = load
        streams[key][a] = bytes(buf)
    return streams


def ws_frames(data):
    """Yield (opcode, payload) for each WebSocket frame after the HTTP upgrade."""
    i = data.find(b"\r\n\r\n"); i = i + 4 if i >= 0 else 0
    while i + 2 <= len(data):
        b0, b1 = data[i], data[i + 1]; opcode, masked, ln = b0 & 0x0f, b1 & 0x80, b1 & 0x7f; i += 2
        if ln == 126:
            ln = struct.unpack(">H", data[i:i + 2])[0]; i += 2
        elif ln == 127:
            ln = struct.unpack(">Q", data[i:i + 8])[0]; i += 8
        mask = data[i:i + 4] if masked else b""; i += 4 if masked else 0
        payload = data[i:i + ln]; i += ln
        if len(payload) < ln:
            break
        if masked:
            payload = bytes(c ^ mask[j % 4] for j, c in enumerate(payload))
        yield opcode, payload


def collect_keys(streams):
    """Reassemble a 32-byte key per channel from /telemetry?ch=..&s=..&b=.. fragments."""
    beacons = defaultdict(dict)
    for sides in streams.values():
        for data in sides.values():
            for m in TELEMETRY_RE.finditer(data):
                kv = dict(p.split("=", 1) for p in m.group(1).decode("latin-1").split("&") if "=" in p)
                if {"ch", "s", "b"} <= kv.keys():
                    try:
                        beacons[kv["ch"]][int(kv["s"])] = base64.urlsafe_b64decode(kv["b"])
                    except Exception:
                        pass
    return {ch: b"".join(fr[i] for i in sorted(fr)) for ch, fr in beacons.items()}


def find_uploads(streams):
    """Each WebSocket carrying binary frames, tagged with its session channel."""
    uploads = []
    for sides in streams.values():
        client = next((d for d in sides.values() if b"Upgrade: websocket" in d and b"GET " in d), None)
        if client is None:
            continue
        frames = [pl for op, pl in ws_frames(client) if op == 0x2]
        if not frames:
            continue
        ch = None
        for d in sides.values():
            for op, pl in ws_frames(d):
                if op == 0x1:
                    try:
                        o = json.loads(pl.decode())
                    except Exception:
                        continue
                    if isinstance(o, dict) and o.get("op") == "session":
                        ch = o.get("ch")
        uploads.append((ch, frames))
    return uploads


def decrypt_frames(frames, key):
    """ChaCha20-decrypt each length-prefixed frame (nonce = 16-byte big-endian seq)."""
    chunks = {}
    for fr in frames:
        seq, ln = struct.unpack(">IH", fr[:6])
        dec = Cipher(algorithms.ChaCha20(key, seq.to_bytes(16, "big")), None).decryptor()
        chunks[seq] = dec.update(fr[6:6 + ln])
    return b"".join(chunks[s] for s in sorted(chunks))


def open_container(blob):
    """Reverse the self-describing OVSH1 container: magic | orig_len | n_layers | TLV."""
    if not blob.startswith(CONTAINER_MAGIC):
        raise ValueError("not an OVSH1 container")
    orig_len = struct.unpack(">I", blob[6:10])[0]; off, layers = 11, []
    for _ in range(blob[10]):
        plen = blob[off + 1]; layers.append((blob[off], blob[off + 2:off + 2 + plen])); off += 2 + plen
    body = blob[off:off + orig_len]
    for typ, params in reversed(layers):
        if typ == 2:                                    # middle-endian 4-byte word swap
            b = bytearray(body)
            for i in range(0, len(b) - 3, 4):
                b[i:i + 4] = bytes((b[i + 2], b[i + 3], b[i], b[i + 1]))
            body = bytes(b)
        elif typ == 1:                                  # xorshift32 whitening
            x = struct.unpack(">I", params[:4])[0]; a, bb, c = params[4:7]; ks = bytearray()
            for _ in range(orig_len):
                x ^= (x << a) & 0xffffffff; x ^= x >> bb; x ^= (x << c) & 0xffffffff; ks.append(x & 0xff)
            body = bytes(p ^ q for p, q in zip(body, ks))
        else:
            raise ValueError(f"unknown container layer type {typ}")
    return body


def acrop_recover(png, width):
    """Recover the Sub-filtered leftover scanlines deflated past IEND (aCropalypse)."""
    tail, stride, best, idx = png[png.find(b"IEND") + 8:], 1 + width * 3, None, -1
    while (idx := tail.find(SYNC, idx + 1)) >= 0:
        try:
            d = zlib.decompressobj(-15); raw = d.decompress(tail[idx + 4:]) + d.flush()
        except Exception:
            continue
        nrows = len(raw) // stride
        if nrows and {raw[r * stride] for r in range(nrows)} == {1} and (best is None or nrows > best[0]):
            best = (nrows, raw)
    if not best:
        raise ValueError("no aCropalypse leftover")
    nrows, raw = best
    rows = [np.cumsum(np.frombuffer(raw[r * stride + 1:r * stride + 1 + width * 3], np.uint8)
                      .reshape(width, 3).astype(np.int32), axis=0) % 256 for r in range(nrows)]
    return np.stack(rows).astype(np.uint8)


def solve(path: Path) -> str:
    streams = reassemble_streams(load_pcap(path))
    keys = collect_keys(streams)
    uploads = find_uploads(streams)
    if not uploads:
        raise SystemExit("no binary upload found")
    for ch, frames in uploads:
        for key in ([keys[ch]] if ch in keys else list(keys.values())):
            if not key or len(key) != 32:
                continue
            try:
                png = open_container(decrypt_frames(frames, key))
                if not png.startswith(MAGIC):
                    continue
                w = struct.unpack(">I", png[png.find(b"IHDR") + 4:png.find(b"IHDR") + 8])[0]
                token = read_token(acrop_recover(png, w)).strip()
            except Exception:
                continue
            if FLAG_RE.fullmatch(token):
                return token
    raise SystemExit("no flag recovered from any upload")


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python3 solve.py <capture.pcap|.zip>", file=sys.stderr); return 2
    path = Path(sys.argv[1])
    if not path.exists():
        print(f"file not found: {path}", file=sys.stderr); return 2
    print(solve(path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
