# overshare — reference solver

Digital-forensics challenge (GEMASTIK 2026 quals, category *forensics*, difficulty *Insane*).
Handout is a single packet capture (`capture.pcap`); this repo is the reference solver
plus a writeup.

## Run

```bash
pip install -r requirements.txt
python3 solve.py capture.pcap        # prints the flag to stdout
```

`solve.py` is self-contained (no extra local modules). A `.zip` holding one pcap also works.

## What it does

The capture hides one DLP-flagged file exfil inside ordinary workstation traffic
(DNS, TLS, HTTP image download, ARP, ping) plus deliberate dead ends (a plaintext
`flag.txt` decoy, telemetry noise, a chat that tells you to stop, and **two**
look-alike WebSocket binary uploads: channels `share` and `backup`).

Pipeline:

1. Reassemble the TCP streams; ignore the noise and the decoy chat.
2. Two look-alike binary WebSocket uploads exist — only one is the real exfil.
3. The content key is **not** in the upload. The client leaked it in fragments over
   telemetry beacons (`GET /telemetry?ch=..&s=..&b=..`); reassemble per channel,
   order by `s`, base64url-decode `b`, concatenate to a 32-byte key.
4. Decrypt each upload with its channel key (ChaCha20, per-frame nonce = seq) and
   rebuild an **OVSH1** container.
5. Reverse the self-describing OVSH1 container (magic `OVSH1` + a TLV layer table:
   xorshift32 whitening, then a middle-endian 4-byte word swap) to a PNG.
6. The real channel's PNG was cropped by a buggy tool (**aCropalypse**,
   CVE-2023-21036): recover the Sub-filtered leftover scanlines past `IEND` and read
   the token painted into the bottom of the original screenshot. The decoy channel
   has no leftover and yields nothing.

The token is never stored as text anywhere in the capture — it survives only as
deflated pixel leftover.

## Writeup

See [`writeup/writeup.md`](writeup/writeup.md) (with figures).
