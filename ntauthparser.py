#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Any, Optional

from Crypto.Hash import MD4


NTLM_SIG = b"NTLMSSP\x00"

NEGOTIATE_FLAGS = {
    0x00000001: "NEGOTIATE_UNICODE",
    0x00000002: "NEGOTIATE_OEM",
    0x00000004: "REQUEST_TARGET",
    0x00000010: "NEGOTIATE_SIGN",
    0x00000020: "NEGOTIATE_SEAL",
    0x00000200: "NEGOTIATE_NTLM",
    0x00004000: "NEGOTIATE_ALWAYS_SIGN",
    0x00040000: "NEGOTIATE_EXTENDED_SESSIONSECURITY",
    0x00200000: "NEGOTIATE_TARGET_INFO",
    0x00400000: "NEGOTIATE_VERSION",
    0x00800000: "NEGOTIATE_128",
    0x01000000: "NEGOTIATE_KEY_EXCH",
    0x02000000: "NEGOTIATE_56",
}

AV_IDS = {
    0x0000: "MsvAvEOL",
    0x0001: "NbComputerName",
    0x0002: "NbDomainName",
    0x0003: "DnsComputerName",
    0x0004: "DnsDomainName",
    0x0005: "DnsTreeName",
    0x0006: "Flags",
    0x0007: "Timestamp",
    0x0008: "SingleHost",
    0x0009: "TargetName",
    0x000A: "ChannelBindings",
}


@dataclass
class Msg:
    frame: str
    src: str
    dst: str
    kind: str
    raw: bytes
    username: str = ""
    domain: str = ""
    workstation: str = ""
    flags_raw: Optional[int] = None
    flags: Optional[list[str]] = None
    target_name: str = ""
    server_challenge: str = ""
    av_pairs: Optional[list[dict[str, Any]]] = None
    lm_len: Optional[int] = None
    nt_len: Optional[int] = None
    nt_proof: str = ""
    ntlmv2_blob: bytes = b""
    mic: str = ""
    pyspnego: Any = None


def run_tshark_json(pcap: str) -> list[dict[str, Any]]:
    cmd = ["tshark", "-r", pcap, "-Y", "ldap || spnego || ntlmssp", "-T", "json"]
    p = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return json.loads(p.stdout)


def walk(obj: Any, path: str = ""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk(v, f"{path}.{k}" if path else k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from walk(v, f"{path}[{i}]")
    else:
        yield path, obj


def first_scalar(obj: Any, suffix: str) -> Optional[str]:
    for path, value in walk(obj):
        if path.endswith(suffix) and isinstance(value, str):
            return value
    return None


def maybe_hex_to_bytes(s: str) -> Optional[bytes]:
    s = s.replace(":", "").replace(" ", "").strip()
    if len(s) < 16 or len(s) % 2 != 0 or not re.fullmatch(r"[0-9a-fA-F]+", s):
        return None
    try:
        return binascii.unhexlify(s)
    except binascii.Error:
        return None


def utf16le(data: bytes) -> str:
    return data.decode("utf-16-le", errors="replace").rstrip("\x00")


def secbuf(buf: bytes, off: int) -> tuple[int, int, int]:
    return (
        int.from_bytes(buf[off:off + 2], "little"),
        int.from_bytes(buf[off + 2:off + 4], "little"),
        int.from_bytes(buf[off + 4:off + 8], "little"),
    )


def secbuf_bytes(buf: bytes, off: int) -> bytes:
    ln, _, ptr = secbuf(buf, off)
    if ptr + ln > len(buf):
        return b""
    return buf[ptr:ptr + ln]


def decode_flags(v: int) -> list[str]:
    return [name for bit, name in sorted(NEGOTIATE_FLAGS.items()) if v & bit]


def parse_av_pairs(data: bytes) -> list[dict[str, Any]]:
    out = []
    i = 0
    while i + 4 <= len(data):
        avid = int.from_bytes(data[i:i + 2], "little")
        ln = int.from_bytes(data[i + 2:i + 4], "little")
        i += 4
        val = data[i:i + ln]
        i += ln

        name = AV_IDS.get(avid, f"0x{avid:04x}")
        item: dict[str, Any] = {"name": name, "raw": val.hex()}

        if avid == 0x0000:
            out.append(item)
            break
        elif avid in {0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0009}:
            item["value"] = utf16le(val)
        elif avid == 0x0006 and len(val) == 4:
            flags = int.from_bytes(val, "little")
            bits = []
            if flags & 0x00000002:
                bits.append("MIC_PRESENT")
            item["value"] = f"0x{flags:08x}"
            item["bits"] = bits
        else:
            item["value"] = val.hex()

        out.append(item)
    return out


def parse_ntlm(token: bytes) -> Optional[Msg]:
    if not token.startswith(NTLM_SIG) or len(token) < 12:
        return None

    typ = int.from_bytes(token[8:12], "little")
    if typ == 1:
        flags = int.from_bytes(token[12:16], "little") if len(token) >= 16 else 0
        return Msg(
            frame="",
            src="",
            dst="",
            kind="NEGOTIATE",
            raw=token,
            flags_raw=flags,
            flags=decode_flags(flags),
        )

    if typ == 2:
        flags = int.from_bytes(token[20:24], "little") if len(token) >= 24 else 0
        target_name = utf16le(secbuf_bytes(token, 12)) if len(token) >= 20 else ""
        challenge = token[24:32].hex() if len(token) >= 32 else ""
        av = parse_av_pairs(secbuf_bytes(token, 40)) if len(token) >= 48 else []
        return Msg(
            frame="",
            src="",
            dst="",
            kind="CHALLENGE",
            raw=token,
            flags_raw=flags,
            flags=decode_flags(flags),
            target_name=target_name,
            server_challenge=challenge,
            av_pairs=av,
        )

    if typ == 3:
        lm = secbuf_bytes(token, 12)
        nt = secbuf_bytes(token, 20)
        domain = utf16le(secbuf_bytes(token, 28))
        user = utf16le(secbuf_bytes(token, 36))
        workstation = utf16le(secbuf_bytes(token, 44))
        flags = int.from_bytes(token[60:64], "little") if len(token) >= 64 else 0

        mic = ""
        for off in (72, 64):
            if off + 16 <= len(token):
                cand = token[off:off + 16]
                if cand != b"\x00" * 16:
                    mic = cand.hex()
                    break

        nt_proof = nt[:16].hex() if len(nt) >= 16 else ""
        nt_blob = nt[16:] if len(nt) > 16 else b""

        return Msg(
            frame="",
            src="",
            dst="",
            kind="AUTHENTICATE",
            raw=token,
            username=user,
            domain=domain,
            workstation=workstation,
            flags_raw=flags,
            flags=decode_flags(flags),
            lm_len=len(lm),
            nt_len=len(nt),
            nt_proof=nt_proof,
            ntlmv2_blob=nt_blob,
            mic=mic,
        )

    return Msg(frame="", src="", dst="", kind=f"TYPE_{typ}", raw=token)


def call_pyspnego(token: bytes) -> Any:
    b64 = base64.b64encode(token).decode()
    for cmd in (
        [sys.executable, "-m", "spnego", "--token", b64, "--format", "json"],
        [sys.executable, "-m", "spnego", "--token", b64],
    ):
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, check=True)
            out = p.stdout.strip()
            try:
                return json.loads(out)
            except json.JSONDecodeError:
                return out
        except Exception:
            pass
    return None


def extract_messages(packets: list[dict[str, Any]]) -> list[Msg]:
    msgs: list[Msg] = []
    seen: set[str] = set()

    for pkt in packets:
        layers = pkt.get("_source", {}).get("layers", {})
        frame = first_scalar(layers.get("frame", {}), "frame.number") or "?"
        src = first_scalar(layers.get("ip", {}), "ip.src") or first_scalar(layers.get("ipv6", {}), "ipv6.src") or "?"
        dst = first_scalar(layers.get("ip", {}), "ip.dst") or first_scalar(layers.get("ipv6", {}), "ipv6.dst") or "?"

        for path, value in walk(layers):
            if not isinstance(value, str):
                continue
            if not any(k in path.lower() for k in ("spnego", "ntlmssp", "mechtoken", "token", "blob", "sasl")):
                continue

            raw = maybe_hex_to_bytes(value)
            if not raw:
                continue

            candidates = []
            if NTLM_SIG in raw:
                candidates.append(raw[raw.find(NTLM_SIG):])
            else:
                candidates.append(raw)

            for c in candidates:
                hx = c.hex()
                if hx in seen:
                    continue
                seen.add(hx)

                msg = parse_ntlm(c)
                if not msg:
                    continue
                msg.frame = frame
                msg.src = src
                msg.dst = dst
                msg.pyspnego = call_pyspnego(c)
                msgs.append(msg)

    return msgs


def nt_hash_from_password(password: str) -> bytes:
    h = MD4.new()
    h.update(password.encode("utf-16-le"))
    return h.digest()


def parse_hashes(hashes: str) -> tuple[Optional[bytes], Optional[bytes]]:
    if ":" not in hashes:
        raise ValueError("-hashes must be LM:NT")
    lm_hex, nt_hex = hashes.split(":", 1)
    lm = bytes.fromhex(lm_hex) if lm_hex else None
    nt = bytes.fromhex(nt_hex) if nt_hex else None
    return lm, nt


def ntowfv2(nt_hash: bytes, user: str, domain: str) -> bytes:
    ident = (user.upper() + domain).encode("utf-16-le")
    return hmac.new(nt_hash, ident, hashlib.md5).digest()


def analyze_auth(msg: Msg, nt_hash: bytes, challenge: Optional[Msg]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if not challenge or not challenge.server_challenge or not msg.ntlmv2_blob or not msg.nt_proof:
        return out

    response_key_nt = ntowfv2(nt_hash, msg.username, msg.domain)
    server_challenge = bytes.fromhex(challenge.server_challenge)
    expected_nt_proof = hmac.new(response_key_nt, server_challenge + msg.ntlmv2_blob, hashlib.md5).digest()
    session_base_key = hmac.new(response_key_nt, expected_nt_proof, hashlib.md5).digest()

    out["response_key_nt"] = response_key_nt.hex()
    out["expected_nt_proof"] = expected_nt_proof.hex()
    out["captured_nt_proof"] = msg.nt_proof
    out["nt_proof_match"] = expected_nt_proof.hex() == msg.nt_proof
    out["session_base_key"] = session_base_key.hex()

    mic_expected = False
    for av in challenge.av_pairs or []:
        if av.get("name") == "Flags" and "MIC_PRESENT" in av.get("bits", []):
            mic_expected = True
            break
    out["mic_expected"] = mic_expected
    out["mic_present"] = bool(msg.mic)
    return out


def print_obj(obj: Any, indent: int = 0) -> None:
    pad = " " * indent
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                print(f"{pad}{k}:")
                print_obj(v, indent + 2)
            else:
                print(f"{pad}{k}: {v}")
    elif isinstance(obj, list):
        for v in obj:
            if isinstance(v, (dict, list)):
                print(f"{pad}-")
                print_obj(v, indent + 2)
            else:
                print(f"{pad}- {v}")
    else:
        print(f"{pad}{obj}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("-u")
    ap.add_argument("-d")
    ap.add_argument("-p")
    ap.add_argument("-hashes")
    args = ap.parse_args()

    if args.p and args.hashes:
        print("Use either -p or -hashes, not both.", file=sys.stderr)
        return 2

    creds_mode = bool(args.u and args.d and (args.p or args.hashes))
    partial = any([args.u, args.d, args.p, args.hashes]) and not creds_mode
    if partial:
        print("Creds mode requires: -u USER -d DOMAIN and either -p PASS or -hashes LM:NT", file=sys.stderr)
        return 2

    try:
        packets = run_tshark_json(args.pcap)
    except FileNotFoundError:
        print("tshark not found in PATH", file=sys.stderr)
        return 2
    except subprocess.CalledProcessError as e:
        print(e.stderr, file=sys.stderr)
        return 2

    msgs = extract_messages(packets)
    if not msgs:
        print("No NTLM/SPNEGO messages found.")
        return 1

    nt_hash = None
    if creds_mode:
        if args.p:
            nt_hash = nt_hash_from_password(args.p)
        else:
            _, nt_hash = parse_hashes(args.hashes)
        msgs = [m for m in msgs if m.kind != "AUTHENTICATE" or (m.username.lower() == args.u.lower() and m.domain.lower() == args.d.lower())]

        if not any(m.kind == "AUTHENTICATE" for m in msgs):
            print("No packets found involving that user/domain.")
            return 1

    last_challenge: Optional[Msg] = None

    for m in msgs:
        if creds_mode and m.kind == "AUTHENTICATE":
            if m.username.lower() != args.u.lower() or m.domain.lower() != args.d.lower():
                continue

        print("=" * 80)
        print(f"Frame {m.frame}  {m.src} -> {m.dst}")
        print(f"Type: {m.kind}")

        if m.flags_raw is not None:
            print(f"Flags: 0x{m.flags_raw:08x}")
        if m.flags:
            print("Flag names:")
            for f in m.flags:
                print(f"  - {f}")

        if m.kind == "CHALLENGE":
            last_challenge = m
            if m.target_name:
                print(f"TargetName: {m.target_name}")
            if m.server_challenge:
                print(f"ServerChallenge: {m.server_challenge}")
            if m.av_pairs:
                print("AV Pairs:")
                for av in m.av_pairs:
                    val = av.get("value", av.get("raw"))
                    print(f"  - {av['name']}: {val}")

        elif m.kind == "AUTHENTICATE":
            print(f"Username: {m.username}")
            print(f"Domain: {m.domain}")
            print(f"Workstation: {m.workstation}")
            print(f"LM Resp Len: {m.lm_len}")
            print(f"NT Resp Len: {m.nt_len}")
            if m.nt_proof:
                print(f"NT Proof Str: {m.nt_proof}")
            if m.mic:
                print(f"MIC: {m.mic}")

            if creds_mode and nt_hash:
                analysis = analyze_auth(m, nt_hash, last_challenge)
                if analysis:
                    print("Analysis:")
                    print_obj(analysis, 2)

        if m.pyspnego is not None:
            print("pyspnego:")
            print_obj(m.pyspnego, 2)

        print("Raw Hex:")
        print(m.raw.hex())

    return 0


if __name__ == "__main__":
    main()
