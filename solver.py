#!/usr/bin/env python3
"""Recover the inner ZIP password from info.pcap, hayoo.png and .personal.enc.

Usage from the challenge directory, after extracting documents.zip and gallery.zip:
    python solver.py

Or pass paths explicitly:
    python solver.py --pcap info.pcap --hayoo gallery/hayoo.png \
        --personal documents/.personal.enc

This script recovers the RSA plaintext/password. It does not extract/decrypt danger.zip.
"""
from __future__ import annotations

import argparse
import struct
from pathlib import Path


PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": "<",  # little-endian, microsecond timestamps
    b"\xa1\xb2\xc3\xd4": ">",  # big-endian, microsecond timestamps
    b"\x4d\x3c\xb2\xa1": "<",  # little-endian, nanosecond timestamps
    b"\xa1\xb2\x3c\x4d": ">",  # big-endian, nanosecond timestamps
}


def locate(root: Path, explicit: str | None, relative: str) -> Path:
    if explicit:
        path = Path(explicit).expanduser().resolve()
        if not path.is_file():
            raise FileNotFoundError(f"File tidak ditemukan: {path}")
        return path

    direct = root / relative
    if direct.is_file():
        return direct

    matches = list(root.rglob(Path(relative).name))
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise FileNotFoundError(
            f"Tidak menemukan {Path(relative).name} di {root}. "
            "Ekstrak dulu arsip documents.zip/gallery.zip, atau berikan path dengan argumen."
        )
    raise RuntimeError(
        f"Menemukan beberapa file bernama {Path(relative).name}; "
        f"pilih salah satu dengan argumen. Kandidat: {matches}"
    )


def read_dns_name(msg: bytes, pos: int, depth: int = 0) -> tuple[str, int]:
    """Read a DNS name, following compression pointers; return name and next offset."""
    if depth > 20:
        raise ValueError("DNS compression pointer loop")
    labels: list[str] = []
    resume_at: int | None = None

    while True:
        if pos >= len(msg):
            raise ValueError("Truncated DNS name")
        size = msg[pos]
        if size == 0:
            pos += 1
            if resume_at is None:
                resume_at = pos
            break
        if size & 0xC0 == 0xC0:
            if pos + 1 >= len(msg):
                raise ValueError("Truncated DNS compression pointer")
            pointer = ((size & 0x3F) << 8) | msg[pos + 1]
            if resume_at is None:
                resume_at = pos + 2
            suffix, _ = read_dns_name(msg, pointer, depth + 1)
            if suffix:
                labels.extend(suffix.split("."))
            pos += 2
            break
        if size & 0xC0:
            raise ValueError("Unsupported DNS label encoding")
        pos += 1
        if pos + size > len(msg):
            raise ValueError("Truncated DNS label")
        labels.append(msg[pos : pos + size].decode("ascii", errors="strict"))
        pos += size

    return ".".join(labels), resume_at if resume_at is not None else pos


def dns_txt_records(msg: bytes) -> list[tuple[str, str]]:
    if len(msg) < 12:
        return []
    _txid, _flags, qdcount, ancount, nscount, arcount = struct.unpack_from("!HHHHHH", msg, 0)
    pos = 12

    for _ in range(qdcount):
        _qname, pos = read_dns_name(msg, pos)
        if pos + 4 > len(msg):
            return []
        pos += 4  # QTYPE + QCLASS

    out: list[tuple[str, str]] = []
    for count in (ancount, nscount, arcount):
        for _ in range(count):
            try:
                rrname, pos = read_dns_name(msg, pos)
                if pos + 10 > len(msg):
                    return out
                rtype, _rclass, _ttl, rdlength = struct.unpack_from("!HHIH", msg, pos)
                pos += 10
                rdata = msg[pos : pos + rdlength]
                if len(rdata) != rdlength:
                    return out
                pos += rdlength
            except (ValueError, IndexError, struct.error):
                return out

            if rtype == 16:  # TXT
                chunks: list[bytes] = []
                j = 0
                valid = True
                while j < len(rdata):
                    chunk_len = rdata[j]
                    j += 1
                    if j + chunk_len > len(rdata):
                        valid = False
                        break
                    chunks.append(rdata[j : j + chunk_len])
                    j += chunk_len
                if valid:
                    # TXT character-strings in this record form one logical value.
                    value = b"".join(chunks).decode("ascii", errors="strict")
                    out.append((rrname.lower(), value))
    return out


def extract_rsa_params(pcap_path: Path) -> tuple[int, int]:
    data = pcap_path.read_bytes()
    if len(data) < 24 or data[:4] not in PCAP_MAGICS:
        raise ValueError("Format PCAP klasik tidak dikenali")
    endian = PCAP_MAGICS[data[:4]]
    linktype = struct.unpack_from(endian + "I", data, 20)[0]
    if linktype != 1:
        raise ValueError(f"Link type PCAP {linktype} bukan Ethernet (1)")

    wanted: dict[str, str] = {}
    offset = 24
    frame_no = 0
    while offset + 16 <= len(data):
        _sec, _frac, incl_len, _orig_len = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        if offset + incl_len > len(data):
            raise ValueError("PCAP terpotong di tengah packet")
        frame = data[offset : offset + incl_len]
        offset += incl_len
        frame_no += 1

        if len(frame) < 14:
            continue
        ethertype = int.from_bytes(frame[12:14], "big")
        if ethertype != 0x0800:  # DNS key records in this capture are IPv4.
            continue
        ip = frame[14:]
        if len(ip) < 20 or ip[0] >> 4 != 4:
            continue
        ihl = (ip[0] & 0x0F) * 4
        if ihl < 20 or len(ip) < ihl + 8 or ip[9] != 17:  # UDP
            continue
        frag = int.from_bytes(ip[6:8], "big") & 0x1FFF
        if frag:
            continue
        udp = ip[ihl:]
        src_port, dst_port, udp_len = struct.unpack_from("!HHH", udp, 0)
        if src_port != 53 and dst_port != 53:
            continue
        if udp_len < 8 or len(udp) < udp_len:
            continue
        message = udp[8:udp_len]
        for rrname, value in dns_txt_records(message):
            if rrname in ("k1.mtd-sync.internal", "k2.mtd-sync.internal"):
                wanted[rrname] = value

    try:
        n_text = wanted["k1.mtd-sync.internal"]
        e_text = wanted["k2.mtd-sync.internal"]
    except KeyError as exc:
        raise ValueError(
            "Tidak menemukan jawaban TXT k1/k2.mtd-sync.internal di PCAP"
        ) from exc

    if not n_text.startswith("n=") or not e_text.startswith("e="):
        raise ValueError(f"Format TXT tidak sesuai: n={n_text[:30]!r}, e={e_text!r}")
    return int(n_text[2:]), int(e_text[2:])


def extract_factor_from_png(png_path: Path) -> int:
    image = png_path.read_bytes()
    if not image.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError(f"Bukan PNG yang valid: {png_path}")

    pos = 8
    while pos + 12 <= len(image):
        chunk_len = int.from_bytes(image[pos : pos + 4], "big")
        chunk_type = image[pos + 4 : pos + 8]
        end = pos + 12 + chunk_len
        if end > len(image):
            raise ValueError("Chunk PNG terpotong")
        if chunk_type == b"IEND":
            trailer = image[end:]
            break
        pos = end
    else:
        raise ValueError("Chunk IEND tidak ditemukan")

    if len(trailer) < 6 or trailer[:4] != bytes.fromhex("deadbeef"):
        raise ValueError("Trailer DEADBEEF tidak ditemukan setelah IEND")
    payload_len = int.from_bytes(trailer[4:6], "big")
    payload = trailer[6 : 6 + payload_len]
    if payload_len != 128 or len(payload) != payload_len or len(trailer) != 6 + payload_len:
        raise ValueError(f"Panjang trailer tidak sesuai: {len(trailer)} byte")
    return int.from_bytes(payload, "big")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", help="Path ke info.pcap (default: cari di folder ini)")
    parser.add_argument("--hayoo", help="Path ke gallery/hayoo.png")
    parser.add_argument("--personal", help="Path ke documents/.personal.enc")
    args = parser.parse_args()

    # Prefer the nearest working/script ancestor that contains the challenge PCAP.
    # This also works when solver.py itself is stored in a subfolder such as gallery/.
    cwd = Path.cwd().resolve()
    script_dir = Path(__file__).resolve().parent
    candidates: list[Path] = []
    for start in (cwd, script_dir):
        for candidate in (start, *start.parents):
            if candidate not in candidates:
                candidates.append(candidate)
    root = next(
        (candidate for candidate in candidates
         if (candidate / "info.pcap").is_file()
         or any(candidate.rglob("info.pcap"))),
        cwd,
    )

    pcap_path = locate(root, args.pcap, "info.pcap")
    png_path = locate(root, args.hayoo, "gallery/hayoo.png")
    personal_path = locate(root, args.personal, "documents/.personal.enc")

    n, e = extract_rsa_params(pcap_path)
    p = extract_factor_from_png(png_path)
    c_text = personal_path.read_text(encoding="ascii").strip()
    if not c_text.isdigit():
        raise ValueError(".personal.enc harus berisi ciphertext desimal")
    C = int(c_text)

    q, remainder = divmod(n, p)
    if remainder != 0:
        raise ValueError("Faktor dari PNG tidak membagi modulus n dari PCAP")
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    m = pow(C, d, n)
    if pow(m, e, n) != C:
        raise ValueError("Verifikasi RSA gagal: m^e mod n tidak sama dengan C")

    password = m.to_bytes((m.bit_length() + 7) // 8, "big").decode("ascii")
    print(f"PCAP: {pcap_path}")
    print(f"PNG faktor: {png_path}")
    print(f"Ciphertext RSA: {personal_path}")
    print(f"n: {n.bit_length()} bit; e={e}; p: {p.bit_length()} bit; q: {q.bit_length()} bit")
    print("RSA re-encryption check: OK")
    print(f"Password dalam: {password}")


if __name__ == "__main__":
    main()
