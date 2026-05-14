# Author:   Bushy <contact@bushy.dev>
# Version:  v1.1.0
# Modified: 2026-05-14
#
# test_sign.py: verify the signer produces signatures that pass RSA
# verification against the public key it emits.

from __future__ import annotations

import hashlib
import struct
from pathlib import Path

from sign_pbo import (
    _V3_EXTS,
    gen_checksum,
    hash_filenames,
    hash_files_v3,
    pad_hash,
    parse_pbo,
    sign,
)


def _read_bisign(data: bytes) -> dict:
    """Parse a .bisign back into its fields for verification."""
    off = data.index(b"\x00") + 1   # authority + null
    authority = data[: off - 1].decode()

    off += 4 + 8 + 4                # length, magic, RSA1
    key_bits = struct.unpack_from("<I", data, off)[0]
    off += 4
    key_bytes = key_bits // 8
    e = struct.unpack_from("<I", data, off)[0]
    off += 4
    n = int.from_bytes(data[off : off + key_bytes], "little")
    off += key_bytes

    sig1_len = struct.unpack_from("<I", data, off)[0]
    off += 4
    sig1 = int.from_bytes(data[off : off + sig1_len], "little")
    off += sig1_len

    version = struct.unpack_from("<I", data, off)[0]
    off += 4

    sig2_len = struct.unpack_from("<I", data, off)[0]
    off += 4
    sig2 = int.from_bytes(data[off : off + sig2_len], "little")
    off += sig2_len

    sig3_len = struct.unpack_from("<I", data, off)[0]
    off += 4
    sig3 = int.from_bytes(data[off : off + sig3_len], "little")

    return dict(
        authority=authority,
        n=n,
        e=e,
        key_bits=key_bits,
        sig1=sig1,
        sig2=sig2,
        sig3=sig3,
        version=version,
    )


def _expected_hashes(pbo_bytes: bytes) -> tuple[bytes, bytes, bytes]:
    properties, files, raw_headers = parse_pbo(pbo_bytes)
    h1 = gen_checksum(properties, files, raw_headers, pbo_bytes)

    prefix = properties.get("prefix", "")
    fn_hash = hash_filenames(files, pbo_bytes)

    h = hashlib.sha1()
    h.update(h1)
    h.update(fn_hash)
    h.update(prefix.encode())
    if prefix and not prefix.endswith("\\"):
        h.update(b"\\")
    h2 = h.digest()

    fh = hash_files_v3(files, pbo_bytes)
    h = hashlib.sha1()
    h.update(fh)
    h.update(fn_hash)
    h.update(prefix.encode())
    if prefix and not prefix.endswith("\\"):
        h.update(b"\\")
    h3 = h.digest()

    return h1, h2, h3


def _bisign_path(pbo: Path, authority: str) -> Path:
    return pbo.parent / f"{pbo.name}.{authority}.bisign"


def test_sign_produces_bisign(tiny_pbo: Path, fixed_key: Path) -> None:
    sign(tiny_pbo, "TestAuthority", fixed_key)
    bisign = _bisign_path(tiny_pbo, "TestAuthority")
    assert bisign.exists()
    assert (fixed_key / "TestAuthority.bikey").exists()


def test_signatures_verify(tiny_pbo: Path, tiny_pbo_bytes: bytes, fixed_key: Path) -> None:
    """sig^e mod n must equal the padded hash for each of the three signatures."""
    sign(tiny_pbo, "TestAuthority", fixed_key)
    bisign = _read_bisign(_bisign_path(tiny_pbo, "TestAuthority").read_bytes())

    h1, h2, h3 = _expected_hashes(tiny_pbo_bytes)
    key_bytes = bisign["key_bits"] // 8

    for hsh, sig in [(h1, bisign["sig1"]), (h2, bisign["sig2"]), (h3, bisign["sig3"])]:
        recovered = pow(sig, bisign["e"], bisign["n"])
        assert recovered == pad_hash(hsh, key_bytes)

    assert bisign["version"] == 3


def test_v3_includes_c_files(tiny_pbo_bytes: bytes) -> None:
    """Regression guard: the V3 extension whitelist must include .c (DayZ)."""
    assert ".c" in _V3_EXTS

    _, files, _ = parse_pbo(tiny_pbo_bytes)
    h_with_c = hash_files_v3(files, tiny_pbo_bytes)

    files_no_c = [f for f in files if not f.filename.endswith(".c")]
    h_without_c = hash_files_v3(files_no_c, tiny_pbo_bytes)

    assert h_with_c != h_without_c, "removing .c must change hash3, otherwise V3 is broken"
