"""Shared fixtures: a minimal in-memory PBO and a deterministic test key."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest


def _build_pbo(prefix: str, entries: list[tuple[str, bytes]]) -> bytes:
    """Construct a minimal valid PBO from a list of (filename, data) pairs."""
    buf = bytearray()

    # Vers header
    buf += b"\x00"                          # empty filename
    buf += struct.pack("<I", 0x56657273)    # 'Vers' magic
    buf += b"\x00" * 16                     # 4 reserved u32s
    if prefix:
        buf += b"prefix\x00" + prefix.encode() + b"\x00"
    buf += b"\x00"                          # empty key terminates properties

    # File headers
    for name, data in entries:
        buf += name.encode() + b"\x00"
        buf += struct.pack("<I", 0)             # packing_method = uncompressed
        buf += struct.pack("<I", len(data))     # original_size
        buf += struct.pack("<I", 0)             # reserved
        buf += struct.pack("<I", 0)             # timestamp
        buf += struct.pack("<I", len(data))     # data_size

    # Sentinel
    buf += b"\x00"
    buf += b"\x00" * 20

    # File data
    for _, data in entries:
        buf += data

    return bytes(buf)


@pytest.fixture
def tiny_pbo_bytes() -> bytes:
    """A minimal PBO with one .c file, one .cfg and one .paa (V3-excluded)."""
    return _build_pbo(
        prefix="test\\mod",
        entries=[
            ("config.cpp", b"class CfgPatches {};\n"),
            ("scripts\\main.c", b"void main() {}\n"),
            ("icon.paa", b"\x00\x01\x02\x03"),
        ],
    )


@pytest.fixture
def tiny_pbo(tmp_path: Path, tiny_pbo_bytes: bytes) -> Path:
    p = tmp_path / "tiny.pbo"
    p.write_bytes(tiny_pbo_bytes)
    return p


@pytest.fixture
def fixed_key(tmp_path: Path) -> Path:
    """Return a key_dir pre-populated with a deterministic test key.

    Uses a fixed RSA-1024 keypair (THROWAWAY, do not use for real signing).
    """
    src = Path(__file__).parent / "fixtures" / "TestAuthority.privatekey"
    key_dir = tmp_path / ".signing"
    key_dir.mkdir()
    (key_dir / "TestAuthority.privatekey").write_bytes(src.read_bytes())
    return key_dir
