# Author:   Bushy <contact@bushy.dev>
# Version:  v1.1.0
# Modified: 2026-05-14
#
# gen_test_key.py: generate the throwaway test key used by the test suite.
# Run once; commit the resulting .privatekey under tests/fixtures/.
# Once the key is committed, all signatures over fixed input are deterministic.

from __future__ import annotations

import struct
import sys
from pathlib import Path


def generate() -> bytes:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa

    priv = rsa.generate_private_key(
        public_exponent=65537, key_size=1024, backend=default_backend()
    )
    pub = priv.public_key().public_numbers()
    nums = priv.private_numbers()

    key_bits = 1024
    out = bytearray()
    out += struct.pack("<I", key_bits)
    _write_le_int(out, pub.n, key_bits // 8)
    _write_le_int(out, pub.e, 4)
    _write_le_int(out, nums.d, key_bits // 8)
    return bytes(out)


def _write_le_int(buf: bytearray, value: int, size: int) -> None:
    raw = value.to_bytes(size, "little")
    buf += struct.pack("<I", size)
    buf += raw


def main() -> None:
    out_path = (
        Path(__file__).resolve().parents[1]
        / "tests"
        / "fixtures"
        / "TestAuthority.privatekey"
    )
    if out_path.exists() and "--force" not in sys.argv:
        sys.exit(f"refusing to overwrite {out_path} (pass --force)")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(generate())
    print(f"wrote {out_path} ({out_path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
