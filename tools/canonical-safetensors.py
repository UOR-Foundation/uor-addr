#!/usr/bin/env python3
"""canonical-safetensors.py — the executable form of the safetensors
realization's canonical-form specification.

Reads a safetensors file, applies the canonicalization rules implemented by
`crates/uor-addr/src/safetensors/value.rs`, and emits the κ-label (BLAKE3
of the canonical flat Merkle skeleton). The κ-label is byte-identical to the
Rust crate's `uor_addr::safetensors::address` output; this script is the
spec attestation the CL-SAFETENSORS conformance vectors check against.

It is written independently of the Rust parser: the header is decoded with
the standard library's `json` module, not a hand-written reader, so the two
agree only if both read the format the same way.

Canonical form v2 (flat Merkle skeleton, every variable-length leaf replaced
by its BLAKE3 digest):

    b"SAFE" || LE_u32(2)
    LE_u64(tensor_count) || LE_u64(metadata_count)
    -- __metadata__ entries, sorted by key bytes --
      blake3(key) || LE_u64(len(value)) || blake3(value)
    -- tensors, sorted by name bytes --
      blake3(name) || LE_u32(dtype_id) || LE_u32(rank) || LE_u64(dim) x rank
      || LE_u64(canonical_offset) || blake3(tensor data bytes)

Strings are compared and hashed as the UTF-8 bytes of the decoded JSON
string (escapes resolved, no Unicode normalization). `canonical_offset` is
the cumulative byte position in sorted-name order, so stored offsets and
data-section order do not affect the label.

Stdlib-only (json, struct, and tools/blake3_ref.py).

Usage:
    python3 canonical-safetensors.py MODEL.safetensors             # κ-label
    python3 canonical-safetensors.py --commitment MODEL.safetensors  # skeleton hex
    python3 canonical-safetensors.py --leaves MODEL.safetensors      # name, blake3 leaf
"""
import json
import math
import struct
import sys
import importlib.util as _ilu
import os as _os

# BLAKE3: the official package when installed, else the pure-Python reference
# port beside this file (tools/blake3_ref.py), loaded by path so the spec runs
# under `python -I` too.
_b3_spec = _ilu.spec_from_file_location(
    "blake3_ref", _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "blake3_ref.py"))
_b3 = _ilu.module_from_spec(_b3_spec)
_b3_spec.loader.exec_module(_b3)

TAG = b"SAFE"
VERSION = 2
MAX_HEADER = 100_000_000

# Fixed IDs assigned by this canonical form; never reused or renumbered.
# Bit widths are the safetensors reference implementation's `Dtype::bitsize`.
DTYPES = {
    "BOOL": (0, 8), "U8": (1, 8), "I8": (2, 8), "I16": (3, 16), "U16": (4, 16),
    "F16": (5, 16), "BF16": (6, 16), "I32": (7, 32), "U32": (8, 32),
    "F32": (9, 32), "F64": (10, 64), "I64": (11, 64), "U64": (12, 64),
    "F8_E5M2": (13, 8), "F8_E4M3": (14, 8), "F8_E8M0": (15, 8),
    "F8_E4M3FNUZ": (16, 8), "F8_E5M2FNUZ": (17, 8), "C64": (18, 64),
    "F4": (19, 4), "F6_E2M3": (20, 6), "F6_E3M2": (21, 6),
}


def blake3(b):
    return _b3.digest(b)


def no_duplicates(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate key")
    return dict(pairs)


def is_uint(v):
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v < 2**64


def commitment(raw):
    if len(raw) < 8:
        raise ValueError("truncated")
    n = struct.unpack_from("<Q", raw, 0)[0]
    if n > MAX_HEADER:
        raise ValueError("header too large")
    if 8 + n > len(raw):
        raise ValueError("truncated")
    text = raw[8:8 + n].decode("utf-8")
    header = json.loads(text, object_pairs_hook=no_duplicates,
                        parse_constant=lambda c: (_ for _ in ()).throw(ValueError(c)),
                        parse_float=lambda f: (_ for _ in ()).throw(ValueError(f)))
    if not isinstance(header, dict):
        raise ValueError("header is not an object")
    data = raw[8 + n:]

    meta = header.pop("__metadata__", {})
    if not isinstance(meta, dict) or not all(isinstance(v, str) for v in meta.values()):
        raise ValueError("bad __metadata__")

    tensors = []
    for name, info in header.items():
        if not isinstance(info, dict) or set(info) != {"dtype", "shape", "data_offsets"}:
            raise ValueError(f"bad tensor info {name}")
        if info["dtype"] not in DTYPES:
            raise ValueError(f"unknown dtype {info['dtype']}")
        shape, offs = info["shape"], info["data_offsets"]
        if not isinstance(shape, list) or not all(is_uint(d) for d in shape):
            raise ValueError("bad shape")
        if not isinstance(offs, list) or len(offs) != 2 or not all(is_uint(o) for o in offs):
            raise ValueError("bad data_offsets")
        dtype_id, bits = DTYPES[info["dtype"]]
        # Overflow is judged over the non-zero dimensions even when a zero
        # makes the tensor empty, as the reference implementation does.
        if bits * math.prod(d for d in shape if d) >= 2**64:
            raise ValueError("size overflow")
        nbits = bits * math.prod(shape)
        if nbits % 8:
            raise ValueError("misaligned slice")
        if offs[1] < offs[0] or offs[1] - offs[0] != nbits // 8:
            raise ValueError("tensor size does not match dtype and shape")
        tensors.append((name.encode("utf-8"), dtype_id, shape, offs[0], offs[1]))

    # The buffer is covered exactly: contiguous from 0, no holes, no overlap.
    at = 0
    for t in sorted(tensors, key=lambda t: (t[3], t[4])):
        if t[3] != at:
            raise ValueError("invalid offset")
        at = t[4]
    if at != len(data):
        raise ValueError("buffer not fully covered")

    out = bytearray(TAG + struct.pack("<I", VERSION))
    out += struct.pack("<QQ", len(tensors), len(meta))
    for key in sorted(meta, key=lambda k: k.encode("utf-8")):
        value = meta[key].encode("utf-8")
        out += blake3(key.encode("utf-8")) + struct.pack("<Q", len(value)) + blake3(value)
    offset = 0
    leaves = []
    for name, dtype_id, shape, s, e in sorted(tensors, key=lambda t: t[0]):
        leaf = blake3(data[s:e])
        out += blake3(name) + struct.pack("<II", dtype_id, len(shape))
        out += b"".join(struct.pack("<Q", d) for d in shape)
        out += struct.pack("<Q", offset) + leaf
        offset += e - s
        leaves.append((name.decode("utf-8"), leaf.hex()))
    return bytes(out), leaves


def kappa_label(raw):
    return "blake3:" + _b3.new(commitment(raw)[0]).hexdigest()


def main(argv):
    mode = argv[1] if argv[1].startswith("--") else None
    path = argv[-1]
    with open(path, "rb") as f:
        skeleton, leaves = commitment(f.read())
    if mode == "--commitment":
        print(skeleton.hex())
    elif mode == "--leaves":
        for name, leaf in leaves:
            print(f"{name}\tblake3:{leaf}")
    else:
        print("blake3:" + _b3.new(skeleton).hexdigest())


if __name__ == "__main__":
    main(sys.argv)
