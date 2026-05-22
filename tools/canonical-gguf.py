#!/usr/bin/env python3
"""canonical-gguf.py — the executable form of the GGUF realization's
canonical-form specification.

Reads a GGUF v3 file, applies the canonicalization rules implemented by
`crates/uor-addr/src/gguf/value.rs`, and emits the κ-label (SHA-256 of
the canonical two-level commitment). The κ-label is byte-identical to
the Rust crate's `uor_addr::gguf::address` output — this script is the
spec attestation the CL-GGUF / CN-GGUF conformance vectors check against.

Stdlib-only (hashlib, struct) so it runs without `gguf-py`; the canonical
commitment is the realization's own discipline, applied directly over the
GGUF wire bytes.

Usage:
    python3 canonical-gguf.py MODEL.gguf            # prints the κ-label
    python3 canonical-gguf.py --commitment MODEL.gguf   # hex of the 96-byte commitment
"""
import hashlib
import struct
import sys

GGUF_MAGIC = 0x46554747
GGUF_VERSION = 3
DEFAULT_ALIGNMENT = 32

# GGML metadata value type tags.
T_UINT8, T_INT8, T_UINT16, T_INT16, T_UINT32, T_INT32 = 0, 1, 2, 3, 4, 5
T_FLOAT32, T_BOOL, T_STRING, T_ARRAY, T_UINT64, T_INT64, T_FLOAT64 = 6, 7, 8, 9, 10, 11, 12
SCALAR_WIDTH = {T_UINT8: 1, T_INT8: 1, T_BOOL: 1, T_UINT16: 2, T_INT16: 2,
                T_UINT32: 4, T_INT32: 4, T_FLOAT32: 4, T_UINT64: 8, T_INT64: 8, T_FLOAT64: 8}

# GGML block geometry (bytes, elems) mirroring prism::tensor::dtype /
# ggml-common.h. GGML_HALF=2, GGML_FLOAT=4, QK_K=256, K_SCALE_SIZE=12.
GGML = {
    0: (4, 1), 1: (2, 1),                      # F32, F16
    2: (18, 32), 3: (20, 32),                  # Q4_0, Q4_1
    6: (22, 32), 7: (24, 32),                  # Q5_0, Q5_1
    8: (34, 32), 9: (36, 32),                  # Q8_0, Q8_1
    10: (84, 256), 11: (110, 256), 12: (144, 256),   # Q2_K, Q3_K, Q4_K
    13: (176, 256), 14: (210, 256), 15: (292, 256),  # Q5_K, Q6_K, Q8_K
    16: (66, 256), 17: (74, 256), 18: (98, 256),     # IQ2_XXS, IQ2_XS, IQ3_XXS
    19: (50, 256), 20: (18, 32), 21: (110, 256),     # IQ1_S, IQ4_NL, IQ3_S
    22: (82, 256), 23: (136, 256),                   # IQ2_S, IQ4_XS
    24: (1, 1), 25: (2, 1), 26: (4, 1), 27: (8, 1),  # I8, I16, I32, I64
    28: (8, 1), 29: (56, 256), 30: (2, 1),           # F64, IQ1_M, BF16
}


def sha256(b):
    return hashlib.sha256(b).digest()


def align_up(o, a):
    r = o % a
    return o if r == 0 else o + (a - r)


class Cur:
    def __init__(self, buf):
        self.b, self.p = buf, 0

    def take(self, n):
        if self.p + n > len(self.b):
            raise ValueError("truncated")
        s = self.b[self.p:self.p + n]
        self.p += n
        return s

    def u32(self):
        return struct.unpack_from("<I", self.take(4))[0]

    def u64(self):
        return struct.unpack_from("<Q", self.take(8))[0]


def measure_value(c, type_tag):
    """Advance past a metadata value; return its wire byte span."""
    start = c.p
    if type_tag in SCALAR_WIDTH:
        c.take(SCALAR_WIDTH[type_tag])
    elif type_tag == T_STRING:
        c.take(c.u64())
    elif type_tag == T_ARRAY:
        elem = c.u32()
        n = c.u64()
        for _ in range(n):
            measure_value(c, elem)
    else:
        raise ValueError(f"unknown type tag {type_tag}")
    return c.p - start


def canonical_value(raw, off, span, type_tag):
    payload = raw[off:off + span]
    if type_tag in SCALAR_WIDTH:
        return payload
    if type_tag == T_STRING:
        ln = struct.unpack_from("<Q", payload, 0)[0]
        return struct.pack("<Q", ln) + sha256(payload[8:])
    if type_tag == T_ARRAY:
        elem = struct.unpack_from("<I", payload, 0)[0]
        ln = struct.unpack_from("<Q", payload, 4)[0]
        return struct.pack("<I", elem) + struct.pack("<Q", ln) + sha256(payload[12:])
    raise ValueError("unknown type tag")


def commitment(raw):
    c = Cur(raw)
    if c.u32() != GGUF_MAGIC:
        raise ValueError("bad magic")
    if c.u32() != GGUF_VERSION:
        raise ValueError("unsupported version")
    tensor_count = c.u64()
    kv_count = c.u64()

    kvs = []
    alignment = DEFAULT_ALIGNMENT
    for _ in range(kv_count):
        key_len = c.u64()
        key_off = c.p
        key = c.take(key_len)
        type_tag = c.u32()
        val_off = c.p
        span = measure_value(c, type_tag)
        if key == b"general.alignment" and type_tag == T_UINT32:
            alignment = struct.unpack_from("<I", raw, val_off)[0]
        kvs.append((key, type_tag, val_off, span))

    tensors = []
    for _ in range(tensor_count):
        name = c.take(c.u64())
        n_dims = c.u32()
        dims = [c.u64() for _ in range(n_dims)]
        type_id = c.u32()
        offset = c.u64()
        nelem = 1
        for d in dims:
            nelem *= d
        bb, be = GGML[type_id]
        if nelem % be != 0:
            raise ValueError("bad tensor element count")
        data_bytes = (nelem // be) * bb
        tensors.append((name, dims, type_id, offset, data_bytes))

    data_start = align_up(c.p, alignment)

    # metadata_root
    mh = hashlib.sha256()
    for key, type_tag, val_off, span in sorted(kvs, key=lambda e: e[0]):
        mh.update(sha256(key))
        mh.update(struct.pack("<I", type_tag))
        mh.update(canonical_value(raw, val_off, span, type_tag))
    metadata_root = mh.digest()

    # tensor_root
    th = hashlib.sha256()
    canonical_offset = 0
    for name, dims, type_id, offset, data_bytes in sorted(tensors, key=lambda t: t[0]):
        th.update(sha256(name))
        th.update(struct.pack("<I", len(dims)))
        for d in dims:
            th.update(struct.pack("<Q", d))
        th.update(struct.pack("<I", type_id))
        th.update(struct.pack("<Q", canonical_offset))
        start = data_start + offset
        th.update(sha256(raw[start:start + data_bytes]))
        canonical_offset = align_up(canonical_offset + data_bytes, alignment)
    tensor_root = th.digest()

    return (struct.pack("<IIQQQ", GGUF_MAGIC, GGUF_VERSION, tensor_count, kv_count, alignment)
            + metadata_root + tensor_root)


def kappa_label(raw):
    return "sha256:" + sha256(commitment(raw)).hex()


def main(argv):
    args = [a for a in argv[1:] if not a.startswith("--")]
    flags = {a for a in argv[1:] if a.startswith("--")}
    if len(args) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    raw = open(args[0], "rb").read()
    if "--commitment" in flags:
        print(commitment(raw).hex())
    else:
        print(kappa_label(raw))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
