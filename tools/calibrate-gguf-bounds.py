#!/usr/bin/env python3
"""calibrate-gguf-bounds.py — report the minimum `GgufHostBounds` an
application must declare to admit a given GGUF v3 model.

Operational helper (not a spec attestation): walks the file's structure
and prints the per-constant maxima, plus a ready-to-paste
`impl GgufHostBounds` snippet. No bound is invented — each is the
observed extent of the input.

Usage:
    python3 calibrate-gguf-bounds.py MODEL.gguf
"""
import struct
import sys

SCALAR_WIDTH = {0: 1, 1: 1, 7: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 10: 8, 11: 8, 12: 8}
T_STRING, T_ARRAY = 8, 9
GGML = {0: (4, 1), 1: (2, 1), 2: (18, 32), 3: (20, 32), 6: (22, 32), 7: (24, 32),
        8: (34, 32), 9: (36, 32), 10: (84, 256), 11: (110, 256), 12: (144, 256),
        13: (176, 256), 14: (210, 256), 15: (292, 256), 16: (66, 256), 17: (74, 256),
        18: (98, 256), 19: (50, 256), 20: (18, 32), 21: (110, 256), 22: (82, 256),
        23: (136, 256), 24: (1, 1), 25: (2, 1), 26: (4, 1), 27: (8, 1), 28: (8, 1),
        29: (56, 256), 30: (2, 1)}


class C:
    def __init__(s, b): s.b, s.p = b, 0
    def take(s, n):
        r = s.b[s.p:s.p + n]; s.p += n; return r
    def u32(s): return struct.unpack_from("<I", s.take(4))[0]
    def u64(s): return struct.unpack_from("<Q", s.take(8))[0]


def measure(c, t, depth, out):
    out["array_depth"] = max(out["array_depth"], depth)
    if t in SCALAR_WIDTH:
        c.take(SCALAR_WIDTH[t])
    elif t == T_STRING:
        n = c.u64(); out["string_bytes"] = max(out["string_bytes"], n); c.take(n)
    elif t == T_ARRAY:
        elem = c.u32(); n = c.u64()
        out["array_len"] = max(out["array_len"], n)
        for _ in range(n):
            measure(c, elem, depth + 1, out)


def calibrate(raw):
    c = C(raw)
    assert c.u32() == 0x46554747, "bad magic"
    assert c.u32() == 3, "version != 3"
    tc, kc = c.u64(), c.u64()
    out = {"kv": kc, "tensors": tc, "key_bytes": 0, "string_bytes": 0,
           "array_len": 0, "array_depth": 0, "data_bytes": 0}
    for _ in range(kc):
        kl = c.u64(); out["key_bytes"] = max(out["key_bytes"], kl); c.take(kl)
        measure(c, c.u32(), 1, out)
    for _ in range(tc):
        c.take(c.u64())  # name
        nd = c.u32(); dims = [c.u64() for _ in range(nd)]
        tid = c.u32(); c.u64()
        ne = 1
        for d in dims:
            ne *= d
        bb, be = GGML[tid]
        out["data_bytes"] += (ne // be) * bb
    return out


def main(argv):
    if len(argv) != 2:
        print(__doc__, file=sys.stderr); return 2
    o = calibrate(open(argv[1], "rb").read())
    print(f"GGUF_METADATA_KV_COUNT_MAX    >= {o['kv']}")
    print(f"GGUF_TENSOR_COUNT_MAX         >= {o['tensors']}")
    print(f"GGUF_METADATA_KEY_BYTES_MAX   >= {o['key_bytes']}")
    print(f"GGUF_STRING_BYTES_MAX         >= {o['string_bytes']}")
    print(f"GGUF_METADATA_ARRAY_LEN_MAX   >= {o['array_len']}")
    print(f"GGUF_METADATA_ARRAY_DEPTH_MAX >= {o['array_depth']}")
    print(f"GGUF_TENSOR_DATA_BYTES_MAX    >= {o['data_bytes']}")
    print("\n// Paste into your application source, citing this model:")
    print("impl GgufHostBounds for MyBounds {")
    print(f"    const GGUF_METADATA_KV_COUNT_MAX: usize = {o['kv']};")
    print(f"    const GGUF_TENSOR_COUNT_MAX: usize = {o['tensors']};")
    print(f"    const GGUF_METADATA_KEY_BYTES_MAX: usize = {o['key_bytes']};")
    print(f"    const GGUF_STRING_BYTES_MAX: usize = {o['string_bytes']};")
    print(f"    const GGUF_METADATA_ARRAY_LEN_MAX: usize = {o['array_len']};")
    print(f"    const GGUF_METADATA_ARRAY_DEPTH_MAX: usize = {o['array_depth']};")
    print(f"    const GGUF_TENSOR_DATA_BYTES_MAX: u64 = {o['data_bytes']};")
    print("}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
