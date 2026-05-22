#!/usr/bin/env python3
"""canonical-onnx.py — the executable form of the ONNX realization's
canonical-form specification.

Reads an ONNX `ModelProto`, applies the canonicalization rules
implemented by `crates/uor-addr/src/onnx/value.rs`, and emits the
κ-label (SHA-256 of the protobuf-canonical commitment). Byte-identical
to `uor_addr::onnx::address`. Stdlib-only (a minimal protobuf reader is
inlined) so it runs without the `onnx` Python package; the canonical
commitment is the realization's own discipline.

Usage:
    python3 canonical-onnx.py MODEL.onnx
"""
import hashlib
import struct
import sys

IR_VERSION = 13


def sha256(b):
    return hashlib.sha256(b).digest()


class WireError(ValueError):
    pass


def read_varint(buf, pos):
    # Mirror the Rust MessageReader: cap at 10 bytes, error on truncation.
    result = shift = 0
    start = pos
    while True:
        if pos >= len(buf):
            raise WireError("truncated varint")
        if pos - start >= 10:
            raise WireError("varint overflow")
        b = buf[pos]
        result |= (b & 0x7F) << shift
        pos += 1
        if not (b & 0x80):
            return result, pos
        shift += 7


def fields(body):
    """Yield (number, wire_type, value) for each field, with the same
    strict acceptance criteria as the Rust `MessageReader` (zero field
    number, unknown wire type, truncation, and out-of-range lengths all
    raise) so the recurse-or-fallback decision in `canonical_proto_digest`
    matches the Rust realization exactly. value is int for varint, raw
    little-endian bytes for fixed32/64, bytes for length-delimited."""
    pos = 0
    while pos < len(body):
        tag, pos = read_varint(body, pos)
        num, wt = tag >> 3, tag & 7
        if num == 0:
            raise WireError("zero field number")
        if wt == 0:
            v, pos = read_varint(body, pos)
            yield num, wt, v
        elif wt == 1:
            if pos + 8 > len(body):
                raise WireError("truncated fixed64")
            yield num, wt, body[pos:pos + 8]
            pos += 8
        elif wt == 2:
            ln, pos = read_varint(body, pos)
            if pos + ln > len(body):
                raise WireError("length out of range")
            yield num, wt, body[pos:pos + ln]
            pos += ln
        elif wt == 5:
            if pos + 4 > len(body):
                raise WireError("truncated fixed32")
            yield num, wt, body[pos:pos + 4]
            pos += 4
        else:
            raise WireError(f"bad wire type {wt}")


def canonical_proto_digest(body, depth=0):
    """Field-order-canonical digest of an opaque protobuf message —
    mirrors `canonical_proto_digest` in crates/uor-addr/src/onnx/value.rs.
    Fields are folded in ascending field-number order (stable), recursing
    into length-delimited fields with a raw-bytes fallback on parse
    failure."""
    fs = list(fields(body))            # raises on malformed (caller may fall back)
    fs.sort(key=lambda f: f[0])        # Python sort is stable
    h = hashlib.sha256()
    for num, wt, val in fs:
        h.update(struct.pack("<Q", num))
        h.update(bytes([wt]))
        if wt == 0:
            h.update(struct.pack("<Q", val))
        elif wt in (1, 5):
            h.update(val)              # raw LE bytes == u64/u32 to_le_bytes
        else:
            if depth < 32 and len(val) > 0:
                try:
                    sub = canonical_proto_digest(val, depth + 1)
                except WireError:
                    sub = sha256(val)
            else:
                sub = sha256(val)
            h.update(sub)
    return h.digest()


def first(body, n):
    for num, _, v in fields(body):
        if num == n:
            return v
    return None


def first_bytes(body, n):
    v = first(body, n)
    return v if isinstance(v, (bytes, bytearray)) else b""


def first_varint(body, n, default=0):
    v = first(body, n)
    return v if isinstance(v, int) else default


def each(body, n):
    for num, _, v in fields(body):
        if num == n:
            yield v


# ── tensor data digest ──

# typed-field (#5/#7/#11) varint widths per data_type id.
INT32_WIDTH = {6: 4, 5: 2, 4: 2, 10: 2, 16: 2, 3: 1, 2: 1, 9: 1,
               17: 1, 18: 1, 19: 1, 20: 1, 22: 1, 21: 1, 23: 1}


def fold_packed_varints_i64(h, body, n):
    for v in each(body, n):
        if isinstance(v, (bytes, bytearray)):
            pos = 0
            while pos < len(v):
                val, pos = read_varint(v, pos)
                h.update(struct.pack("<q", val if val < (1 << 63) else val - (1 << 64)))
        elif isinstance(v, int):
            h.update(struct.pack("<q", v if v < (1 << 63) else v - (1 << 64)))


def fold_typed_varints(h, body, n, width):
    for v in each(body, n):
        if isinstance(v, (bytes, bytearray)):
            pos = 0
            while pos < len(v):
                val, pos = read_varint(v, pos)
                h.update(struct.pack("<Q", val)[:width])
        elif isinstance(v, int):
            h.update(struct.pack("<Q", v)[:width])


def fold_fixed_payload(h, body, n):
    for v in each(body, n):
        if isinstance(v, (bytes, bytearray)):
            h.update(v)


def tensor_data_digest(t, dtype):
    # External data (data_location #14 == EXTERNAL): bind the external
    # reference (#13, sorted by key) under a domain tag — mirrors the Rust
    # no_std core, which cannot dereference sibling files.
    if first_varint(t, 14) == 1:
        h = hashlib.sha256()
        h.update(b"onnx:external-data:v1")
        h.update(string_string_root(t, 13))
        return h.digest()
    raw = first(t, 9)
    if isinstance(raw, (bytes, bytearray)) and len(raw) > 0:
        return sha256(raw)
    h = hashlib.sha256()
    if dtype == 1:           # FLOAT
        fold_fixed_payload(h, t, 4)
    elif dtype in (11, 15):  # DOUBLE, COMPLEX128
        fold_fixed_payload(h, t, 10)
    elif dtype == 14:        # COMPLEX64
        fold_fixed_payload(h, t, 4)
    elif dtype == 7:         # INT64
        fold_typed_varints(h, t, 7, 8)
    elif dtype == 13:        # UINT64
        fold_typed_varints(h, t, 11, 8)
    elif dtype == 12:        # UINT32
        fold_typed_varints(h, t, 11, 4)
    elif dtype == 8:         # STRING
        for s in each(t, 6):
            h.update(sha256(s))
    else:                    # int32_data-backed
        fold_typed_varints(h, t, 5, INT32_WIDTH.get(dtype, 4))
    return h.digest()


def count_dims(t):
    n = 0
    for v in each(t, 1):
        if isinstance(v, (bytes, bytearray)):
            pos = 0
            while pos < len(v):
                _, pos = read_varint(v, pos)
                n += 1
        else:
            n += 1
    return n


def tensor_digest(t):
    dtype = first_varint(t, 2)
    if not (1 <= dtype <= 23):
        raise ValueError(f"unknown dtype {dtype}")
    h = hashlib.sha256()
    h.update(sha256(first_bytes(t, 8)))         # name
    h.update(struct.pack("<i", dtype))
    h.update(struct.pack("<I", count_dims(t)))  # rank
    fold_packed_varints_i64(h, t, 1)            # dims
    h.update(tensor_data_digest(t, dtype))
    return h.digest()


def attribute_value_digest(a, atype, depth):
    h = hashlib.sha256()
    if atype == 1:           # FLOAT (fixed32)
        v = first(a, 2)
        if isinstance(v, (bytes, bytearray)):
            h.update(v)
    elif atype == 2:         # INT
        h.update(struct.pack("<q", first_varint(a, 3)))
    elif atype == 3:         # STRING
        h.update(sha256(first_bytes(a, 4)))
    elif atype == 4:         # TENSOR
        h.update(tensor_digest(first_bytes(a, 5)))
    elif atype == 5:         # GRAPH
        h.update(canonical_graph(first_bytes(a, 6), depth + 1))
    elif atype == 6:         # FLOATS
        for v in each(a, 7):
            h.update(sha256(v) if isinstance(v, (bytes, bytearray)) else v)
    elif atype == 7:         # INTS
        fold_packed_varints_i64(h, a, 8)
    elif atype == 8:         # STRINGS
        for s in each(a, 9):
            h.update(sha256(s))
    elif atype == 9:         # TENSORS
        for tb in each(a, 10):
            h.update(tensor_digest(tb))
    elif atype == 10:        # GRAPHS
        for g in each(a, 11):
            h.update(canonical_graph(g, depth + 1))
    elif atype == 11:        # SPARSE_TENSOR
        h.update(canonical_proto_digest(first_bytes(a, 22)))
    elif atype == 12:        # SPARSE_TENSORS
        for s in each(a, 23):
            h.update(canonical_proto_digest(s))
    elif atype == 13:        # TYPE_PROTO
        h.update(canonical_proto_digest(first_bytes(a, 14)))
    elif atype == 14:        # TYPE_PROTOS
        for s in each(a, 15):
            h.update(canonical_proto_digest(s))
    return h.digest()


def attribute_root(node):
    attrs = list(each(node, 5))
    attrs.sort(key=lambda a: first_bytes(a, 1))
    h = hashlib.sha256()
    for a in attrs:
        h.update(sha256(first_bytes(a, 1)))
        atype = first_varint(a, 20)
        h.update(struct.pack("<i", atype))
        h.update(attribute_value_digest(a, atype, 0))
    return h.digest()


def node_commitment(node):
    h = hashlib.sha256()
    h.update(sha256(first_bytes(node, 3)))   # name
    h.update(sha256(first_bytes(node, 4)))   # op_type
    h.update(sha256(first_bytes(node, 7)))   # domain
    h.update(sha256(first_bytes(node, 8)))   # overload
    ins = list(each(node, 1))
    h.update(struct.pack("<I", len(ins)))
    for i in ins:
        h.update(sha256(i))
    outs = list(each(node, 2))
    h.update(struct.pack("<I", len(outs)))
    for o in outs:
        h.update(sha256(o))
    h.update(attribute_root(node))
    return h.digest()


def topo_order(nodes):
    producers = {}
    for idx, n in enumerate(nodes):
        for o in each(n, 2):
            producers.setdefault(bytes(o), idx)
    emitted = [False] * len(nodes)
    order = []
    for _ in range(len(nodes)):
        best = None
        for cand, n in enumerate(nodes):
            if emitted[cand]:
                continue
            ready = True
            for i in each(n, 1):
                p = producers.get(bytes(i))
                if p is not None and not emitted[p]:
                    ready = False
                    break
            if not ready:
                continue
            key = (first_bytes(n, 3), first_bytes(n, 4), first_bytes(n, 7))
            if best is None or key < best[1]:
                best = (cand, key)
        if best is None:
            raise ValueError("graph cycle")
        emitted[best[0]] = True
        order.append(best[0])
    return [nodes[i] for i in order]


def string_string_root(body, n):
    entries = list(each(body, n))
    entries.sort(key=lambda e: first_bytes(e, 1))
    h = hashlib.sha256()
    for e in entries:
        h.update(sha256(first_bytes(e, 1)))
        h.update(sha256(first_bytes(e, 2)))
    return h.digest()


def value_info_root(graph, n):
    vis = list(each(graph, n))
    vis.sort(key=lambda v: first_bytes(v, 1))
    h = hashlib.sha256()
    for v in vis:
        h.update(sha256(first_bytes(v, 1)))
        h.update(canonical_proto_digest(first_bytes(v, 2)))
    return h.digest()


def canonical_graph(graph, depth):
    h = hashlib.sha256()
    h.update(sha256(first_bytes(graph, 2)))           # name
    for n in topo_order(list(each(graph, 1))):        # nodes (topo)
        h.update(node_commitment(n))
    inits = list(each(graph, 5))                      # initializers
    inits.sort(key=lambda t: first_bytes(t, 8))
    th = hashlib.sha256()
    for t in inits:
        th.update(tensor_digest(t))
    h.update(th.digest())
    h.update(value_info_root(graph, 11))
    h.update(value_info_root(graph, 12))
    h.update(value_info_root(graph, 13))
    return h.digest()


def opset_root(model):
    entries = list(each(model, 8))
    entries.sort(key=lambda e: (first_bytes(e, 1), first_varint(e, 2)))
    h = hashlib.sha256()
    for e in entries:
        h.update(sha256(first_bytes(e, 1)))
        h.update(struct.pack("<q", first_varint(e, 2)))
    return h.digest()


def model_meta_root(model):
    h = hashlib.sha256()
    h.update(sha256(first_bytes(model, 2)))
    h.update(sha256(first_bytes(model, 3)))
    h.update(sha256(first_bytes(model, 4)))
    h.update(struct.pack("<q", first_varint(model, 5)))
    h.update(string_string_root(model, 14))
    return h.digest()


def commitment(model):
    ir = first_varint(model, 1)
    if ir != IR_VERSION:
        raise ValueError(f"unsupported IR version {ir}")
    graph = first_bytes(model, 7)
    if not graph:
        raise ValueError("missing graph")
    return (struct.pack("<q", ir) + opset_root(model)
            + canonical_graph(graph, 0) + model_meta_root(model))


def kappa_label(model):
    return "sha256:" + sha256(commitment(model)).hex()


def main(argv):
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    print(kappa_label(open(argv[1], "rb").read()))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
