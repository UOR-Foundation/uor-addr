"""blake3_ref.py: BLAKE3 for the canonical-form specs, with a hashlib-style API.

The canonical forms' leaves and default κ-labels are BLAKE3, and Python's
standard library has none. `new()` returns the official implementation (the
`blake3` package, Rust bindings to the reference crate) when it is installed,
because a real model's tensors are gigabytes. Without it, `new()` returns the
pure-Python port below, so every spec still runs on the standard library alone.

The port follows BLAKE3's `reference_impl.py` (CC0 / Apache-2.0,
https://github.com/BLAKE3-team/BLAKE3), hash mode only, 32-byte output. It is
slow: use it for fixtures, not models. `python3 blake3_ref.py --check`
compares it with the official package on inputs that cross chunk boundaries.
"""
import struct

OUT_LEN = 32
BLOCK_LEN = 64
CHUNK_LEN = 1024
CHUNK_START = 1 << 0
CHUNK_END = 1 << 1
PARENT = 1 << 2
ROOT = 1 << 3
IV = (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
      0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)
MSG_PERMUTATION = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)
M32 = 0xFFFFFFFF


def _g(s, a, b, c, d, mx, my):
    s[a] = (s[a] + s[b] + mx) & M32
    x = s[d] ^ s[a]
    s[d] = ((x >> 16) | (x << 16)) & M32
    s[c] = (s[c] + s[d]) & M32
    x = s[b] ^ s[c]
    s[b] = ((x >> 12) | (x << 20)) & M32
    s[a] = (s[a] + s[b] + my) & M32
    x = s[d] ^ s[a]
    s[d] = ((x >> 8) | (x << 24)) & M32
    s[c] = (s[c] + s[d]) & M32
    x = s[b] ^ s[c]
    s[b] = ((x >> 7) | (x << 25)) & M32


def _compress(cv, m, counter, block_len, flags):
    s = [cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7],
         IV[0], IV[1], IV[2], IV[3],
         counter & M32, (counter >> 32) & M32, block_len, flags]
    m = list(m)
    for r in range(7):
        _g(s, 0, 4, 8, 12, m[0], m[1])
        _g(s, 1, 5, 9, 13, m[2], m[3])
        _g(s, 2, 6, 10, 14, m[4], m[5])
        _g(s, 3, 7, 11, 15, m[6], m[7])
        _g(s, 0, 5, 10, 15, m[8], m[9])
        _g(s, 1, 6, 11, 12, m[10], m[11])
        _g(s, 2, 7, 8, 13, m[12], m[13])
        _g(s, 3, 4, 9, 14, m[14], m[15])
        if r < 6:
            m = [m[i] for i in MSG_PERMUTATION]
    for i in range(8):
        s[i] ^= s[i + 8]
        s[i + 8] ^= cv[i]
    return s


def _words(block):
    return struct.unpack("<16I", bytes(block).ljust(BLOCK_LEN, b"\0"))


class _Output:
    def __init__(self, cv, block_words, counter, block_len, flags):
        self.cv, self.m, self.counter, self.block_len, self.flags = cv, block_words, counter, block_len, flags

    def chaining_value(self):
        return _compress(self.cv, self.m, self.counter, self.block_len, self.flags)[:8]

    def root_bytes(self):
        words = _compress(self.cv, self.m, 0, self.block_len, self.flags | ROOT)
        return struct.pack("<16I", *words)[:OUT_LEN]


class _Chunk:
    def __init__(self, counter):
        self.cv = IV
        self.counter = counter
        self.block = bytearray()
        self.blocks_compressed = 0

    def length(self):
        return BLOCK_LEN * self.blocks_compressed + len(self.block)

    def _start(self):
        return CHUNK_START if self.blocks_compressed == 0 else 0

    def update(self, data):
        at = 0
        while at < len(data):
            if len(self.block) == BLOCK_LEN:
                self.cv = _compress(self.cv, _words(self.block), self.counter, BLOCK_LEN, self._start())[:8]
                self.blocks_compressed += 1
                self.block = bytearray()
            take = min(BLOCK_LEN - len(self.block), len(data) - at)
            self.block += data[at:at + take]
            at += take

    def output(self):
        return _Output(self.cv, _words(self.block), self.counter, len(self.block), self._start() | CHUNK_END)


def _parent(left, right):
    return _Output(IV, tuple(left) + tuple(right), 0, BLOCK_LEN, PARENT)


class Blake3Reference:
    """hashlib-style BLAKE3 in pure Python."""

    name = "blake3"
    digest_size = OUT_LEN

    def __init__(self, data=b""):
        self._chunk = _Chunk(0)
        self._stack = []
        if data:
            self.update(data)

    def update(self, data):
        data = memoryview(bytes(data))
        at = 0
        while at < len(data):
            if self._chunk.length() == CHUNK_LEN:
                cv = self._chunk.output().chaining_value()
                total = self._chunk.counter + 1
                while total & 1 == 0:
                    cv = _parent(self._stack.pop(), cv).chaining_value()
                    total >>= 1
                self._stack.append(cv)
                self._chunk = _Chunk(self._chunk.counter + 1)
            take = min(CHUNK_LEN - self._chunk.length(), len(data) - at)
            self._chunk.update(data[at:at + take])
            at += take
        return self

    def digest(self):
        out = self._chunk.output()
        for cv in reversed(self._stack):
            out = _parent(cv, out.chaining_value())
        return out.root_bytes()

    def hexdigest(self):
        return self.digest().hex()


def new(data=b""):
    """The official implementation when installed, the pure-Python port otherwise."""
    try:
        import blake3 as official
    except ImportError:
        return Blake3Reference(data)
    return official.blake3(data)


def digest(data):
    return new(data).digest()


if __name__ == "__main__":
    import sys

    if sys.argv[1:] != ["--check"]:
        print(__doc__)
        sys.exit(2)
    import blake3 as official

    for n in (0, 1, 63, 64, 65, 1023, 1024, 1025, 2048, 2049, 3072, 3073, 4096, 4097, 8192, 8193, 31744, 102400):
        data = bytes(i % 251 for i in range(n))
        ours, theirs = Blake3Reference(data).hexdigest(), official.blake3(data).hexdigest()
        split = Blake3Reference(data[: n // 3]).update(data[n // 3:]).hexdigest()
        if not (ours == theirs == split):
            sys.exit(f"{n} bytes: reference {ours}, split {split}, official {theirs}")
    print("blake3_ref agrees with the official implementation on 18 lengths, whole and split")
