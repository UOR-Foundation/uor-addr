"""uor-addr — typed content-addressing Python bindings.

Wraps the `uor-addr-c` C ABI dynamic library via `ctypes` (stdlib).
The bundled native library (`libuor_addr_c.so` on Linux,
`libuor_addr_c.dylib` on macOS, `uor_addr_c.dll` on Windows) is
included in the wheel for each supported platform. The produced
κ-label is byte-for-byte identical to the Rust crate's output
(cross-validation pinned by CF-C* in CONFORMANCE.md).

>>> from uor_addr import kappa
>>> kappa.json_address(b'{"foo":"bar"}')
'sha256:7a38bf81f383f69433ad6e900d35b3e2385593f76a7b7ab5d4355b8ba41ee24b'

Why C ABI rather than wasm? wasmtime-py's Component Model API is not
yet stable as of wasmtime 24.x; once it lands, a follow-on release
can pivot to the WASM Component Model artifact this repository also
publishes.
"""

from __future__ import annotations

import ctypes
import importlib.resources
import platform
import sys
from typing import Final


class AddressError(Exception):
    """Raised when a realization's address function fails.

    Maps the C ABI return codes to one of three kinds:

    - `'invalid-input'` — input failed the realization's host-boundary
      parser (e.g. malformed JSON, non-DER ASN.1, schema admission
      mismatch).
    - `'too-large'` — input exceeded a typed-input ceiling (depth,
      width, container arity).
    - `'pipeline-failure'` — defensive substrate-level failure;
      unreachable on well-formed input.
    """

    def __init__(self, kind: str, message: str = "") -> None:
        self.kind = kind
        super().__init__(message or f"uor-addr address failed: {kind}")


# Wire-format width: len("sha256:") + 64-byte lowercase-hex digest.
ADDRESS_LABEL_BYTES: Final[int] = 71

# C ABI return codes (mirror UOR_ADDR_* in uor_addr.h).
_OK = 0
_ERR_NULL_POINTER = -1
_ERR_BUFFER_TOO_SMALL = -2
_ERR_INVALID_INPUT = -3
_ERR_TOO_LARGE = -4
_ERR_PIPELINE = -5

_ERR_KIND: Final[dict[int, str]] = {
    _ERR_INVALID_INPUT: "invalid-input",
    _ERR_TOO_LARGE: "too-large",
    _ERR_PIPELINE: "pipeline-failure",
    _ERR_NULL_POINTER: "pipeline-failure",
    _ERR_BUFFER_TOO_SMALL: "pipeline-failure",
}


def _libname() -> str:
    """Resolve the bundled C ABI library filename for the current OS."""
    system = sys.platform
    if system.startswith("linux"):
        return "libuor_addr_c.so"
    if system == "darwin":
        return "libuor_addr_c.dylib"
    if system in ("win32", "cygwin"):
        return "uor_addr_c.dll"
    raise OSError(f"unsupported platform for uor-addr: {system} {platform.machine()}")


def _load_lib() -> ctypes.CDLL:
    """Locate + load the bundled native library."""
    lib_path = importlib.resources.files(__package__).joinpath(_libname())
    with importlib.resources.as_file(lib_path) as path:
        return ctypes.CDLL(str(path))


# Bind once at import time; subsequent calls reuse the same library
# handle and the same function-pointer bindings.
_lib = _load_lib()


def _bind(symbol: str) -> ctypes._NamedFuncPointer:
    """Bind one `uor_addr_*` C function with its argtypes / restype."""
    fn = getattr(_lib, symbol)
    fn.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),  # const uint8_t *input
        ctypes.c_size_t,                  # size_t input_len
        ctypes.POINTER(ctypes.c_uint8),  # uint8_t *out_label
        ctypes.c_size_t,                  # size_t out_label_len
        ctypes.POINTER(ctypes.c_size_t), # size_t *out_written
    ]
    fn.restype = ctypes.c_int32
    return fn


_FUNCS: Final[dict[str, ctypes._NamedFuncPointer]] = {
    "json_address":                       _bind("uor_addr_json"),
    "sexp_address":                       _bind("uor_addr_sexp"),
    "xml_address":                        _bind("uor_addr_xml"),
    "asn1_address":                       _bind("uor_addr_asn1"),
    "ring_address":                       _bind("uor_addr_ring"),
    "codemodule_address":                 _bind("uor_addr_codemodule"),
    "schema_photo_address":               _bind("uor_addr_schema_photo"),
    "schema_document_address":            _bind("uor_addr_schema_document"),
    "schema_codemodule_signed_address":   _bind("uor_addr_schema_codemodule_signed"),
}


def _call(fn: ctypes._NamedFuncPointer, data: bytes | bytearray | memoryview) -> str:
    buf = bytes(data)
    in_ptr = (ctypes.c_uint8 * len(buf)).from_buffer_copy(buf)
    out_buf = (ctypes.c_uint8 * ADDRESS_LABEL_BYTES)()
    written = ctypes.c_size_t(0)
    rc = fn(in_ptr, len(buf), out_buf, ADDRESS_LABEL_BYTES, ctypes.byref(written))
    if rc != _OK:
        kind = _ERR_KIND.get(rc, "pipeline-failure")
        raise AddressError(kind)
    if written.value != ADDRESS_LABEL_BYTES:
        raise AddressError(
            "pipeline-failure",
            f"C ABI wrote {written.value} bytes, expected {ADDRESS_LABEL_BYTES}",
        )
    return bytes(out_buf).decode("ascii")


class _Kappa:
    """Bound facade exposing the C ABI realization functions."""

    def json_address(self, data: bytes) -> str:
        """RFC 8259 JSON under RFC 8785 JCS + Unicode NFC + SHA-256."""
        return _call(_FUNCS["json_address"], data)

    def sexp_address(self, data: bytes) -> str:
        """Rivest 1997 canonical S-expressions + SHA-256."""
        return _call(_FUNCS["sexp_address"], data)

    def xml_address(self, data: bytes) -> str:
        """W3C XML-C14N 1.1 (subset) + SHA-256."""
        return _call(_FUNCS["xml_address"], data)

    def asn1_address(self, data: bytes) -> str:
        """ITU-T X.690 DER + SHA-256."""
        return _call(_FUNCS["asn1_address"], data)

    def ring_address(self, data: bytes) -> str:
        """UOR-Framework Amendment 43 §2 ring elements + SHA-256."""
        return _call(_FUNCS["ring_address"], data)

    def codemodule_address(self, data: bytes) -> str:
        """CCMAS canonical AST + SHA-256."""
        return _call(_FUNCS["codemodule_address"], data)

    def schema_photo_address(self, data: bytes) -> str:
        """schema.org/Photograph admission + JSON canonicalization."""
        return _call(_FUNCS["schema_photo_address"], data)

    def schema_document_address(self, data: bytes) -> str:
        """schema.org/Article admission + JSON canonicalization."""
        return _call(_FUNCS["schema_document_address"], data)

    def schema_codemodule_signed_address(self, data: bytes) -> str:
        """in-toto Statement v1 admission + JSON canonicalization."""
        return _call(_FUNCS["schema_codemodule_signed_address"], data)


# Singleton facade — matches the npm package's `kappa` export shape.
kappa: Final[_Kappa] = _Kappa()


__all__ = [
    "ADDRESS_LABEL_BYTES",
    "AddressError",
    "kappa",
]
