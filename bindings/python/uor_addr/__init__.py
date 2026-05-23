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
_ERR_TOO_LARGE = -4  # reserved; never returned under ADR-060 (unbounded inputs)
_ERR_PIPELINE = -5

_ERR_KIND: Final[dict[int, str]] = {
    _ERR_INVALID_INPUT: "invalid-input",
    _ERR_TOO_LARGE: "too-large",  # reserved (see above) — kept for forward-compat
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


# ─── Grounded handle wrapper (TC-05 replay across the FFI) ─────────

# Verify-error codes mirror UOR_ADDR_ERR_VERIFY_* in the C header. All
# five map to defensive substrate corruption; unreachable for a handle
# minted via the *_with_witness Python wrappers.
_ERR_VERIFY_KIND: Final[dict[int, str]] = {
    -10: "empty-trace",
    -11: "out-of-order-event",
    -12: "zero-target",
    -13: "non-contiguous-steps",
    -14: "capacity-exceeded",
}


# `*_with_witness` ABI: (input, input_len, out_handle) -> i32
def _bind_with_witness(symbol: str) -> ctypes._NamedFuncPointer:
    fn = getattr(_lib, symbol)
    fn.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),                          # const uint8_t *input
        ctypes.c_size_t,                                          # size_t input_len
        ctypes.POINTER(ctypes.c_void_p),                          # UorAddrGrounded **out_handle
    ]
    fn.restype = ctypes.c_int32
    return fn


_WITH_WITNESS_FUNCS: Final[dict[str, ctypes._NamedFuncPointer]] = {
    "json":                       _bind_with_witness("uor_addr_json_with_witness"),
    "sexp":                       _bind_with_witness("uor_addr_sexp_with_witness"),
    "xml":                        _bind_with_witness("uor_addr_xml_with_witness"),
    "asn1":                       _bind_with_witness("uor_addr_asn1_with_witness"),
    "ring":                       _bind_with_witness("uor_addr_ring_with_witness"),
    "codemodule":                 _bind_with_witness("uor_addr_codemodule_with_witness"),
    "schema_photo":               _bind_with_witness("uor_addr_schema_photo_with_witness"),
    "schema_document":            _bind_with_witness("uor_addr_schema_document_with_witness"),
    "schema_codemodule_signed":   _bind_with_witness("uor_addr_schema_codemodule_signed_with_witness"),
}

# Grounded accessor ABIs.
_lib.uor_addr_grounded_kappa_label.argtypes = [
    ctypes.c_void_p,                  # const UorAddrGrounded *handle
    ctypes.POINTER(ctypes.c_uint8),  # uint8_t *out_label
    ctypes.c_size_t,                  # size_t out_label_len
    ctypes.POINTER(ctypes.c_size_t), # size_t *out_written
]
_lib.uor_addr_grounded_kappa_label.restype = ctypes.c_int32

_lib.uor_addr_grounded_content_fingerprint.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
_lib.uor_addr_grounded_content_fingerprint.restype = ctypes.c_int32

_lib.uor_addr_grounded_verify.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
_lib.uor_addr_grounded_verify.restype = ctypes.c_int32

_lib.uor_addr_grounded_free.argtypes = [ctypes.c_void_p]
_lib.uor_addr_grounded_free.restype = None


class VerifyError(Exception):
    """Raised when `Grounded.verify()` fails.

    The `kind` attribute is one of: `'empty-trace'`,
    `'out-of-order-event'`, `'zero-target'`, `'non-contiguous-steps'`,
    `'capacity-exceeded'` — matching the WIT `verify-error` variant.
    All five are defensive against substrate corruption; unreachable
    for a `Grounded` minted through this binding.
    """

    def __init__(self, kind: str, message: str = "") -> None:
        self.kind = kind
        super().__init__(message or f"uor-addr verify failed: {kind}")


class Grounded:
    """Opaque handle to a Rust-side `Grounded<AddressLabel>` witness.

    Constructed by any of the `kappa.*_address_with_witness` methods.
    Carries the ψ-pipeline's emitted derivation; verifiable through
    [`verify`] without re-invoking SHA-256.

    TC-05 conformance: every `Grounded` produced by a
    `*_address_with_witness` call replays through `verify()` to a
    κ-label byte-identical to the one [`kappa_label`] reports
    (QS-05 replay equivalence — bit-identical round-trip).

    Use as a context manager to deterministically release the
    underlying handle on scope exit; otherwise the handle is freed at
    garbage-collection time via `__del__`.
    """

    __slots__ = ("_handle",)

    def __init__(self, handle: int) -> None:
        # `handle` is a raw integer pointer returned by a C ABI
        # `*_with_witness` call. Must be non-zero on success.
        self._handle: int | None = handle

    def __enter__(self) -> "Grounded":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def __del__(self) -> None:
        # Defensive: free the handle on GC if the caller didn't
        # close() it explicitly.
        self.close()

    def close(self) -> None:
        """Release the underlying handle. After `close()`, further
        method calls raise `RuntimeError`."""
        if self._handle is not None:
            _lib.uor_addr_grounded_free(self._handle)
            self._handle = None

    def _require(self) -> int:
        if self._handle is None:
            raise RuntimeError("Grounded handle has been closed")
        return self._handle

    def kappa_label(self) -> str:
        """Return the 71-byte ASCII κ-label this Grounded carries."""
        handle = self._require()
        out_buf = (ctypes.c_uint8 * ADDRESS_LABEL_BYTES)()
        written = ctypes.c_size_t(0)
        rc = _lib.uor_addr_grounded_kappa_label(
            handle, out_buf, ADDRESS_LABEL_BYTES, ctypes.byref(written)
        )
        if rc != _OK:
            raise AddressError(_ERR_KIND.get(rc, "pipeline-failure"))
        return bytes(out_buf).decode("ascii")

    def content_fingerprint(self) -> bytes:
        """Return the 32-byte SHA-256 content fingerprint."""
        handle = self._require()
        out_buf = (ctypes.c_uint8 * 32)()
        written = ctypes.c_size_t(0)
        rc = _lib.uor_addr_grounded_content_fingerprint(
            handle, out_buf, 32, ctypes.byref(written)
        )
        if rc != _OK:
            raise AddressError(_ERR_KIND.get(rc, "pipeline-failure"))
        return bytes(out_buf)

    def verify(self) -> str:
        """Replay the derivation through `prism_verify::certify_from_trace`
        and return the recovered κ-label. SHA-256 is **not** re-invoked.

        Round-trip equivalence: `g.verify() == g.kappa_label()` byte-for-byte
        (QS-05 / CL-R* in CONFORMANCE.md).
        """
        handle = self._require()
        out_buf = (ctypes.c_uint8 * ADDRESS_LABEL_BYTES)()
        written = ctypes.c_size_t(0)
        rc = _lib.uor_addr_grounded_verify(
            handle, out_buf, ADDRESS_LABEL_BYTES, ctypes.byref(written)
        )
        if rc != _OK:
            if rc in _ERR_VERIFY_KIND:
                raise VerifyError(_ERR_VERIFY_KIND[rc])
            raise AddressError(_ERR_KIND.get(rc, "pipeline-failure"))
        return bytes(out_buf).decode("ascii")


def _mint_with_witness(
    realization: str, data: bytes | bytearray | memoryview
) -> Grounded:
    buf = bytes(data)
    in_ptr = (ctypes.c_uint8 * len(buf)).from_buffer_copy(buf)
    out_handle = ctypes.c_void_p()
    fn = _WITH_WITNESS_FUNCS[realization]
    rc = fn(in_ptr, len(buf), ctypes.byref(out_handle))
    if rc != _OK:
        kind = _ERR_KIND.get(rc, "pipeline-failure")
        raise AddressError(kind)
    if out_handle.value is None:
        raise AddressError(
            "pipeline-failure",
            "C ABI returned OK without writing a handle",
        )
    return Grounded(out_handle.value)


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

    # ─── Witness-bearing entry points (TC-05) ──────────────────────

    def json_address_with_witness(self, data: bytes) -> Grounded:
        """JSON realization; returns a verifiable [`Grounded`] witness."""
        return _mint_with_witness("json", data)

    def sexp_address_with_witness(self, data: bytes) -> Grounded:
        """S-expression realization; returns a verifiable [`Grounded`] witness."""
        return _mint_with_witness("sexp", data)

    def xml_address_with_witness(self, data: bytes) -> Grounded:
        """XML realization; returns a verifiable [`Grounded`] witness."""
        return _mint_with_witness("xml", data)

    def asn1_address_with_witness(self, data: bytes) -> Grounded:
        """ASN.1 realization; returns a verifiable [`Grounded`] witness."""
        return _mint_with_witness("asn1", data)

    def ring_address_with_witness(self, data: bytes) -> Grounded:
        """Ring realization; returns a verifiable [`Grounded`] witness."""
        return _mint_with_witness("ring", data)

    def codemodule_address_with_witness(self, data: bytes) -> Grounded:
        """Code-module realization; returns a verifiable [`Grounded`] witness."""
        return _mint_with_witness("codemodule", data)

    def schema_photo_address_with_witness(self, data: bytes) -> Grounded:
        """schema.org/Photograph; returns a verifiable [`Grounded`] witness."""
        return _mint_with_witness("schema_photo", data)

    def schema_document_address_with_witness(self, data: bytes) -> Grounded:
        """schema.org/Article; returns a verifiable [`Grounded`] witness."""
        return _mint_with_witness("schema_document", data)

    def schema_codemodule_signed_address_with_witness(self, data: bytes) -> Grounded:
        """in-toto Statement v1; returns a verifiable [`Grounded`] witness."""
        return _mint_with_witness("schema_codemodule_signed", data)


# Singleton facade — matches the npm package's `kappa` export shape.
kappa: Final[_Kappa] = _Kappa()


__all__ = [
    "ADDRESS_LABEL_BYTES",
    "AddressError",
    "Grounded",
    "VerifyError",
    "kappa",
]
