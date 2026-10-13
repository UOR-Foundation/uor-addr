"""Duplicate JSON member names are rejected through the Python binding.

Pinned invariant (mirrors CT-B05 on the Rust side and
`rejects_duplicate_member_names` on the C side):

- **PY-JSON-01**: an object that repeats a member name raises
  `AddressError` with kind `'invalid-input'`, including names that only
  become equal after escape decoding or NFC normalization, at any depth.
- **PY-JSON-02**: the same name in sibling objects is still admitted.

Run with `python -m pytest bindings/python/tests/` (the bundled
`libuor_addr_c.so` must be current — see the release workflow / the
local `cargo build -p uor-addr-c --release` + copy step).
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from uor_addr import AddressError, kappa  # noqa: E402

DUPLICATES = [
    pytest.param(b'{"a":1,"a":2}', id="plain"),
    pytest.param('{"café":1,"café":2}'.encode("utf-8"), id="nfc_equivalent"),
    pytest.param(b'{"a":1,"\\u0061":2}', id="escape_spelled"),
    pytest.param(b'{"outer":{"x":1,"x":2}}', id="nested"),
]


@pytest.mark.parametrize("raw", DUPLICATES)
def test_py_json_01_duplicate_member_names_rejected(raw):
    with pytest.raises(AddressError) as excinfo:
        kappa.json_address(raw)
    assert excinfo.value.kind == "invalid-input"


def test_py_json_02_sibling_objects_may_share_names():
    label = kappa.json_address(b'{"x":{"a":1},"y":{"a":2}}')
    assert label.startswith("sha256:")
