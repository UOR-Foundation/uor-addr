"""JSON object members sort by UTF-16 code units through the Python binding.

Pinned invariant (mirrors CT-E05 on the Rust side and
`json_members_sort_by_utf16_code_units` on the C side):

- **PY-JSON-03**: members are ordered by the UTF-16 code units of their
  names (RFC 8785 section 3.2.3), at any depth. A name starting in
  U+E000..U+FFFF sorts after an astral-plane name, so both input orders of
  `{"\uff11":1,"\U0001d400":2}` mint the label of the canonical bytes
  `{"\U0001d400":2,"\uff11":1}`.

Run with `python -m pytest bindings/python/tests/` (the bundled
`libuor_addr_c.so` must be current, see the release workflow / the
local `cargo build -p uor-addr-c --release` + copy step).
"""

import hashlib
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from uor_addr import kappa  # noqa: E402

CASES = [
    pytest.param(
        '{"\uff11":1,"\U0001d400":2}',
        '{"\U0001d400":2,"\uff11":1}',
        "sha256:05c7d52a4d1707689b620f9672547238ad89696481cd125cf838266fb86a6c69",
        id="flat",
    ),
    pytest.param(
        '{"outer":{"\uff11":1,"\U0001d400":2}}',
        '{"outer":{"\U0001d400":2,"\uff11":1}}',
        "sha256:8c5a8c983233c60a5d2f078ecd92c1671b90b2f812285eb3e3b995a6b550b261",
        id="nested",
    ),
]


@pytest.mark.parametrize("raw, canonical, label", CASES)
def test_py_json_03_members_sort_by_utf16_code_units(raw, canonical, label):
    assert label == "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert kappa.json_address(raw.encode("utf-8")) == label
    assert kappa.json_address(canonical.encode("utf-8")) == label
