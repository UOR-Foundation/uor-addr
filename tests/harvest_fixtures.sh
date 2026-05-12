#!/usr/bin/env bash
# Harvest known-good content-address fixtures from the canonical UOR Foundation
# reference endpoint (mcp.uor.foundation/mcp).
#
# Run this when:
#   - Adding new fixture inputs to cross_validation.rs
#   - Re-verifying that vendored fixtures still match the live spec
#   - The UOR Foundation publishes a new canonicalization version
#
# Usage:
#   bash tests/harvest_fixtures.sh
#
# Output is human-readable; copy/paste relevant entries into the `fixtures()`
# function in tests/cross_validation.rs.

set -euo pipefail

ENDPOINT="https://mcp.uor.foundation/mcp"
TMP_HEADERS=$(mktemp)
trap 'rm -f "$TMP_HEADERS"' EXIT

# Step 1 — initialize the MCP session
curl -fsS -X POST "$ENDPOINT" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -D "$TMP_HEADERS" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"uor-addr-1-fixture-harvester","version":"0.1.0"}}}' \
  > /dev/null

SESSION_ID=$(grep -i '^mcp-session-id:' "$TMP_HEADERS" | awk '{print $2}' | tr -d '\r\n')

if [ -z "$SESSION_ID" ]; then
  echo "ERROR: MCP server did not return a session id." >&2
  exit 1
fi
echo "# MCP session: $SESSION_ID"

# Step 2 — send the initialized notification (required before tool calls)
curl -fsS -X POST "$ENDPOINT" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "mcp-session-id: $SESSION_ID" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  > /dev/null || true

# Helper that calls encode_address with the given JSON content and prints the
# address + canonical form in a format ready to paste into Rust fixtures.
call() {
  local label="$1"
  local content_json="$2"
  local body
  body=$(printf '{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"encode_address","arguments":{"content":%s}}}' "$content_json")

  echo ""
  echo "=== $label ==="
  echo "INPUT: $content_json"

  curl -fsS -X POST "$ENDPOINT" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -H "mcp-session-id: $SESSION_ID" \
    -d "$body" \
    | grep '^data: {' \
    | sed 's/^data: //' \
    | python3 -c "
import sys, json
for line in sys.stdin:
    d = json.loads(line)
    texts = d.get('result', {}).get('content', [])
    addr = None
    canon = None
    for t in texts:
        if t.get('type') != 'text': continue
        txt = t.get('text', '')
        if txt.startswith('sha256:') and addr is None:
            addr = txt
        elif txt.startswith('{') and 'canonical_form' in txt:
            meta = json.loads(txt)
            canon = meta.get('canonical_form')
    print(f'  ADDRESS:   {addr}')
    print(f'  CANONICAL: {canon!r}')
"
}

# ----------------------------------------------------------------------------
# Fixture roster — add new cases below as needed.
# ----------------------------------------------------------------------------

call "simple_object"         '{"foo":"bar"}'
call "empty_object"          '{}'
call "empty_array"           '[]'
call "key_sort_test"         '{"b":1,"a":2}'
call "unicode_muller"        '{"name":"Müller"}'
call "unicode_sao_paulo"     '{"city":"São Paulo"}'
call "unicode_cafe_composed" '{"name":"café"}'
# NOTE: bash heredoc can't easily inject combining marks; for decomposed-form
# test cases, edit this script to use printf with \xCC\x81 (UTF-8 of U+0301):
call "unicode_cafe_decomposed" "$(printf '{"name":"cafe\xCC\x81"}')"
call "mixed_types"           '{"int":42,"bool":true,"null_val":null}'
call "nested"                '{"nested":{"deep":{"value":"found"}}}'
call "string_array"          '["a","b","c"]'
call "number_array"          '[1,2,3]'

echo ""
echo "# Done. Copy outputs into tests/cross_validation.rs as needed."
