/-!
# GGUF `GgufHostBounds` — the application-policy bound surface.

Mirrors `crates/uor-addr/src/gguf/shapes/bounds.rs`. The GGUF spec sets
no ceiling on KV / tensor / string / array extents, so every bound is
application policy. Modelled here as a record of `Nat` ceilings.
-/
namespace UorAddr.Gguf

/-- The GGUF-specific typed-input ceilings an application declares. -/
structure GgufHostBounds where
  metadataKvCountMax     : Nat
  tensorCountMax         : Nat
  metadataKeyBytesMax    : Nat
  stringBytesMax         : Nat
  metadataArrayLenMax    : Nat
  metadataArrayDepthMax  : Nat
  tensorDataBytesMax     : Nat

end UorAddr.Gguf
