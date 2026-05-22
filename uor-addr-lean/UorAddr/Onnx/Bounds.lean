/-!
# ONNX `OnnxHostBounds` — the application-policy bound surface.

Mirrors `crates/uor-addr/src/onnx/shapes/bounds.rs`.
-/
namespace UorAddr.Onnx

/-- The ONNX-specific typed-input ceilings an application declares. -/
structure OnnxHostBounds where
  graphNodeCountMax     : Nat
  initializerCountMax   : Nat
  nodeInputCountMax     : Nat
  nodeOutputCountMax    : Nat
  nodeAttributeCountMax : Nat
  subgraphDepthMax      : Nat
  tensorRankMax         : Nat
  opsetVersionMin       : Int

end UorAddr.Onnx
