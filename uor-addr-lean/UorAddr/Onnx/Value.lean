/-!
# ONNX typed input + canonical commitment byte form.

The realization reduces a `ModelProto` to a fixed-width commitment
(`LE_i64(ir_version) ‖ opset_root ‖ graph_root ‖ model_meta_root`); see
`crates/uor-addr/src/onnx/value.rs`.
-/
namespace UorAddr.Onnx

/-- The canonical commitment the ψ-pipeline hashes. -/
abbrev Commitment := List UInt8

end UorAddr.Onnx
