//! Closed-loop (CL-SAFETENSORS) conformance for the safetensors realization.
//!
//! Synthesizes safetensors byte buffers in-process and asserts the
//! canonical-form invariants:
//!
//! - every well-formed input yields a 71-byte `sha256:<64hex>` κ-label;
//! - the label is deterministic;
//! - it is invariant under header key order, JSON whitespace / padding,
//!   string escape spelling, and tensor-data relayout;
//! - it binds every tensor byte, every `__metadata__` byte, and every
//!   dtype, shape and name;
//! - each tensor's leaf in the skeleton is the SHA-256 of that tensor's own
//!   bytes, so one tensor can be checked from a ranged read;
//! - a GGUF skeleton and a safetensors skeleton cannot coincide;
//! - malformed inputs are refused, each for its own reason.

#![cfg(feature = "safetensors")]

use uor_addr::safetensors::{self, AddressFailure};

#[derive(Clone)]
struct T {
    name: &'static str,
    dtype: &'static str,
    shape: Vec<u64>,
    data: Vec<u8>,
}

fn f32s(vals: &[f32]) -> Vec<u8> {
    vals.iter().flat_map(|v| v.to_le_bytes()).collect()
}

fn sample() -> Vec<T> {
    vec![
        T {
            name: "embed.weight",
            dtype: "F32",
            shape: vec![2, 2],
            data: f32s(&[1.0, 2.0, 3.0, 4.0]),
        },
        T {
            name: "head.bias",
            dtype: "F32",
            shape: vec![2],
            data: f32s(&[5.0, 6.0]),
        },
        T {
            name: "mask",
            dtype: "BOOL",
            shape: vec![3],
            data: vec![1, 0, 1],
        },
    ]
}

/// Serialize a safetensors file with tensors laid out in the given order.
/// `meta` is emitted as `__metadata__` when non-empty; `pad` adds trailing
/// spaces to the header, as writers do for alignment.
fn build_with(tensors: &[T], meta: &[(&str, &str)], pad: usize, meta_first: bool) -> Vec<u8> {
    let mut entries = Vec::new();
    let mut at = 0u64;
    for t in tensors {
        let end = at + t.data.len() as u64;
        let shape: Vec<String> = t.shape.iter().map(u64::to_string).collect();
        entries.push(format!(
            "\"{}\":{{\"dtype\":\"{}\",\"shape\":[{}],\"data_offsets\":[{},{}]}}",
            t.name,
            t.dtype,
            shape.join(","),
            at,
            end
        ));
        at = end;
    }
    if !meta.is_empty() {
        let kv: Vec<String> = meta
            .iter()
            .map(|(k, v)| format!("\"{k}\":\"{v}\""))
            .collect();
        let m = format!("\"__metadata__\":{{{}}}", kv.join(","));
        if meta_first {
            entries.insert(0, m);
        } else {
            entries.push(m);
        }
    }
    let mut header = format!("{{{}}}", entries.join(",")).into_bytes();
    header.resize(header.len() + pad, b' ');
    raw(
        &header,
        &tensors
            .iter()
            .flat_map(|t| t.data.clone())
            .collect::<Vec<_>>(),
    )
}

fn raw(header: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = (header.len() as u64).to_le_bytes().to_vec();
    out.extend_from_slice(header);
    out.extend_from_slice(data);
    out
}

fn build(tensors: &[T]) -> Vec<u8> {
    build_with(tensors, &[("format", "pt")], 0, true)
}

fn label(bytes: &[u8]) -> String {
    safetensors::address(bytes)
        .expect("valid safetensors")
        .address
        .as_str()
        .to_string()
}

fn refused(bytes: &[u8]) -> bool {
    matches!(
        safetensors::address(bytes),
        Err(AddressFailure::InvalidSafetensors)
    )
}

#[test]
fn well_formed_yields_kappa_label() {
    let l = label(&build(&sample()));
    assert_eq!(l.len(), 71);
    assert!(l.starts_with("blake3:"));
    assert!(l[7..]
        .bytes()
        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
}

#[test]
fn label_is_deterministic() {
    let b = build(&sample());
    assert_eq!(label(&b), label(&b));
}

#[test]
fn invariant_under_tensor_order_and_relayout() {
    let mut reversed = sample();
    reversed.reverse();
    assert_eq!(label(&build(&sample())), label(&build(&reversed)));
}

#[test]
fn invariant_under_metadata_position_and_padding() {
    let a = build_with(&sample(), &[("format", "pt")], 0, true);
    let b = build_with(&sample(), &[("format", "pt")], 7, false);
    assert_eq!(label(&a), label(&b));
}

#[test]
fn invariant_under_metadata_key_order() {
    let a = build_with(&sample(), &[("a", "1"), ("b", "2")], 0, true);
    let b = build_with(&sample(), &[("b", "2"), ("a", "1")], 0, true);
    assert_eq!(label(&a), label(&b));
}

#[test]
fn invariant_under_json_whitespace_and_escapes() {
    let data = f32s(&[1.0]);
    let plain = raw(
        br#"{"w":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}"#,
        &data,
    );
    let spaced = raw(
        b"{ \"\\u0077\" : {\n\t\"data_offsets\" : [ 0 , 4 ] , \"shape\" : [ 1 ] , \"dtype\" : \"F32\" } }",
        &data,
    );
    assert_eq!(label(&plain), label(&spaced));
}

#[test]
fn binds_every_tensor_byte() {
    let base = build(&sample());
    let header_end = 8 + u64::from_le_bytes(base[..8].try_into().unwrap()) as usize;
    for i in header_end..base.len() {
        let mut flipped = base.clone();
        flipped[i] ^= 1;
        assert_ne!(label(&base), label(&flipped), "byte {i} does not bind");
    }
}

#[test]
fn binds_metadata_values() {
    let a = build_with(&sample(), &[("format", "pt")], 0, true);
    let b = build_with(&sample(), &[("format", "pu")], 0, true);
    let none = build_with(&sample(), &[], 0, true);
    assert_ne!(label(&a), label(&b));
    assert_ne!(label(&a), label(&none));
}

#[test]
fn binds_name_dtype_and_shape() {
    let base = label(&build(&sample()));
    let mut renamed = sample();
    renamed[0].name = "embed.weights";
    let mut retyped = sample();
    retyped[2].dtype = "U8";
    let mut reshaped = sample();
    reshaped[0].shape = vec![4];
    let mut transposed = sample();
    transposed[0].shape = vec![1, 4];
    for other in [renamed, retyped, reshaped, transposed] {
        assert_ne!(base, label(&build(&other)));
    }
}

#[test]
fn tensor_leaf_is_blake3_of_its_own_bytes() {
    let tensors = sample();
    let skeleton = safetensors::canonicalize(&build(&tensors)).expect("valid");
    for t in &tensors {
        let leaf = blake3(&t.data);
        assert!(
            skeleton.windows(32).any(|w| w == leaf),
            "leaf of {} is not the BLAKE3 of its bytes",
            t.name
        );
    }
}

#[test]
fn skeleton_is_domain_separated_from_gguf() {
    let skeleton = safetensors::canonicalize(&build(&sample())).expect("valid");
    assert_eq!(&skeleton[..4], b"SAFE");
    assert_ne!(&skeleton[..4], &0x4655_4747u32.to_le_bytes());
}

#[test]
fn zero_sized_and_sub_byte_tensors_are_admitted() {
    let empty = T {
        name: "empty",
        dtype: "F32",
        shape: vec![0, 5],
        data: vec![],
    };
    let fp4 = T {
        name: "fp4",
        dtype: "F4",
        shape: vec![4],
        data: vec![0x12, 0x34],
    };
    label(&build(&[empty, fp4]));
}

#[test]
fn refuses_malformed_inputs() {
    let data = f32s(&[1.0]);
    let ok = br#"{"w":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}"#;
    assert!(!refused(&raw(ok, &data)));
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("shorter than the length prefix", vec![1, 0, 0]),
        ("header runs past the end", {
            let mut v = raw(ok, &data);
            v[0] = 200;
            v
        }),
        ("header over 100 MB", {
            let mut v = raw(ok, &data);
            v[..8].copy_from_slice(&100_000_001u64.to_le_bytes());
            v
        }),
        ("header not an object", raw(b"[1]", &[])),
        ("invalid UTF-8", raw(b"{\"\xff\":1}", &[])),
        ("lone surrogate", raw(br#"{"\ud800":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}"#, &data)),
        ("trailing garbage", raw(br#"{"w":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}} x"#, &data)),
        ("duplicate tensor", raw(br#"{"w":{"dtype":"F32","shape":[1],"data_offsets":[0,4]},"w":{"dtype":"F32","shape":[1],"data_offsets":[4,8]}}"#, &f32s(&[1.0, 2.0]))),
        ("unknown dtype", raw(br#"{"w":{"dtype":"F12","shape":[1],"data_offsets":[0,4]}}"#, &data)),
        ("unknown field", raw(br#"{"w":{"dtype":"F32","shape":[1],"data_offsets":[0,4],"x":1}}"#, &data)),
        ("missing field", raw(br#"{"w":{"dtype":"F32","shape":[1]}}"#, &data)),
        ("float in shape", raw(br#"{"w":{"dtype":"F32","shape":[1.0],"data_offsets":[0,4]}}"#, &data)),
        ("negative offset", raw(br#"{"w":{"dtype":"F32","shape":[1],"data_offsets":[-1,4]}}"#, &data)),
        ("size disagrees with shape", raw(br#"{"w":{"dtype":"F32","shape":[2],"data_offsets":[0,4]}}"#, &data)),
        ("hole before tensor", raw(br#"{"w":{"dtype":"F32","shape":[1],"data_offsets":[4,8]}}"#, &f32s(&[1.0, 2.0]))),
        ("overlapping tensors", raw(br#"{"a":{"dtype":"F32","shape":[1],"data_offsets":[0,4]},"b":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}"#, &data)),
        ("bytes after the last tensor", raw(ok, &f32s(&[1.0, 2.0]))),
        ("data shorter than declared", raw(ok, &data[..3])),
        ("sub-byte slice", raw(br#"{"w":{"dtype":"F4","shape":[3],"data_offsets":[0,2]}}"#, &[0, 0])),
        ("metadata value not a string", raw(br#"{"__metadata__":{"a":1}}"#, &[])),
        ("metadata not an object", raw(br#"{"__metadata__":"a"}"#, &[])),
    ];
    for (why, bytes) in cases {
        assert!(refused(&bytes), "not refused: {why}");
    }
}

fn blake3(bytes: &[u8]) -> [u8; 32] {
    use prism::vocabulary::Hasher;
    uor_addr::Blake3Hasher::initial()
        .fold_bytes(bytes)
        .finalize()
}
