//! `SafetensorsDtype` — the safetensors element-type alphabet.
//!
//! The names and bit widths are the reference implementation's `Dtype`
//! enum and `Dtype::bitsize`. The numeric IDs are this canonical form's
//! own: fixed, never reused, and independent of the reference enum's
//! declaration order, which has had variants inserted mid-list before
//! (`F8_E8M0`, the FNUZ variants).
//!
//! Sub-byte types (`F4`, `F6_*`) are admitted; a tensor of one is valid
//! only when its total bit count is a whole number of bytes, which is the
//! reference implementation's `MisalignedSlice` rule.
//!
//! Authoritative source:
//! <https://github.com/huggingface/safetensors/blob/main/safetensors/src/tensor.rs>.

/// A safetensors tensor element type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
#[non_exhaustive]
pub enum SafetensorsDtype {
    /// `BOOL`, 8 bits.
    BOOL,
    /// `U8`, 8 bits.
    U8,
    /// `I8`, 8 bits.
    I8,
    /// `I16`, 16 bits.
    I16,
    /// `U16`, 16 bits.
    U16,
    /// `F16`, 16 bits.
    F16,
    /// `BF16`, 16 bits.
    BF16,
    /// `I32`, 32 bits.
    I32,
    /// `U32`, 32 bits.
    U32,
    /// `F32`, 32 bits.
    F32,
    /// `F64`, 64 bits.
    F64,
    /// `I64`, 64 bits.
    I64,
    /// `U64`, 64 bits.
    U64,
    /// `F8_E5M2`, 8 bits.
    F8_E5M2,
    /// `F8_E4M3`, 8 bits.
    F8_E4M3,
    /// `F8_E8M0`, 8 bits.
    F8_E8M0,
    /// `F8_E4M3FNUZ`, 8 bits.
    F8_E4M3FNUZ,
    /// `F8_E5M2FNUZ`, 8 bits.
    F8_E5M2FNUZ,
    /// `C64`, 64 bits.
    C64,
    /// `F4`, 4 bits.
    F4,
    /// `F6_E2M3`, 6 bits.
    F6_E2M3,
    /// `F6_E3M2`, 6 bits.
    F6_E3M2,
}

/// `(name, id, bits)` for every admitted dtype. The single table both
/// directions of the mapping read.
const TABLE: [(&str, SafetensorsDtype, u32, u64); 22] = [
    ("BOOL", SafetensorsDtype::BOOL, 0, 8),
    ("U8", SafetensorsDtype::U8, 1, 8),
    ("I8", SafetensorsDtype::I8, 2, 8),
    ("I16", SafetensorsDtype::I16, 3, 16),
    ("U16", SafetensorsDtype::U16, 4, 16),
    ("F16", SafetensorsDtype::F16, 5, 16),
    ("BF16", SafetensorsDtype::BF16, 6, 16),
    ("I32", SafetensorsDtype::I32, 7, 32),
    ("U32", SafetensorsDtype::U32, 8, 32),
    ("F32", SafetensorsDtype::F32, 9, 32),
    ("F64", SafetensorsDtype::F64, 10, 64),
    ("I64", SafetensorsDtype::I64, 11, 64),
    ("U64", SafetensorsDtype::U64, 12, 64),
    ("F8_E5M2", SafetensorsDtype::F8_E5M2, 13, 8),
    ("F8_E4M3", SafetensorsDtype::F8_E4M3, 14, 8),
    ("F8_E8M0", SafetensorsDtype::F8_E8M0, 15, 8),
    ("F8_E4M3FNUZ", SafetensorsDtype::F8_E4M3FNUZ, 16, 8),
    ("F8_E5M2FNUZ", SafetensorsDtype::F8_E5M2FNUZ, 17, 8),
    ("C64", SafetensorsDtype::C64, 18, 64),
    ("F4", SafetensorsDtype::F4, 19, 4),
    ("F6_E2M3", SafetensorsDtype::F6_E2M3, 20, 6),
    ("F6_E3M2", SafetensorsDtype::F6_E3M2, 21, 6),
];

impl SafetensorsDtype {
    /// The dtype a header names, or `None` for a name the format does not
    /// define.
    #[must_use]
    pub fn from_name(name: &[u8]) -> Option<Self> {
        TABLE
            .iter()
            .find(|row| row.0.as_bytes() == name)
            .map(|row| row.1)
    }

    fn row(self) -> &'static (&'static str, SafetensorsDtype, u32, u64) {
        // Variants are declared in ID order, so the discriminant indexes the
        // table; `every_dtype_round_trips` holds the two to that.
        &TABLE[self as usize]
    }

    /// The dtype's name as the header spells it.
    #[must_use]
    pub fn name(self) -> &'static str {
        self.row().0
    }

    /// The canonical form's fixed ID for this dtype.
    #[must_use]
    pub fn id(self) -> u32 {
        self.row().2
    }

    /// Bits per element.
    #[must_use]
    pub fn bits(self) -> u64 {
        self.row().3
    }

    /// Every admitted dtype, in ID order.
    pub fn all() -> impl Iterator<Item = Self> {
        TABLE.iter().map(|row| row.1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_dtype_round_trips() {
        let mut ids: Vec<u32> = SafetensorsDtype::all().map(SafetensorsDtype::id).collect();
        assert_eq!(ids, (0..22).collect::<Vec<u32>>());
        ids.dedup();
        assert_eq!(ids.len(), 22);
        for (i, d) in SafetensorsDtype::all().enumerate() {
            assert_eq!(d as usize, i);
            assert_eq!(SafetensorsDtype::from_name(d.name().as_bytes()), Some(d));
        }
    }

    #[test]
    fn unknown_name_is_none() {
        assert_eq!(SafetensorsDtype::from_name(b"F12"), None);
        assert_eq!(SafetensorsDtype::from_name(b"f32"), None);
    }
}
