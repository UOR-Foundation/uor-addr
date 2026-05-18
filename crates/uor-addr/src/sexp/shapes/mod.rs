//! Substitution-axis selections for the S-expression realization.

pub mod bounds;

pub use bounds::{
    SExprAddrBounds, MAX_SEXPR_ATOM_BYTES, MAX_SEXPR_DEPTH, MAX_SEXPR_ELEMENTS,
    SEXPR_VALUE_MAX_BYTES,
};
