//! Substitution-axis selections for the code-module AST realization.

pub mod bounds;

pub use bounds::{
    CodeModuleAddrBounds, CODEMODULE_VALUE_MAX_BYTES, MAX_CODEMODULE_DEPTH, MAX_CODEMODULE_ITEMS,
    MAX_CODEMODULE_NAME_BYTES,
};
