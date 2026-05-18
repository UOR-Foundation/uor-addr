//! Substitution-axis selections for the XML realization.

pub mod bounds;

pub use bounds::{
    XmlAddrBounds, MAX_XML_ATTRIBUTES, MAX_XML_DEPTH, MAX_XML_ELEMENT_NAME_BYTES,
    MAX_XML_TEXT_BYTES, XML_VALUE_MAX_BYTES,
};
