//! Shared types, the five pluggable traits, the harness adapter schema and the
//! launch orchestration. See `docs/DESIGN.md`.

pub mod adapter;
pub mod env;
pub mod launch;
pub mod template;
pub mod types;

pub use adapter::{Adapter, AdapterError, AdapterSet, HarnessPlan};
pub use types::*;
