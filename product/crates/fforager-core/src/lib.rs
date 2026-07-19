//! Pure, deterministic Phase 0 lifecycle and resource-accounting models.
//!
//! The crate deliberately contains no runtime handles or effectful adapters. A
//! transition returns effect *intent* data which a later production adapter may
//! execute and acknowledge through another transition.

#![forbid(unsafe_code)]

pub mod lifecycle;
pub mod resource;
