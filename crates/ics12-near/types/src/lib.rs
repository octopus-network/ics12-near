//! ICS-12: Near Client implements a client verification algorithm for blockchains which use
//! the Near consensus algorithm.

#![no_std]
#![forbid(unsafe_code)]
#![feature(btree_cursors)]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]
#![cfg_attr(not(test), deny(clippy::disallowed_methods, clippy::disallowed_types,))]
#![deny(
    warnings,
    trivial_casts,
    trivial_numeric_casts,
    unused_import_braces,
    unused_qualifications,
    // rust_2018_idioms
)]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "v1")]
pub mod v1;
