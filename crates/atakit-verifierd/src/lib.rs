//! `atakit-verifierd`: peer session verification over HTTP.
//!
//! The daemon connects to a request-selected portal, verifies portal TLS, fetches a
//! challenge-bound current-session evidence bundle, verifies it, and returns
//! the peer's verified session public key. It does nothing else: no key
//! exchange, no workload secrets, no signing, no transactions, no proxying.
//!
//! It exists because a workload in an atakit CVM cannot otherwise verify
//! another atakit CVM without reimplementing the whole verification in its own
//! language. It runs in the caller's security domain — inside that CVM for a
//! workload, locally for an operator — so it is a library exposed as a local
//! service rather than a party anyone else trusts.

pub mod config;
pub mod destination;
pub mod server;
