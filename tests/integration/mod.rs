//! Integration tests with real external systems
//!
//! These tests verify production behavior against actual APIs and services:
//! - No mocks or stubs
//! - Real network requests
//! - Real system packages
//! - Real cryptographic verification
//!
//! Run with: `cargo test --test real_world_integration -- --ignored`

mod security_real_world;
