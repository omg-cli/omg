//! Test infrastructure and utilities for TDD
//!
//! This module provides fixture builders and a package-manager test double.

pub mod fixtures;
pub mod mocks;

pub use fixtures::{PackageFixture, UpdateFixture};
pub use mocks::TestPackageManager;

#[cfg(test)]
mod isolated;

#[cfg(test)]
pub(crate) use isolated::run_isolated_test;
