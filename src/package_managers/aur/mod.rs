//! AUR (Arch User Repository) client with build support
//!
//! This module provides the `AurClient` for searching, building, and installing
//! packages from the Arch User Repository.

mod approval;
mod archive_metadata;
mod archive_reader;
pub(crate) mod artifact_inspector;
mod client;
mod error;
pub(super) mod git_process;
mod history;
mod parallel_build;
pub(crate) mod source_file;
pub(super) mod utils;

pub use client::{AurClient, AurPackageDetail, search_detailed};
pub use parallel_build::{BuildJob, ParallelBuildSummary, ParallelBuilder};
