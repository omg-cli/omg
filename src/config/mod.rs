//! Configuration module for OMG

pub(crate) mod mise_config;
pub(crate) mod mise_env;
pub(crate) mod mise_tasks;
pub(crate) mod mise_tools;
mod settings;

pub use settings::{AurBuildMethod, AurSecurityProfile, Settings};

pub(crate) use settings::{validate_build_concurrency, validate_makeflags};
