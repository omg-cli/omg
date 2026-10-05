//! Compiles the production mise modules independently of platform package backends.
#![allow(dead_code)]

#[path = "../../../src/config/mise_config.rs"]
mod mise_config;
#[path = "../../../src/config/mise_env.rs"]
mod mise_env;
#[path = "../../../src/config/mise_tasks.rs"]
mod mise_tasks;
#[path = "../../../src/config/mise_tools.rs"]
mod mise_tools;
