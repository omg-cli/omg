//! Integration wrappers for Elm-based models

use crate::cli::tea::{Program, StatusModel};

/// Run status command using Elm Architecture
pub fn run_status_elm(fast: bool) -> Result<(), std::io::Error> {
    let model = StatusModel::new().with_fast_mode(fast);
    Program::new(model).run()
}
