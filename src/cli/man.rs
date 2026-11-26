//! Man page generation for OMG CLI
//!
//! Generates man pages from clap command definitions using `clap_mangen`.

use anyhow::{Context, Result};
use clap::CommandFactory;
use clap_mangen::Man;
use std::fs;
use std::path::{Path, PathBuf};

use super::args::Cli;
use super::style;

/// Generate man pages for all OMG commands
pub fn generate(output_dir: Option<String>) -> Result<()> {
    let output_path = if let Some(dir) = output_dir {
        let path = PathBuf::from(dir);
        if let Ok(relative) = path.strip_prefix("~") {
            dirs::home_dir()
                .context("Cannot determine the home directory for man page output")?
                .join(relative)
        } else {
            path
        }
    } else {
        dirs::data_dir()
            .context("Cannot determine the data directory for man page output")?
            .join("man")
            .join("man1")
    };

    fs::create_dir_all(&output_path)
        .with_context(|| format!("Failed to create directory: {}", output_path.display()))?;

    println!(
        "{} Generating man pages to {}",
        style::info("→"),
        output_path.display()
    );

    // Build the whole tree once so pages inherit global flags, versions, and
    // command names. The generated help commands have no standalone pages.
    let mut command = Cli::command().disable_help_subcommand(true);
    command.build();
    let generated = render_pages(&command, &output_path, &mut Vec::new())?;

    println!();
    println!("{} Generated {} man pages", style::success("✓"), generated);
    println!();
    println!("{} To view: man omg", style::dim("Tip:"));
    println!(
        "{}",
        style::dim("     You may need to run 'mandb' to update the man database.")
    );

    Ok(())
}

fn render_pages(command: &clap::Command, output: &Path, buffer: &mut Vec<u8>) -> Result<usize> {
    let name = command
        .get_display_name()
        .unwrap_or_else(|| command.get_name());
    let path = output.join(format!("{name}.1"));
    buffer.clear();
    Man::new(command.clone())
        .render(buffer)
        .with_context(|| format!("Failed to render {}", path.display()))?;
    fs::write(&path, buffer.as_slice())
        .with_context(|| format!("Failed to write {}", path.display()))?;
    println!("  {} {name}.1", style::success("✓"));

    let mut generated = 1;
    for subcommand in command.get_subcommands().filter(|cmd| !cmd.is_hide_set()) {
        generated += render_pages(subcommand, output, buffer)?;
    }
    Ok(generated)
}
