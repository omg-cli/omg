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
        PathBuf::from(shellexpand(&dir))
    } else {
        // Default to ~/.local/share/man/man1
        dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("~/.local/share"))
            .join("man")
            .join("man1")
    };

    // Create output directory if it doesn't exist
    fs::create_dir_all(&output_path)
        .with_context(|| format!("Failed to create directory: {}", output_path.display()))?;

    println!(
        "{} Generating man pages to {}",
        style::info("→"),
        output_path.display()
    );

    let cmd = Cli::command();
    let mut generated = 0;

    // Generate main omg man page
    let man = Man::new(cmd.clone());
    let man_path = output_path.join("omg.1");
    let mut buffer = Vec::new();
    man.render(&mut buffer)?;
    fs::write(&man_path, buffer)
        .with_context(|| format!("Failed to write {}", man_path.display()))?;
    println!("  {} omg.1", style::success("✓"));
    generated += 1;

    generated += render_subcommand_pages(&cmd, &output_path, "omg")?;

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

fn render_subcommand_pages(command: &clap::Command, output: &Path, prefix: &str) -> Result<usize> {
    let mut generated = 0;
    for subcommand in command.get_subcommands().filter(|cmd| !cmd.is_hide_set()) {
        let name = format!("{prefix}-{}", subcommand.get_name());
        let path = output.join(format!("{name}.1"));
        let mut buffer = Vec::new();
        Man::new(subcommand.clone()).render(&mut buffer)?;
        fs::write(&path, buffer).with_context(|| format!("Failed to write {}", path.display()))?;
        println!("  {} {name}.1", style::success("✓"));
        generated += 1 + render_subcommand_pages(subcommand, output, &name)?;
    }
    Ok(generated)
}

/// Simple shell expansion for ~ paths
fn shellexpand(path: &str) -> String {
    if path.starts_with("~/")
        && let Ok(home) = std::env::var("HOME")
    {
        return path.replacen('~', &home, 1);
    }
    path.to_string()
}
