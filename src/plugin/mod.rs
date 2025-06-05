//! Plugin system for memory forensics analysis
//! 
//! This module contains the core plugin system implementation along with
//! built-in plugins for memory analysis.

mod string_carve;
mod pe_scanner;
mod registry;

pub use string_carve::StringCarvePlugin;
pub use pe_scanner::PEScanner;
pub use registry::{PluginRegistry, Finding, MemoryPlugin};

// Re-export registry
pub use registry::get_plugin_registry;

use anyhow::{Result, Context};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle, MultiProgress};
use pager::Pager;
use prettytable::{Table, row, format};
use std::path::PathBuf;
use crate::loader::load_memory_image;

/// Run a plugin by name on the provided memory dump
pub fn run_plugin(dump_path: PathBuf, plugin_name: String) -> Result<()> {
    println!("{} {} {} {}",
        "Running plugin".bright_green(),
        plugin_name.bright_yellow().bold(),
        "on".bright_green(),
        dump_path.display().to_string().bright_cyan()
    );

    // Get the global plugin registry
    let registry = get_plugin_registry();
    let registry = registry.read().unwrap();

    // Check if plugin exists
    let plugin = registry.get(&plugin_name)
        .with_context(|| format!("Plugin '{}' not found. Available plugins: {}",
            plugin_name,
            registry.list_plugins().iter()
                .map(|(name, _, _)| name.clone())
                .collect::<Vec<_>>()
                .join(", ")
        ))?;

    println!("{}: {} (v{})",
        "Plugin description".bright_blue(),
        plugin.description(),
        plugin.get_version().bright_blue());

    // Load memory image
    let memory_image = load_memory_image(&dump_path)?;

    // Set up progress bars
    let multi_progress = MultiProgress::new();
    let scan_progress = multi_progress.add(ProgressBar::new(100));
    scan_progress.set_style(ProgressStyle::with_template(
        "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} {msg}"
    )?.progress_chars("#>-"));

    // Run the plugin
    println!("{}", "Starting scan...".bright_green());
    let findings = plugin.scan(&memory_image, &scan_progress);

    // Display findings using pager if there are many
    if !findings.is_empty() {
        let mut table = Table::new();
        table.set_format(*format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
        table.set_titles(row![b->"Address", b->"Confidence", b->"Description"]);

        for finding in &findings {
            table.add_row(row![
                format!("0x{:08X}", finding.addr),
                format!("{}%", finding.confidence),
                finding.desc
            ]);
        }

        if findings.len() > 20 {
            Pager::new().setup();
        }

        println!("\n{} {} {}",
            "Found".bright_green(),
            findings.len().to_string().bright_yellow().bold(),
            "items".bright_green()
        );

        table.printstd();
    } else {
        println!("{}", "No findings from the scan".bright_yellow());
    }

    Ok(())
}
