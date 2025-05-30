use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use colored::*;
use std::path::PathBuf;

mod arch;
mod loader;
mod paging;
mod processes;
mod modules;
mod plugin;

/// Supported memory dump formats
#[derive(Debug, Clone, Copy, ValueEnum)]
enum DumpFormat {
    /// Raw memory dump
    Raw,
    /// Windows crash dump
    Crashdump,
    /// VMware memory dump
    Vmem,
    /// Volatility profile
    Profile,
}

/// Operating system type for analysis
#[derive(Debug, Clone, Copy, ValueEnum)]
enum OSType {
    /// Windows OS
    Windows,
    /// Linux OS
    Linux,
    /// macOS
    MacOS,
    /// Auto-detect OS (may not be accurate)
    Auto,
}

/// Rust Memory Forensics Toolkit (rmf)
#[derive(Parser)]
#[command(name = "rmf", about = "Rust Memory Forensics Toolkit", version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Map a memory dump and display basic info
    Load {
        /// Path to the raw memory dump file
        path: PathBuf,
        
        /// Format of the memory dump
        #[arg(short, long, value_enum, default_value_t = DumpFormat::Raw)]
        format: DumpFormat,
    },
    
    /// List processes in a memory dump
    ListProcs {
        /// Path to the memory dump file
        dump: PathBuf,
        
        /// Operating system type
        #[arg(short, long, value_enum, default_value_t = OSType::Auto)]
        os: OSType,
        
        /// Directory Table Base / CR3 value (hex)
        #[arg(short, long)]
        dtb: Option<String>,
    },
    
    /// Extract loaded modules from a memory dump
    ExtractModules {
        /// Path to the memory dump file
        dump: PathBuf,
        
        /// Output directory for extracted modules
        output: PathBuf,
        
        /// Only extract modules matching this pattern
        #[arg(short, long)]
        pattern: Option<String>,
    },
    
    /// Run a memory analysis plugin
    RunPlugin {
        /// Path to the memory dump file
        dump: PathBuf,
        
        /// Name of the plugin to run
        plugin: String,
        
        /// Export findings to this file (CSV format)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    
    /// List available plugins
    ListPlugins,
    
    /// Scan memory for specific patterns or signatures
    Scan {
        /// Path to the memory dump file
        dump: PathBuf,
        
        /// Type of scan to perform (strings, pe, urls, etc.)
        #[arg(short, long, default_value = "strings")]
        scan_type: String,
        
        /// Minimum match length for string scans
        #[arg(short, long, default_value_t = 8)]
        min_length: usize,
    },
    
    /// Translate virtual memory addresses to physical
    Translate {
        /// Path to the memory dump file
        dump: PathBuf,
        
        /// Virtual address to translate (hex)
        address: String,
        
        /// Directory Table Base / CR3 value (hex)
        #[arg(short, long)]
        dtb: Option<String>,
    },
}

fn parse_hex_address(addr_str: &str) -> Result<u64> {
    let cleaned = addr_str.trim_start_matches("0x").trim_start_matches("0X");
    Ok(u64::from_str_radix(cleaned, 16)?)
}

fn main() -> Result<()> {
    // Enable colors in Windows terminals
    #[cfg(target_os = "windows")]
    colored::control::set_virtual_terminal(true).unwrap_or(());
    
    // Always enable colors
    colored::control::set_override(true);
    
    loader::display_banner();
    let cli = Cli::parse();
    
    match cli.cmd {
        Commands::Load { path, format } => {
            println!("Loading memory dump in {} format", match format {
                DumpFormat::Raw => "Raw".bright_green(),
                DumpFormat::Crashdump => "Windows Crashdump".bright_green(),
                DumpFormat::Vmem => "VMware".bright_green(),
                DumpFormat::Profile => "Volatility Profile".bright_green(),
            });
            loader::load_dump(path)?
        },
        
        Commands::ListProcs { dump, os, dtb } => {
            if let Some(dtb_str) = dtb {
                let dtb_val = parse_hex_address(&dtb_str)?;
                println!("Using DTB/CR3: {}", format!("0x{:X}", dtb_val).bright_yellow());
                // In a real implementation, we'd set the DTB in the memory image
            }
            processes::list_processes(dump)?
        },
        
        Commands::ExtractModules { dump, output, pattern } => {
            if let Some(pat) = pattern {
                println!("Extracting modules matching: {}", pat.bright_yellow());
            }
            modules::extract_modules(dump, output)?
        },
        
        Commands::RunPlugin { dump, plugin, output } => {
            if let Some(out_path) = &output {
                println!("Will export findings to: {}", out_path.display().to_string().bright_cyan());
            }
            plugin::run_plugin(dump, plugin)?
        },
        
        Commands::ListPlugins => {
            println!("{}", "Available plugins:".bright_green());
            
            // Get the plugin registry and list plugins
            let registry = plugin::get_plugin_registry();
            let registry = registry.read().unwrap();
            let plugins = registry.list_plugins();
            
            if plugins.is_empty() {
                println!("  {}", "No plugins found".bright_red());
            } else {
                for (name, desc, version) in plugins {
                    println!("  {} - {} (v{})", 
                        name.bright_yellow().bold(),
                        desc.bright_white(),
                        version.bright_blue()
                    );
                }
            }
        },
        
        Commands::Scan { dump, scan_type, min_length } => {
            println!("Scanning memory dump for {} with minimum length {}", 
                scan_type.bright_yellow(),
                min_length.to_string().bright_cyan()
            );
            
            // For now, just run the appropriate plugin
            let plugin_name = match scan_type.as_str() {
                "strings" => "string_carve",
                "pe" => "pe_scanner",
                _ => "string_carve",  // Default to string carving
            };
            
            plugin::run_plugin(dump, plugin_name.to_string())?
        },
        
        Commands::Translate { dump, address, dtb } => {
            // Load the memory image
            let mut memory_image = loader::load_memory_image(&dump)?;
            
            // Parse the virtual address
            let virt_addr = parse_hex_address(&address)?;
            
            // Set DTB if provided
            if let Some(dtb_str) = dtb {
                let dtb_val = parse_hex_address(&dtb_str)?;
                memory_image.set_cr3(dtb_val);
            }
            
            // Translate the address
            match memory_image.virt_to_phys(virt_addr) {
                Some(phys_addr) => {
                    println!("{} {} {} {}",
                        "Virtual address".bright_green(),
                        format!("0x{:X}", virt_addr).bright_yellow(),
                        "translates to physical address".bright_green(),
                        format!("0x{:X}", phys_addr).bright_cyan()
                    );
                    
                    // Display memory at that location
                    if let Some(bytes) = memory_image.get_bytes(phys_addr as usize, 16) {
                        println!("{}", "Memory contents:".bright_green());
                        print!("  ");
                        for (i, byte) in bytes.iter().enumerate() {
                            let byte_str = format!("{:02X}", byte);
                            let colored_byte = if i % 2 == 0 {
                                byte_str.bright_yellow()
                            } else {
                                byte_str.bright_cyan()
                            };
                            
                            print!("{} ", colored_byte);
                        }
                        println!();
                        
                        // Also show as ASCII
                        print!("  ");
                        for &byte in bytes {
                            if byte >= 32 && byte <= 126 {
                                print!("{} ", (byte as char).to_string().bright_green());
                            } else {
                                print!("{} ", ".".bright_red());
                            }
                        }
                        println!();
                    }
                },
                None => {
                    println!("{} {}", 
                        "Could not translate virtual address".bright_red(),
                        format!("0x{:X}", virt_addr).bright_yellow()
                    );
                },
            }
        },
    }
    
    Ok(())
}
