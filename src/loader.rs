use anyhow::Result;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use memmap2::MmapOptions;
use std::{fs::File, path::PathBuf};
use crate::paging::MemoryImage;

pub fn display_banner() {
    let banner = "
██████╗ ███╗   ███╗███████╗██╗  ██╗██████╗ ███████╗██████╗ 
██╔══██╗████╗ ████║██╔════╝██║ ██╔╝██╔══██╗██╔════╝██╔══██╗
██████╔╝██╔████╔██║█████╗  █████╔╝ ██████╔╝█████╗  ██████╔╝
██╔══██╗██║╚██╔╝██║██╔══╝  ██╔═██╗ ██╔══██╗██╔══╝  ██╔══██╗
██║  ██║██║ ╚═╝ ██║██║     ██║  ██╗██║  ██║███████╗██████╔╝
╚═╝  ╚═╝╚═╝     ╚═╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═════╝ 
    ".bright_red().bold();
    
    let tagline = "Rust Memory Forensics Toolkit - v0.1.0".bright_blue().bold();
    let separator = "---------------------------------------".bright_white();
    
    println!("{}", banner);
    println!("    {}", tagline);
    println!("    {}", separator);
}

pub fn load_memory_image(path: &PathBuf) -> Result<MemoryImage> {
    // Show a progress bar when opening large memory dumps
    let progress = ProgressBar::new_spinner();
    progress.set_style(
        ProgressStyle::with_template("{spinner:.green} {msg}")
            .unwrap()
            .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈"),
    );
    progress.set_message(format!("Opening memory dump {}", path.display()));
    
    // Open the file and create memory map
    let file = File::open(path)?;
    progress.set_message("Memory mapping the file...");
    let mmap = unsafe { MmapOptions::new().map(&file)? };
    
    // Create a MemoryImage from the memory map
    progress.finish_with_message(format!(
        "Successfully mapped {} bytes from {}", 
        mmap.len(), 
        path.display()
    ));
    
    Ok(MemoryImage::new(mmap))
}

pub fn load_dump(path: PathBuf) -> Result<()> {
    // Load the memory image
    let memory_image = load_memory_image(&path)?;
    
    let size_str = format!("{}", memory_image.size());
    let path_str = format!("{}", path.display());
    
    println!("{} {} {} {}",
        "Mapped".bright_green(),
        size_str.bright_yellow().bold(),
        "bytes from".bright_green(),
        path_str.bright_cyan().underline()
    );
    
    // Print first 16 bytes in hex with colorized output
    print!("{} ", "First 16 bytes:".bright_green());
    
    // Get bytes from the memory image using our accessor
    if let Some(bytes) = memory_image.get_bytes(0, 16) {
        for (i, byte) in bytes.iter().enumerate() {
            let byte_str = format!("{:02X}", byte);
            let colored_byte = if i % 2 == 0 {
                byte_str.bright_yellow()
            } else {
                byte_str.bright_cyan()
            };
            
            let separator = if i == 7 {
                " | ".bright_red().bold()
            } else {
                " ".normal()
            };
            
            print!("{}{}", colored_byte, separator);
        }
    }
    
    println!();
    Ok(())
}
