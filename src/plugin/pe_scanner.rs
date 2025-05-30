//! PE (Portable Executable) scanner plugin

use indicatif::ProgressBar;
use std::collections::HashMap;
use crate::paging::MemoryImage;
use super::registry::{MemoryPlugin, Finding};

/// A plugin that scans for PE headers in memory
pub struct PEScanner;

impl MemoryPlugin for PEScanner {
    fn name(&self) -> &'static str {
        "pe_scanner"
    }
    
    fn description(&self) -> &'static str {
        "Scans memory for Portable Executable (PE) headers and executables"
    }

    fn scan(&self, img: &MemoryImage, progress: &ProgressBar) -> Vec<Finding> {
        let mut findings = Vec::new();
        let size = img.size();
        
        // Set up progress bar
        progress.set_length(size as u64);
        progress.set_message("Scanning for PE headers");
        
        // The PE file format starts with "MZ" (0x4D5A) and has a PE header at a specified offset
        let mz_signature = [0x4D, 0x5A]; // "MZ"
        let pe_signature = [0x50, 0x45, 0x00, 0x00]; // "PE\0\0"
        
        // Scan in chunks to avoid loading the entire memory image at once
        let chunk_size = 0x10000; // 64KB chunks
        
        for chunk_start in (0..size).step_by(chunk_size) {
            // Update progress
            progress.set_position(chunk_start as u64);
            
            // Get the chunk
            if let Some(chunk) = img.get_bytes(chunk_start, chunk_size) {
                for i in 0..chunk.len() - mz_signature.len() {
                    // Check for MZ signature
                    if chunk[i..i + mz_signature.len()] == mz_signature {
                        // Found potential PE file, get the e_lfanew field at offset 0x3C
                        if i + 0x40 < chunk.len() {
                            let e_lfanew_offset = i + 0x3C;
                            let e_lfanew = u32::from_le_bytes([
                                chunk[e_lfanew_offset],
                                chunk[e_lfanew_offset + 1],
                                chunk[e_lfanew_offset + 2],
                                chunk[e_lfanew_offset + 3],
                            ]);
                            
                            // Calculate the PE header offset
                            let pe_offset = i as u32 + e_lfanew;
                            
                            // Check if the PE header is within this chunk
                            let pe_header_in_chunk = pe_offset as usize + pe_signature.len() <= chunk_start + chunk.len();
                            
                            // If PE header is in this chunk, check for "PE\0\0" signature
                            if pe_header_in_chunk {
                                let pe_header_offset = (pe_offset as usize) - chunk_start;
                                if pe_header_offset + pe_signature.len() <= chunk.len() &&
                                   chunk[pe_header_offset..pe_header_offset + pe_signature.len()] == pe_signature {
                                    // This is a PE file
                                    let mut details = HashMap::new();
                                    details.insert("type".to_string(), "PE_HEADER".to_string());
                                    
                                    // Try to extract more information
                                    if pe_header_offset + 0x18 < chunk.len() {
                                        // Extract machine type
                                        let machine = u16::from_le_bytes([
                                            chunk[pe_header_offset + 4],
                                            chunk[pe_header_offset + 5],
                                        ]);
                                        
                                        // Map machine type to architecture
                                        let arch = match machine {
                                            0x014c => "x86",
                                            0x0200 => "IA64",
                                            0x8664 => "x64",
                                            _ => "Unknown",
                                        };
                                        
                                        details.insert("architecture".to_string(), arch.to_string());
                                    }
                                    
                                    findings.push(Finding {
                                        plugin: self.name().to_string(),
                                        addr: (chunk_start + i) as u64,
                                        desc: format!("PE Header found at 0x{:X}", chunk_start + i),
                                        confidence: 95,
                                        details,
                                    });
                                }
                            } else {
                                // PE header might be in another chunk, we'd need to check
                                // For this demo, just add it as a potential finding with lower confidence
                                let mut details = HashMap::new();
                                details.insert("type".to_string(), "POTENTIAL_PE_HEADER".to_string());
                                details.insert("e_lfanew".to_string(), format!("0x{:X}", e_lfanew));
                                
                                findings.push(Finding {
                                    plugin: self.name().to_string(),
                                    addr: (chunk_start + i) as u64,
                                    desc: format!("Potential PE file at 0x{:X}", chunk_start + i),
                                    confidence: 50,
                                    details,
                                });
                            }
                        }
                    }
                }
            }
            
            // Simulate work
            if chunk_start % (1024 * 1024) == 0 {  // Every 1MB
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        }
        
        progress.finish_with_message(format!("Found {} PE headers", findings.len()));
        findings
    }
}
