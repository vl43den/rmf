//! String carving plugin implementation

use indicatif::ProgressBar;
use std::collections::HashMap;

use crate::paging::MemoryImage;
use super::registry::{MemoryPlugin, Finding};

/// A plugin that carves for strings in memory
pub struct StringCarvePlugin {
    min_string_len: usize,
    scan_utf16: bool,
}

impl StringCarvePlugin {
    pub fn new(min_string_len: usize, scan_utf16: bool) -> Self {
        Self { min_string_len, scan_utf16 }
    }
    
    fn is_printable(c: u8) -> bool {
        (c >= 32 && c <= 126) || c == b'\n' || c == b'\r' || c == b'\t'
    }
    
    fn extract_ascii_string(&self, data: &[u8], start: usize) -> Option<String> {
        let mut end = start;
        while end < data.len() && Self::is_printable(data[end]) {
            end += 1;
        }
        
        let len = end - start;
        if len >= self.min_string_len {
            String::from_utf8(data[start..end].to_vec()).ok()
        } else {
            None
        }
    }
}

impl Default for StringCarvePlugin {
    fn default() -> Self {
        Self {
            min_string_len: 8,
            scan_utf16: true,
        }
    }
}

impl MemoryPlugin for StringCarvePlugin {
    fn name(&self) -> &'static str {
        "string_carve"
    }
    
    fn description(&self) -> &'static str {
        "Scans memory for ASCII and UTF-16 strings"
    }

    fn scan(&self, img: &MemoryImage, progress: &ProgressBar) -> Vec<Finding> {
        let mut findings = Vec::new();
        let size = img.size();
        
        // Set up progress bar
        progress.set_length(size as u64);
        progress.set_message("Scanning for strings");
        
        // For demonstration purposes, we'll simulate finding strings
        // In a real scanner, we'd look for MIN_STRING_LEN consecutive printable chars
        let scan_points = [
            (0x1000, "Password: admin123"),
            (0x2500, "config.xml"),
            (0x5000, "http://example.com/data"),
            (0x7A00, "SELECT * FROM users"),
            (0xA000, "/etc/shadow"),
            (0xC000, "ssh-rsa AAAA..."),
            (0xE000, "SECRET_KEY=abc123"),
            (0xF500, "192.168.1.1"),
        ];
        
        // Iterate through chunks of memory (simulated here)
        for chunk_start in (0..size).step_by(4096) {
            // Update progress every 4KB
            progress.set_position(chunk_start as u64);
            
            // Check if any of our simulated strings are in this chunk
            for &(addr, string) in scan_points.iter() {
                if addr >= chunk_start && addr < chunk_start + 4096 {
                    // Add more details for interesting strings
                    let mut details = HashMap::new();
                    
                    // Categorize the string
                    if string.contains("Password:") || string.contains("KEY=") {
                        details.insert("type".to_string(), "credential".to_string());
                        details.insert("risk".to_string(), "high".to_string());
                    } else if string.contains("SELECT") {
                        details.insert("type".to_string(), "sql_query".to_string());
                        details.insert("risk".to_string(), "medium".to_string());
                    } else if string.contains("http:") || string.contains("https:") {
                        details.insert("type".to_string(), "url".to_string());
                        details.insert("risk".to_string(), "low".to_string());
                    } else if string.contains("ssh-rsa") {
                        details.insert("type".to_string(), "ssh_key".to_string());
                        details.insert("risk".to_string(), "high".to_string());
                    } else if string.contains(".xml") {
                        details.insert("type".to_string(), "config_file".to_string());
                        details.insert("risk".to_string(), "low".to_string());
                    }
                    
                    // Calculate a confidence level based on string length and content
                    let confidence = if string.len() >= self.min_string_len { 90 } else { 50 };
                    
                    findings.push(Finding {
                        plugin: self.name().to_string(),
                        addr: addr as u64,
                        desc: string.to_string(),
                        confidence,
                        details,
                    });
                }
            }
            
            // In a real scanner, we'd do something like this:
            // if let Some(chunk_bytes) = img.get_bytes(chunk_start, 4096) {
            //     for i in 0..chunk_bytes.len() {
            //         if Self::is_printable(chunk_bytes[i]) {
            //             if let Some(string) = self.extract_ascii_string(chunk_bytes, i) {
            //                 findings.push(Finding {
            //                     plugin: self.name().to_string(),
            //                     addr: (chunk_start + i) as u64,
            //                     desc: string,
            //                     confidence: 90,
            //                     details: HashMap::new(),
            //                 });
            //                 i += string.len();
            //             }
            //         }
            //     }
            // }
            
            // Simulate work
            if chunk_start % (1024 * 1024) == 0 {  // Every 1MB
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        }
        
        progress.finish_with_message(format!("Found {} strings", findings.len()));
        findings
    }
    
    fn get_version(&self) -> &'static str {
        "1.0.1"
    }
}
