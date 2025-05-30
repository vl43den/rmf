// Example credential scanner plugin for RMF
// 
// This plugin demonstrates how to create an external plugin for the RMF framework.
// It scans memory for common credential patterns like passwords, API keys, etc.

use std::collections::HashMap;
use indicatif::ProgressBar;
use rmf::{MemoryImage, MemoryPlugin, Finding};

#[derive(Default)]
pub struct CredentialScannerPlugin;

// Common credential patterns to scan for
const CREDENTIAL_PATTERNS: &[(&str, &str, u8)] = &[
    ("password=", "Password field", 90),
    ("apikey=", "API Key", 85),
    ("token=", "Authentication token", 80),
    ("secret=", "Secret key", 85),
    ("pwd=", "Password field (abbreviated)", 70),
    ("pass=", "Password field (abbreviated)", 75),
    ("login:", "Login prompt", 60),
    ("Bearer ", "OAuth Bearer token", 90),
    ("-----BEGIN PRIVATE KEY-----", "Private key", 100),
    ("-----BEGIN RSA PRIVATE KEY-----", "RSA private key", 100),
    ("aws_secret_access_key", "AWS secret key", 95),
    ("AKIA", "AWS access key ID", 90),  // AWS keys start with AKIA
];

impl MemoryPlugin for CredentialScannerPlugin {
    fn name(&self) -> &'static str {
        "credential_scanner"
    }
    
    fn description(&self) -> &'static str {
        "Scans memory for potential credentials and secrets"
    }
    
    fn get_version(&self) -> &'static str {
        "1.0.0"
    }

    fn scan(&self, img: &MemoryImage, progress: &ProgressBar) -> Vec<Finding> {
        let mut findings = Vec::new();
        let size = img.size();
        
        // Set up progress bar
        progress.set_length(size as u64);
        progress.set_message("Scanning for credentials");
        
        // We'll scan in 4KB chunks
        let chunk_size = 4096;
        
        for chunk_start in (0..size).step_by(chunk_size) {
            // Update progress
            progress.set_position(chunk_start as u64);
            
            if let Some(chunk) = img.get_bytes(chunk_start, chunk_size) {
                // Convert chunk to string for pattern matching
                // This isn't efficient but works for demonstration
                if let Ok(chunk_str) = String::from_utf8_lossy(chunk).to_lowercase().into_string() {
                    for &(pattern, desc, confidence) in CREDENTIAL_PATTERNS {
                        // Find all occurrences of the pattern
                        let mut start_idx = 0;
                        while let Some(pos) = chunk_str[start_idx..].find(pattern.to_lowercase().as_str()) {
                            let abs_pos = start_idx + pos;
                            
                            // Extract context (up to 32 chars) after the pattern
                            let context_end = (abs_pos + pattern.len() + 32).min(chunk_str.len());
                            let value = &chunk_str[abs_pos..context_end];
                            
                            // Create details map
                            let mut details = HashMap::new();
                            details.insert("type".to_string(), "credential".to_string());
                            details.insert("pattern".to_string(), pattern.to_string());
                            details.insert("risk".to_string(), "high".to_string());
                            
                            findings.push(Finding {
                                plugin: self.name().to_string(),
                                addr: (chunk_start + abs_pos) as u64,
                                desc: format!("{}: {}", desc, value),
                                confidence,
                                details,
                            });
                            
                            // Move past this occurrence
                            start_idx = abs_pos + pattern.len();
                        }
                    }
                }
            }
            
            // Don't hog the CPU
            if chunk_start % (1024 * 1024) == 0 {  // Every 1MB
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }
        
        progress.finish_with_message(format!("Found {} potential credentials", findings.len()));
        findings
    }
}

// Export a function that creates a new instance of our plugin
#[no_mangle]
pub extern "C" fn create_plugin() -> Box<dyn MemoryPlugin> {
    Box::new(CredentialScannerPlugin::default())
}
