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
