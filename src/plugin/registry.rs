//! Plugin registry system for memory forensics plugins

use anyhow::{Result, Context};
use colored::*;
use indicatif::ProgressBar;
use std::{collections::HashMap, sync::{RwLock, Arc}, path::PathBuf};
use crate::paging::MemoryImage;

/// Represents a finding from a memory forensics plugin
#[derive(Debug, Clone)]
pub struct Finding {
    pub plugin: String,
    pub addr: u64,
    pub desc: String,
    pub confidence: u8, // 0-100 confidence level
    pub details: HashMap<String, String>, // Additional details as key-value pairs
}

/// Core trait for memory forensics plugins
pub trait MemoryPlugin: Send + Sync {
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn scan(&self, img: &MemoryImage, progress: &ProgressBar) -> Vec<Finding>;
    fn get_version(&self) -> &'static str {
        "1.0.0" // Default version
    }
}

/// Registry of available plugins
#[derive(Default)]
pub struct PluginRegistry {
    plugins: HashMap<String, Box<dyn MemoryPlugin>>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
        }
    }
    
    pub fn register(&mut self, plugin: Box<dyn MemoryPlugin>) {
        self.plugins.insert(plugin.name().to_string(), plugin);
    }
    
    pub fn get(&self, name: &str) -> Option<&Box<dyn MemoryPlugin>> {
        self.plugins.get(name)
    }
    
    pub fn list_plugins(&self) -> Vec<(String, String, String)> {
        self.plugins.iter()
            .map(|(k, v)| (k.clone(), v.description().to_string(), v.get_version().to_string()))
            .collect()
    }
    
    /// Attempt to load an external plugin from a dynamic library
    #[cfg(all(unix, feature = "plugins"))]
    pub fn load_plugin_from_file(&mut self, path: &PathBuf) -> Result<()> {
        use libloading::{Library, Symbol};
        
        // Load the dynamic library
        let lib = unsafe { Library::new(path) }
            .with_context(|| format!("Failed to load plugin from {}", path.display()))?;
        
        // Get the plugin creation function
        let create_plugin: Symbol<unsafe fn() -> Box<dyn MemoryPlugin>> = unsafe {
            lib.get(b"create_plugin")
                .with_context(|| format!("Symbol 'create_plugin' not found in {}", path.display()))?
        };
        
        // Create the plugin
        let plugin = unsafe { create_plugin() };
        
        // Register the plugin
        self.register(plugin);
        
        // Keep the library loaded
        // In a real implementation, we'd keep track of loaded libraries
        // to prevent them from being dropped and unloaded
        std::mem::forget(lib);
        
        Ok(())
    }
    
    #[cfg(all(windows, feature = "plugins"))]
    pub fn load_plugin_from_file(&mut self, path: &PathBuf) -> Result<()> {
        use libloading::{Library, Symbol};
        
        // Load the dynamic library
        let lib = unsafe { Library::new(path) }
            .with_context(|| format!("Failed to load plugin from {}", path.display()))?;
        
        // Get the plugin creation function
        let create_plugin: Symbol<unsafe fn() -> Box<dyn MemoryPlugin>> = unsafe {
            lib.get(b"create_plugin")
                .with_context(|| format!("Symbol 'create_plugin' not found in {}", path.display()))?
        };
        
        // Create the plugin
        let plugin = unsafe { create_plugin() };
        
        // Register the plugin
        self.register(plugin);
        
        // Keep the library loaded
        std::mem::forget(lib);
        
        Ok(())
    }
}

// Global plugin registry
lazy_static::lazy_static! {
    static ref PLUGIN_REGISTRY: Arc<RwLock<PluginRegistry>> = Arc::new(RwLock::new(PluginRegistry::new()));
}

/// Get a reference to the global plugin registry
pub fn get_plugin_registry() -> Arc<RwLock<PluginRegistry>> {
    PLUGIN_REGISTRY.clone()
}
