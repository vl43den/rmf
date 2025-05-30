# 🕵️‍♂️ RMF - Rust Memory Forensics Toolkit

A modern memory forensics framework written in Rust, designed for analyzing memory dumps for security investigations and incident response.

<p align="center">
  <img src="docs/banner.png" alt="RMF Banner" width="600">
</p>

## Features

🔍 **Memory Analysis Tools**
- Process listing and information extraction
- Module and DLL enumeration
- String extraction and pattern scanning
- Memory address translation and paging support

🔌 **Plugin System**
- Extensible plugin architecture
- Supports built-in and external plugins
- Scan memory for various forensic artifacts

⚡ **Performance**
- Fast memory mapping with minimal overhead
- Built with Rust for memory safety and performance
- Efficient scanning algorithms

🖥️ **User Experience**
- Color-coded terminal output
- Progress bars for long-running operations
- Tabular data presentation

## Installation

### Using Cargo

```bash
cargo install rmf
```

### From Source

```bash
git clone https://github.com/rmf-dev/rmf.git
cd rmf
cargo build --release
```

The binary will be available at `target/release/rmf`.

## Usage

### Basic Commands

```bash
# Display the help message
rmf --help

# Load and analyze a memory dump
rmf load path/to/memory.dump

# List processes in a memory dump
rmf list-procs path/to/memory.dump

# Extract modules
rmf extract-modules path/to/memory.dump output/dir
```

### Advanced Commands

```bash
# Run a specific plugin
rmf run-plugin path/to/memory.dump string_carve

# List all available plugins
rmf list-plugins

# Translate a virtual address to physical
rmf translate path/to/memory.dump 0x7FFFFFFF1000 --dtb 0x1AB000

# Scan for specific patterns
rmf scan path/to/memory.dump --scan-type strings --min-length 10
```

## Supported Formats

RMF currently supports:
- Raw memory dumps
- Windows crash dumps (partial)
- VMware memory dumps

## Creating a Plugin

Plugins can be created by implementing the `MemoryPlugin` trait:

```rust
use rmf::{MemoryImage, MemoryPlugin, Finding};

struct MyPlugin;

impl MemoryPlugin for MyPlugin {
    fn name(&self) -> &'static str {
        "my_plugin"
    }
    
    fn description(&self) -> &'static str {
        "My custom memory analysis plugin"
    }

    fn scan(&self, img: &MemoryImage, progress: &ProgressBar) -> Vec<Finding> {
        // Your analysis code here
        vec![]
    }
}
```

## License

MIT

## Acknowledgements

- The Volatility Framework for inspiration
- The Rust community for amazing libraries
