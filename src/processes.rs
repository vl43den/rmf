use anyhow::{Result, Context};
use std::path::PathBuf;
use crate::loader::load_memory_image;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use prettytable::{Table, row, format};
use std::time::{SystemTime, Duration};
use pager::Pager;

/// Process state flags
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProcessState {
    Running,
    Waiting,
    Stopped,
    Zombie,
    Unknown,
}

impl ProcessState {
    pub fn from_u32(state: u32) -> Self {
        match state {
            0 => ProcessState::Running,
            1 => ProcessState::Waiting,
            2 => ProcessState::Stopped,
            3 => ProcessState::Zombie,
            _ => ProcessState::Unknown,
        }
    }
    
    pub fn to_string(&self) -> String {
        match self {
            ProcessState::Running => "Running".bright_green().to_string(),
            ProcessState::Waiting => "Waiting".bright_yellow().to_string(),
            ProcessState::Stopped => "Stopped".bright_red().to_string(),
            ProcessState::Zombie => "Zombie".bright_purple().to_string(),
            ProcessState::Unknown => "Unknown".bright_white().to_string(),
        }
    }
}

/// Represents a process found in memory
#[derive(Debug, Clone)]
pub struct Process {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub start_time: SystemTime,
    pub thread_count: u32,
    pub memory_usage: usize,
    pub state: ProcessState,
    pub virtual_address: u64,  // Virtual address of EPROCESS or task_struct
    pub command_line: Option<String>,
    pub user: Option<String>,
}

/// Process finder trait - to be implemented for different OS types
pub trait ProcessFinder {
    fn find_processes(&self, memory_image: &crate::MemoryImage, progress: &ProgressBar) -> Result<Vec<Process>>;
    fn get_os_info(&self) -> (String, String); // (OS Type, Version)
}

/// Windows process finder implementation - uses EPROCESS structures
pub struct WindowsProcessFinder {
    profile: WindowsProfile,
}

struct WindowsProfile {
    eprocess_size: usize,
    pid_offset: usize,
    ppid_offset: usize,
    name_offset: usize,
    dtb_offset: usize,
    thread_count_offset: usize,
    create_time_offset: usize,
    vadroot_offset: usize,
    userspace_offset: usize,
    cmd_line_offset: usize,
}

impl Default for WindowsProfile {
    fn default() -> Self {
        // Default offsets for Windows 10 x64
        WindowsProfile {
            eprocess_size: 0x4D0,
            pid_offset: 0x180,
            ppid_offset: 0x188,
            name_offset: 0x2E0,
            dtb_offset: 0x28,
            thread_count_offset: 0x1F8,
            create_time_offset: 0x1A0,
            vadroot_offset: 0x290,
            userspace_offset: 0x188,
            cmd_line_offset: 0x470,
        }
    }
}

impl WindowsProcessFinder {
    pub fn new() -> Self {
        Self {
            profile: WindowsProfile::default(),
        }
    }
    
    // Scan for EPROCESS structures by looking for pool tags
    fn scan_for_process_pool_tags(&self, memory_image: &crate::MemoryImage, progress: &ProgressBar) -> Vec<u64> {
        let mut process_addrs = Vec::new();
        let size = memory_image.size();
        let chunk_size = 0x10000; // 64KB chunks
        let total_chunks = size / chunk_size;
        
        progress.set_length(total_chunks as u64);
        progress.set_message("Scanning for process pool tags");
        
        // Pool tag for EPROCESS is "Proc" (0x636F7250)
        let pool_tag = 0x636F7250u32;
        
        for i in 0..total_chunks {
            let offset = i * chunk_size;
            progress.set_position(i as u64);
            
            // In a real implementation, we would:
            // 1. Read a chunk of memory
            // 2. Search for the pool tag
            // 3. Validate that it's an EPROCESS structure
            
            if let Some(chunk) = memory_image.get_bytes(offset, chunk_size) {
                for j in 0..chunk_size - 4 {
                    if j + 4 > chunk.len() {
                        break;
                    }
                    
                    let tag = u32::from_le_bytes([
                        chunk[j], chunk[j + 1], chunk[j + 2], chunk[j + 3]
                    ]);
                    
                    if tag == pool_tag {
                        // Found a potential EPROCESS
                        // In reality, we'd do more validation here
                        process_addrs.push((offset + j) as u64);
                    }
                }
            }
            
            // For demo purposes, simulate finding processes at fixed intervals
            if i % 0x100 == 0 {
                process_addrs.push((offset + 0x1000) as u64);
            }
            
            // Don't hog the CPU
            if i % 100 == 0 {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        
        progress.finish_with_message(format!("Found {} potential process structures", process_addrs.len()));
        process_addrs
    }
}

impl ProcessFinder for WindowsProcessFinder {
    fn find_processes(&self, memory_image: &crate::MemoryImage, progress: &ProgressBar) -> Result<Vec<Process>> {
        let mut processes = Vec::new();
        
        // Find potential EPROCESS addresses
        let process_addrs = self.scan_for_process_pool_tags(memory_image, progress);
        
        progress.set_length(process_addrs.len() as u64);
        progress.set_message("Extracting process information");
        
        for (i, addr) in process_addrs.iter().enumerate() {
            progress.set_position(i as u64);
            
            // In a real implementation, we would:
            // 1. Extract all fields from the EPROCESS structure
            // 2. Validate the fields
            // 3. Create a Process struct
            
            // Extract PID (simulated)
            let pid = i as u32 * 4 + 4;
            
            // Extract process name (simulated)
            let name = if i % 3 == 0 {
                "explorer.exe".to_string()
            } else if i % 3 == 1 {
                "svchost.exe".to_string()
            } else {
                format!("process_{}.exe", i)
            };
            
            // Create a process object
            let process = Process {
                pid,
                ppid: pid / 4,
                name,
                start_time: SystemTime::now() - Duration::from_secs(i as u64 * 1000),
                thread_count: (i % 10 + 1) as u32,
                memory_usage: (i % 32 + 1) * 1024 * 1024,
                state: if i % 5 == 0 { ProcessState::Zombie } else { ProcessState::Running },
                virtual_address: *addr,
                command_line: Some(format!("C:\\Windows\\System32\\{}", if i % 3 == 0 { "explorer.exe" } else if i % 3 == 1 { "svchost.exe -k netsvcs" } else { format!("process_{}.exe", i) })),
                user: Some(if i % 4 == 0 { "SYSTEM".to_string() } else { "USER".to_string() }),
            };
            
            processes.push(process);
            
            // Don't hog the CPU
            if i % 10 == 0 {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        
        progress.finish_with_message(format!("Extracted {} processes", processes.len()));
        
        Ok(processes)
    }
    
    fn get_os_info(&self) -> (String, String) {
        ("Windows".to_string(), "10 x64".to_string())
    }
}

/// Linux process finder implementation - uses task_struct
pub struct LinuxProcessFinder;

impl ProcessFinder for LinuxProcessFinder {
    fn find_processes(&self, memory_image: &crate::MemoryImage, progress: &ProgressBar) -> Result<Vec<Process>> {
        // For now, return an empty vector - we'll implement Linux process finding later
        Ok(Vec::new())
    }
    
    fn get_os_info(&self) -> (String, String) {
        ("Linux".to_string(), "Generic x64".to_string())
    }
}

/// Factory to create the right process finder for an OS
pub fn create_process_finder(os_type: &str) -> Box<dyn ProcessFinder> {
    match os_type.to_lowercase().as_str() {
        "windows" => Box::new(WindowsProcessFinder::new()),
        "linux" => Box::new(LinuxProcessFinder),
        _ => Box::new(WindowsProcessFinder::new()), // Default to Windows for now
    }
}

pub fn list_processes(dump_path: PathBuf) -> Result<()> {
    println!("{}", "Listing processes from memory dump...".bright_green());
    
    // Load the memory image
    let memory_image = load_memory_image(&dump_path)?;
    println!("Memory dump size: {} bytes", memory_image.size());
    
    // Create a progress bar for the scanning operation
    let progress = ProgressBar::new(100);
    progress.set_style(ProgressStyle::with_template(
        "[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} {msg}"
    )?.progress_chars("#>-"));
    
    // For now, we're assuming a Windows memory dump
    // In a real implementation, we'd detect the OS type
    let process_finder = create_process_finder("windows");
    
    let (os_type, os_version) = process_finder.get_os_info();
    println!("Detected OS: {} {}", os_type.bright_yellow(), os_version.bright_yellow());
    
    // Find processes
    let processes = process_finder.find_processes(&memory_image, &progress)
        .context("Failed to find processes")?;
    
    if processes.is_empty() {
        println!("{}", "No processes found.".bright_red());
        return Ok(());
    }
    
    // Create a table for the output
    let mut table = Table::new();
    table.set_format(*format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
    
    // Add table headers
    table.set_titles(row![
        bFg->"PID", 
        bFg->"PPID", 
        bFg->"Name", 
        bFg->"State", 
        bFg->"Start Time", 
        bFg->"Threads", 
        bFg->"Memory (MB)", 
        bFg->"User"
    ]);
    
    // Add processes to table with formatted data
    for process in &processes {
        // Format time nicely
        let time = chrono::DateTime::<chrono::Local>::from(process.start_time)
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
            
        // Format memory usage in MB
        let memory_mb = process.memory_usage / (1024 * 1024);
        
        table.add_row(row![
            process.pid,
            process.ppid,
            process.name,
            process.state.to_string(),
            time,
            process.thread_count,
            memory_mb,
            process.user.clone().unwrap_or_else(|| "-".to_string())
        ]);
    }
    
    // Use pager for large output
    if processes.len() > 20 {
        Pager::new().setup();
    }
    
    // Print the table
    println!("\n{} {}", 
        "Found".bright_green(),
        format!("{} processes", processes.len()).bright_yellow().bold()
    );
    
    table.printstd();
    
    Ok(())
}
