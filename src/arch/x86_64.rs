//! x86_64 architecture-specific structures and functions

/// The size of a standard page on x86_64 architecture
pub const PAGE_SIZE: usize = 4096;

/// Page Map Level 4 (PML4) entry bit fields
pub struct PML4Entry(u64);

impl PML4Entry {
    pub fn new(value: u64) -> Self {
        PML4Entry(value)
    }

    pub fn is_present(&self) -> bool {
        (self.0 & 0x1) == 0x1
    }

    pub fn get_physical_address(&self) -> u64 {
        // Bits 51:12 contain the physical page frame number
        // Mask with 0x000F_FFFF_FFFF_F000 to get the physical address
        self.0 & 0x000F_FFFF_FFFF_F000
    }

    pub fn flags(&self) -> u64 {
        // Extract the flags (bits 0-11)
        self.0 & 0xFFF
    }
}

/// Page Directory Pointer Table (PDPT) entry
pub struct PDPTEntry(u64);

impl PDPTEntry {
    pub fn new(value: u64) -> Self {
        PDPTEntry(value)
    }

    pub fn is_present(&self) -> bool {
        (self.0 & 0x1) == 0x1
    }

    pub fn is_page_size_1gb(&self) -> bool {
        // PS bit (Page Size bit, bit 7) is set for 1GB pages
        (self.0 & 0x80) == 0x80
    }

    pub fn get_physical_address(&self) -> u64 {
        self.0 & 0x000F_FFFF_FFFF_F000
    }

    pub fn flags(&self) -> u64 {
        self.0 & 0xFFF
    }
}

/// Page Directory (PD) entry
pub struct PDEntry(u64);

impl PDEntry {
    pub fn new(value: u64) -> Self {
        PDEntry(value)
    }

    pub fn is_present(&self) -> bool {
        (self.0 & 0x1) == 0x1
    }

    pub fn is_page_size_2mb(&self) -> bool {
        // PS bit (Page Size bit, bit 7) is set for 2MB pages
        (self.0 & 0x80) == 0x80
    }

    pub fn get_physical_address(&self) -> u64 {
        self.0 & 0x000F_FFFF_FFFF_F000
    }

    pub fn flags(&self) -> u64 {
        self.0 & 0xFFF
    }
}

/// Page Table (PT) entry
pub struct PTEntry(u64);

impl PTEntry {
    pub fn new(value: u64) -> Self {
        PTEntry(value)
    }

    pub fn is_present(&self) -> bool {
        (self.0 & 0x1) == 0x1
    }

    pub fn get_physical_address(&self) -> u64 {
        self.0 & 0x000F_FFFF_FFFF_F000
    }

    pub fn flags(&self) -> u64 {
        self.0 & 0xFFF
    }
}

/// x86_64 virtual address structure
pub struct VirtualAddress(u64);

impl VirtualAddress {
    pub fn new(addr: u64) -> Self {
        VirtualAddress(addr)
    }

    pub fn addr(&self) -> u64 {
        self.0
    }

    /// Extract PML4 index (bits 39-47)
    pub fn get_pml4_index(&self) -> usize {
        ((self.0 >> 39) & 0x1FF) as usize
    }

    /// Extract PDPT index (bits 30-38)
    pub fn get_pdpt_index(&self) -> usize {
        ((self.0 >> 30) & 0x1FF) as usize
    }

    /// Extract PD index (bits 21-29)
    pub fn get_pd_index(&self) -> usize {
        ((self.0 >> 21) & 0x1FF) as usize
    }

    /// Extract PT index (bits 12-20)
    pub fn get_pt_index(&self) -> usize {
        ((self.0 >> 12) & 0x1FF) as usize
    }

    /// Extract page offset (bits 0-11)
    pub fn get_page_offset(&self) -> usize {
        (self.0 & 0xFFF) as usize
    }

    /// Extract 2MB page offset (bits 0-20)
    pub fn get_large_page_offset(&self) -> usize {
        (self.0 & 0x1F_FFFF) as usize
    }

    /// Extract 1GB page offset (bits 0-29)
    pub fn get_huge_page_offset(&self) -> usize {
        (self.0 & 0x3FFF_FFFF) as usize
    }
}
