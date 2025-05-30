use anyhow::Result;
use memmap2::Mmap;

use crate::arch::x86_64::{
    PML4Entry, PDPTEntry, PDEntry, PTEntry, VirtualAddress, PAGE_SIZE
};

/// Different CPU architectures supported by the memory forensics tool
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Architecture {
    X86_64,
    // Other architectures could be added here in the future
}

/// Different page table types for memory dumps
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PageTableType {
    /// Standard 4-level paging on x86_64
    Standard,
    /// 5-level paging for newer x86_64 CPUs
    FiveLevel,
}

/// Memory image information
#[derive(Debug)]
pub struct MemoryImageInfo {
    pub arch: Architecture,
    pub page_table_type: PageTableType,
    pub cr3: Option<u64>,   // Control register 3 (page table base)
    pub dtb: Option<u64>,   // Directory Table Base (another name for CR3)
    pub size: usize,        // Size of the memory image in bytes
}

#[derive(Debug)]
pub struct MemoryImage {
    mmap: Mmap,
    // Memory image information and metadata
    pub info: MemoryImageInfo,
}

impl MemoryImage {
    pub fn new(mmap: Mmap) -> Self {
        let size = mmap.len();
        Self { 
            mmap,
            info: MemoryImageInfo {
                arch: Architecture::X86_64,
                page_table_type: PageTableType::Standard,
                cr3: None,
                dtb: None,
                size,
            }
        }
    }

    pub fn size(&self) -> usize {
        self.info.size
    }

    /// Set the CR3 register value for this memory image
    pub fn set_cr3(&mut self, cr3: u64) -> &mut Self {
        self.info.cr3 = Some(cr3);
        self.info.dtb = Some(cr3);
        self
    }

    pub fn get_bytes(&self, offset: usize, len: usize) -> Option<&[u8]> {
        if offset + len <= self.info.size {
            Some(&self.mmap[offset..offset + len])
        } else {
            None
        }
    }

    /// Virtual to physical address translation for x86_64
    pub fn virt_to_phys(&self, virt_addr: u64) -> Option<u64> {
        // If we don't have a DTB/CR3, we can't do translation
        let dtb = self.info.dtb?;
        
        // Create a virtual address structure
        let va = VirtualAddress::new(virt_addr);
        
        // Extract indices
        let pml4_idx = va.get_pml4_index();
        let pdpt_idx = va.get_pdpt_index();
        let pd_idx = va.get_pd_index();
        let pt_idx = va.get_pt_index();
        let offset = va.get_page_offset();
        
        // Get PML4 entry using DTB as PML4 table base
        let pml4e_addr = dtb + (pml4_idx * 8) as u64;
        let pml4e_val = self.read_u64(pml4e_addr as usize)?;
        let pml4e = PML4Entry::new(pml4e_val);
        
        if !pml4e.is_present() {
            return None;
        }
        
        // Get PDPT entry
        let pdpt_base = pml4e.get_physical_address();
        let pdpte_addr = pdpt_base + (pdpt_idx * 8) as u64;
        let pdpte_val = self.read_u64(pdpte_addr as usize)?;
        let pdpte = PDPTEntry::new(pdpte_val);
        
        if !pdpte.is_present() {
            return None;
        }
        
        // Check if this is a 1GB page
        if pdpte.is_page_size_1gb() {
            let huge_page_offset = va.get_huge_page_offset();
            return Some(pdpte.get_physical_address() + huge_page_offset as u64);
        }
        
        // Get PD entry
        let pd_base = pdpte.get_physical_address();
        let pde_addr = pd_base + (pd_idx * 8) as u64;
        let pde_val = self.read_u64(pde_addr as usize)?;
        let pde = PDEntry::new(pde_val);
        
        if !pde.is_present() {
            return None;
        }
        
        // Check if this is a 2MB page
        if pde.is_page_size_2mb() {
            let large_page_offset = va.get_large_page_offset();
            return Some(pde.get_physical_address() + large_page_offset as u64);
        }
        
        // Get PT entry
        let pt_base = pde.get_physical_address();
        let pte_addr = pt_base + (pt_idx * 8) as u64;
        let pte_val = self.read_u64(pte_addr as usize)?;
        let pte = PTEntry::new(pte_val);
        
        if !pte.is_present() {
            return None;
        }
        
        // Calculate the final physical address
        Some(pte.get_physical_address() + offset as u64)
    }
    
    /// Read a u64 value from the memory image at the given offset
    pub fn read_u64(&self, offset: usize) -> Option<u64> {
        if offset + 8 <= self.info.size {
            let bytes = &self.mmap[offset..offset + 8];
            let value = u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], 
                bytes[4], bytes[5], bytes[6], bytes[7]
            ]);
            Some(value)
        } else {
            None
        }
    }
    
    /// Read a u32 value from the memory image
    pub fn read_u32(&self, offset: usize) -> Option<u32> {
        if offset + 4 <= self.info.size {
            let bytes = &self.mmap[offset..offset + 4];
            let value = u32::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3]
            ]);
            Some(value)
        } else {
            None
        }
    }
    
    /// Read a null-terminated ASCII string from the memory image
    pub fn read_ascii_string(&self, offset: usize, max_len: usize) -> Option<String> {
        if offset >= self.info.size {
            return None;
        }
        
        let mut end = offset;
        let max_end = std::cmp::min(offset + max_len, self.info.size);
        
        // Find the null terminator
        while end < max_end && self.mmap[end] != 0 {
            end += 1;
        }
        
        // Convert the bytes to a string
        let string_bytes = &self.mmap[offset..end];
        String::from_utf8(string_bytes.to_vec()).ok()
    }
    
    /// Read a null-terminated UTF-16 (wide) string from the memory image
    pub fn read_utf16_string(&self, offset: usize, max_len: usize) -> Option<String> {
        if offset + 1 >= self.info.size {
            return None;
        }
        
        let mut chars = Vec::new();
        let max_chars = max_len / 2;
        
        for i in 0..max_chars {
            if offset + (i * 2) + 1 >= self.info.size {
                break;
            }
            
            let low = self.mmap[offset + (i * 2)] as u16;
            let high = self.mmap[offset + (i * 2) + 1] as u16;
            let c = low | (high << 8);
            
            if c == 0 {
                break;
            }
            
            chars.push(c);
        }
        
        String::from_utf16(&chars).ok()
    }
}
