use std::{fs::File, io::Write, path::PathBuf};
use tempfile::tempdir;

use crate::paging::{MemoryImage, Architecture, PageTableType};
use crate::arch::x86_64::VirtualAddress;
use crate::loader::load_memory_image;

// Create a mock memory dump with page tables
fn create_mock_memory_dump() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let test_dir = tempdir()?;
    let test_file_path = test_dir.path().join("page_test.bin");
    let test_file = test_file_path.clone();
    
    // Create a file of 1MB
    let mut file = File::create(&test_file)?;
    let mut data = vec![0u8; 1024 * 1024];
    
    // PML4 table at offset 0x1000 (simulated CR3)
    let cr3 = 0x1000;
    
    // Create a PML4 entry at PML4[0] pointing to PDPT at 0x2000
    let pml4e_offset = cr3;
    let pdpt_addr = 0x2000;
    let pml4e_value = pdpt_addr | 0x1; // Present bit set
    
    // Write PML4 entry
    data[pml4e_offset..pml4e_offset + 8].copy_from_slice(&pml4e_value.to_le_bytes());
    
    // Create a PDPT entry at PDPT[0] pointing to PD at 0x3000
    let pdpt_offset = pdpt_addr;
    let pd_addr = 0x3000;
    let pdpt_entry = pd_addr | 0x1; // Present bit set
    
    // Write PDPT entry
    data[pdpt_offset..pdpt_offset + 8].copy_from_slice(&pdpt_entry.to_le_bytes());
    
    // Create a PD entry at PD[0] pointing to PT at 0x4000
    let pd_offset = pd_addr;
    let pt_addr = 0x4000;
    let pd_entry = pt_addr | 0x1; // Present bit set
    
    // Write PD entry
    data[pd_offset..pd_offset + 8].copy_from_slice(&pd_entry.to_le_bytes());
    
    // Create a PT entry at PT[0] pointing to a 4KB page at 0x5000
    let pt_offset = pt_addr;
    let page_addr = 0x5000;
    let pt_entry = page_addr | 0x1; // Present bit set
    
    // Write PT entry
    data[pt_offset..pt_offset + 8].copy_from_slice(&pt_entry.to_le_bytes());
    
    // Write some recognizable data at the physical page
    let test_data = b"TESTPAGE"; 
    data[page_addr..page_addr + test_data.len()].copy_from_slice(test_data);
    
    // Write the data to the file
    file.write_all(&data)?;
    file.sync_all()?;
    
    // Keep directory from being deleted
    std::mem::forget(test_dir);
    
    Ok(test_file)
}

#[test]
fn test_address_translation_page_walk() -> Result<(), Box<dyn std::error::Error>> {
    let test_file = create_mock_memory_dump()?;
    
    let mut memory_image = load_memory_image(&test_file)?;
    
    // Set the CR3 value
    memory_image.set_cr3(0x1000);
    
    // Create a virtual address that should map to our test page
    let virtual_addr = 0x0;  // This will use PT[0], PD[0], PDPT[0], PML4[0]
    
    // Test the translation
    let physical_addr = memory_image.virt_to_phys(virtual_addr);
    
    assert!(physical_addr.is_some(), "Failed to translate virtual address");
    assert_eq!(physical_addr.unwrap(), 0x5000, "Incorrect physical address translation");
    
    // Test reading the data at the translated address
    let test_data = b"TESTPAGE";
    let data = memory_image.get_bytes(physical_addr.unwrap() as usize, test_data.len());
    
    assert!(data.is_some(), "Failed to read data at physical address");
    assert_eq!(data.unwrap(), test_data, "Data at physical address doesn't match expected value");
    
    // Test virtual address component extraction
    let va = VirtualAddress::new(0x123456789000);
    assert_eq!(va.get_pml4_index(), 0x1, "Wrong PML4 index");
    assert_eq!(va.get_pdpt_index(), 0x23, "Wrong PDPT index");
    assert_eq!(va.get_pd_index(), 0x45, "Wrong PD index");
    assert_eq!(va.get_pt_index(), 0x67, "Wrong PT index");
    assert_eq!(va.get_page_offset(), 0x789, "Wrong page offset");
    
    Ok(())
}

#[test]
fn test_large_page_translation() -> Result<(), Box<dyn std::error::Error>> {
    let test_dir = tempdir()?;
    let test_file_path = test_dir.path().join("large_page_test.bin");
    
    // Create a file of 2MB
    let mut file = File::create(&test_file_path)?;
    let mut data = vec![0u8; 2 * 1024 * 1024];
    
    // PML4 table at offset 0x1000 (simulated CR3)
    let cr3 = 0x1000;
    
    // Create a PML4 entry at PML4[0] pointing to PDPT at 0x2000
    let pml4e_offset = cr3;
    let pdpt_addr = 0x2000;
    let pml4e_value = pdpt_addr | 0x1; // Present bit set
    
    // Write PML4 entry
    data[pml4e_offset..pml4e_offset + 8].copy_from_slice(&pml4e_value.to_le_bytes());
    
    // Create a PDPT entry at PDPT[0] pointing to PD at 0x3000
    let pdpt_offset = pdpt_addr;
    let pd_addr = 0x3000;
    let pdpt_entry = pd_addr | 0x1; // Present bit set
    
    // Write PDPT entry
    data[pdpt_offset..pdpt_offset + 8].copy_from_slice(&pdpt_entry.to_le_bytes());
    
    // Create a PD entry at PD[0] for a 2MB page at 0x100000
    let pd_offset = pd_addr;
    let large_page_addr = 0x100000;
    // PS bit (bit 7) set for 2MB page
    let pd_entry = large_page_addr | 0x1 | 0x80; 
    
    // Write PD entry
    data[pd_offset..pd_offset + 8].copy_from_slice(&pd_entry.to_le_bytes());
    
    // Write some recognizable data at the large page
    let test_data = b"LARGEPAGE"; 
    data[large_page_addr..large_page_addr + test_data.len()].copy_from_slice(test_data);
    
    // Write more data at an offset within the large page
    let offset_data = b"OFFSET_DATA";
    let offset = 0x1000; // 4KB into the large page
    data[large_page_addr + offset..large_page_addr + offset + offset_data.len()]
        .copy_from_slice(offset_data);
    
    // Write the data to the file
    file.write_all(&data)?;
    file.sync_all()?;
    
    let mut memory_image = load_memory_image(&test_file_path)?;
    
    // Set the CR3 value
    memory_image.set_cr3(0x1000);
    
    // Test the translation to the start of the large page
    let virtual_addr_base = 0x0;  // Uses PD[0] with PS=1
    let physical_addr_base = memory_image.virt_to_phys(virtual_addr_base);
    
    assert!(physical_addr_base.is_some(), "Failed to translate large page base address");
    assert_eq!(physical_addr_base.unwrap(), large_page_addr, 
              "Incorrect large page physical address translation");
    
    // Test the translation with an offset into the large page
    let virtual_addr_offset = virtual_addr_base + offset;
    let physical_addr_offset = memory_image.virt_to_phys(virtual_addr_offset);
    
    assert!(physical_addr_offset.is_some(), "Failed to translate address with offset in large page");
    assert_eq!(physical_addr_offset.unwrap(), large_page_addr + offset, 
              "Incorrect offset translation in large page");
    
    // Test reading the data at the offset
    let data = memory_image.get_bytes(physical_addr_offset.unwrap() as usize, offset_data.len());
    assert!(data.is_some(), "Failed to read data at offset in large page");
    assert_eq!(data.unwrap(), offset_data, "Data at offset doesn't match expected value");
    
    Ok(())
}
