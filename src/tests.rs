#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use crate::paging::MemoryImage;
    use crate::loader::load_memory_image;

    // Utility function to get path to test files
    fn test_dump_path() -> PathBuf {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("examples");
        path.push("mini_dump.bin");
        path
    }

    #[test]
    fn test_memory_image_creation() {
        let path = test_dump_path();
        let result = load_memory_image(&path);
        assert!(result.is_ok(), "Failed to load test memory image");
        
        let memory_image = result.unwrap();
        assert_eq!(memory_image.size(), 1048576, "Memory image size should be 1MB");
    }

    #[test]
    fn test_read_from_memory_image() {
        let path = test_dump_path();
        let memory_image = load_memory_image(&path).unwrap();
        
        // Test reading bytes
        let bytes = memory_image.get_bytes(0, 16);
        assert!(bytes.is_some(), "Failed to read bytes from memory image");
        assert_eq!(bytes.unwrap().len(), 16, "Should read exactly 16 bytes");
    }

    #[test]
    fn test_virt_to_phys_translation() {
        let path = test_dump_path();
        let memory_image = load_memory_image(&path).unwrap();
        
        // Test basic virtual to physical translation
        let virt_addr = 0x7FFFFFFF1000;
        let phys_addr = memory_image.virt_to_phys(virt_addr);
        
        assert!(phys_addr.is_some(), "Virtual address translation failed");
        assert_eq!(phys_addr.unwrap() & 0xFFF, virt_addr & 0xFFF, 
                   "Page offset should be preserved in translation");
    }
}
