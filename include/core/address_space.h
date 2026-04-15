#pragma once
#include "core/ir.h"
#include "core/error.h"
#include <optional>
#include <vector>
#include <string>

namespace atlus::ir {

// ── Address Space Model ─────────────────────────────────────────────────────────

/**
 * AddressSpace - Defines a coordinate system for addresses.
 * 
 * Each binary has multiple address spaces that must be translatable:
 *   - FileSpace: Byte offsets in the file on disk
 *   - SectionSpace: Offset within a section (for position-independent code)
 *   - ImageSpace: Virtual addresses (RVA + image base)
 *   - RuntimeSpace: Actual runtime virtual addresses (ASLR, rebasing)
 */
enum class AddressSpace : uint8_t {
    None = 0,
    File,       // File offset (0 = start of file)
    Section,    // Offset within section (0 = start of section)
    RVA,        // Relative Virtual Address (image base relative)
    Image,      // Virtual Address (RVA + preferred image base)
    Runtime,    // Actual runtime VA (with ASLR/rebasing)
    
    Count
};

const char* address_space_name(AddressSpace space);

/**
 * QualifiedAddress - Address with explicit space qualification.
 * 
 * Replaces simple Address with full space context.
 */
struct QualifiedAddress {
    uint64_t offset = 0;
    AddressSpace space = AddressSpace::None;
    SectionId section;  // Uses default ctor which sets to Invalid
    
    bool valid() const { return space != AddressSpace::None; }
    
    static QualifiedAddress file(uint64_t off) {
        return QualifiedAddress{off, AddressSpace::File, SectionId{}};
    }
    static QualifiedAddress section(uint64_t off, SectionId sec) {
        return QualifiedAddress{off, AddressSpace::Section, sec};
    }
    static QualifiedAddress rva(uint64_t rva) {
        return QualifiedAddress{rva, AddressSpace::RVA, SectionId{}};
    }
    static QualifiedAddress image(uint64_t va) {
        return QualifiedAddress{va, AddressSpace::Image, SectionId{}};
    }
    static QualifiedAddress runtime(uint64_t va) {
        return QualifiedAddress{va, AddressSpace::Runtime, SectionId{}};
    }
    
    bool operator==(const QualifiedAddress& other) const {
        return offset == other.offset && 
               space == other.space && 
               section == other.section;
    }
    bool operator<(const QualifiedAddress& other) const {
        if (space != other.space) return space < other.space;
        if (section != other.section) return section < other.section;
        return offset < other.offset;
    }
};

// ── Segment / Section Mapping ───────────────────────────────────────────────────

/**
 * SegmentMapping - Formal definition of how file offsets map to virtual memory.
 * 
 * This abstracts PE sections, ELF segments, and Mach-O sections into a
 * unified model. Each segment defines a contiguous mapping from file to memory.
 */
struct SegmentMapping {
    // Identity
    std::string name;           // e.g., ".text", "LOAD", "__TEXT"
    uint32_t segment_type = 0;  // Platform-specific type (e.g., PE section characteristics)
    
    // File coordinates
    uint64_t file_offset = 0;   // Start in file (FileSpace)
    uint64_t file_size = 0;     // Bytes on disk
    
    // Memory coordinates
    uint64_t virtual_address = 0;  // Base VA (ImageSpace)
    uint64_t virtual_size = 0;       // Size in memory (may be > file_size for BSS)
    uint64_t rva = 0;                // Relative to image base (RVASpace)
    
    // Permissions (normalized across formats)
    bool readable = false;
    bool writable = false;
    bool executable = false;
    
    // Alignment requirements
    uint32_t file_alignment = 0x200;     // PE: 0x200, ELF: platform specific
    uint32_t memory_alignment = 0x1000;  // Usually page size
    
    // Section-specific (for position-independent code analysis)
    bool is_position_independent = false;
    
    // Translation: FileSpace <-> ImageSpace
    bool contains_file_offset(uint64_t offset) const {
        return offset >= file_offset && offset < file_offset + file_size;
    }
    bool contains_virtual_address(uint64_t va) const {
        return va >= virtual_address && va < virtual_address + virtual_size;
    }
    bool contains_rva(uint64_t rva_val) const {
        return rva_val >= rva && rva_val < rva + virtual_size;
    }
    
    // Convert file offset to RVA (if in this segment)
    std::optional<uint64_t> file_to_rva(uint64_t file_offset_val) const {
        if (!contains_file_offset(file_offset_val)) return std::nullopt;
        return rva + (file_offset_val - file_offset);
    }
    
    // Convert RVA to file offset
    std::optional<uint64_t> rva_to_file(uint64_t rva_val) const {
        if (!contains_rva(rva_val)) return std::nullopt;
        // Note: virtual_size may exceed file_size (zero-filled BSS sections)
        if (rva_val >= rva + file_size) return std::nullopt;  // In BSS, not in file
        return file_offset + (rva_val - rva);
    }
};

// ── Base Address Model ──────────────────────────────────────────────────────────

/**
 * BaseAddressModel - Tracks image base addressing and rebasing.
 * 
 * PE, ELF, and Mach-O have different base address semantics:
 *   - PE: Preferred base (usually 0x140000000 for x64), ASLR optional
 *   - ELF: Usually 0, position independent by default
 *   - Mach-O: Slide-based ASLR, no fixed base
 */
struct BaseAddressModel {
    // Preferred/compiled base address
    uint64_t preferred_base = 0;
    
    // Actual runtime base (may differ due to ASLR/rebasing)
    uint64_t runtime_base = 0;
    
    // Rebase delta (runtime - preferred)
    int64_t rebase_delta() const {
        return static_cast<int64_t>(runtime_base) - static_cast<int64_t>(preferred_base);
    }
    
    // Is ASLR active?
    bool is_aslr_active() const { return preferred_base != runtime_base; }
    
    // Apply rebase to a VA
    uint64_t apply_rebase(uint64_t preferred_va) const {
        return preferred_va + rebase_delta();
    }
    
    // Remove rebase from runtime VA
    uint64_t remove_rebase(uint64_t runtime_va) const {
        return runtime_va - rebase_delta();
    }
    
    // Space semantics
    uint64_t rva_to_image(uint64_t rva) const {
        return preferred_base + rva;
    }
    uint64_t image_to_rva(uint64_t va) const {
        return va - preferred_base;
    }
};

// ── Relocation Behavior ─────────────────────────────────────────────────────────

/**
 * RelocationType - Types of relocations across formats.
 */
enum class RelocationType : uint8_t {
    None = 0,
    
    // PE/COFF relocations
    Absolute,       // 64-bit absolute address
    High,           // High 16 bits
    Low,            // Low 16 bits
    HighLow,        // 32-bit address
    HighAdj,        // High 16 + adjustment
    Dir64,          // 64-bit RVA (x64 standard)
    
    // ELF relocations (minimal set)
    Elf_32,         // 32-bit absolute
    Elf_64,         // 64-bit absolute
    Elf_PC32,       // 32-bit PC-relative
    Elf_PC64,       // 64-bit PC-relative
    
    // Mach-O relocations
    Macho_Vanilla,  // Direct address
    Macho_Pair,     // High/low pair
    
    // Atlus-specific
    ImageBaseRel,   // Relative to image base
    SectionRel      // Relative to section start
};

/**
 * RelocationEntry - A single fixup location.
 */
struct RelocationEntry {
    QualifiedAddress location;   // Where to apply fixup
    uint64_t addend = 0;         // Value to add (ELF style)
    RelocationType type = RelocationType::None;
    SymbolId symbol;             // Target symbol (if known)
    uint64_t original_value = 0; // Value at location (pre-relocation)
    
    // Apply this relocation given a base address
    bool apply(uint8_t* data, const BaseAddressModel& base) const;
};

/**
 * RelocationTable - All fixups for a binary.
 */
struct RelocationTable {
    std::vector<RelocationEntry> entries;
    
    // Group by target for efficient lookup
    std::unordered_map<uint64_t, std::vector<size_t>> by_target_address;
    
    // Apply all relocations for a given base address
    void apply_relocations(uint8_t* image_data, const BaseAddressModel& base) const;
    
    // Find relocations affecting an address range
    std::vector<RelocationEntry> find_in_range(AddressRange range) const;
};

// ── Address Translation ─────────────────────────────────────────────────────────

/**
 * AddressTranslation - Converts addresses between spaces with full segment awareness.
 * 
 * This is the central hub for all address resolution.
 * Critical for: debugging (x64dbg uses Runtime space),
 *               firmware (file-based only),
 *               ELF/Mach-O (different section models).
 */
class AddressTranslation {
public:
    AddressTranslation();
    
    // Initialize from a loaded binary
    void initialize(const Binary& binary);
    
    // Core translation (returns nullopt if not translatable)
    std::optional<QualifiedAddress> translate(
        QualifiedAddress from,
        AddressSpace to_space
    ) const;
    
    // Convenience: specific translations
    std::optional<uint64_t> file_to_image(uint64_t file_offset) const;
    std::optional<uint64_t> image_to_file(uint64_t va) const;
    std::optional<uint64_t> rva_to_file(uint64_t rva) const;
    std::optional<uint64_t> file_to_rva(uint64_t file_offset) const;
    std::optional<SectionId> find_section_containing(QualifiedAddress addr) const;
    
    // Runtime translation (with rebasing)
    void set_runtime_base(uint64_t actual_base);
    std::optional<uint64_t> image_to_runtime(uint64_t va) const;
    std::optional<uint64_t> runtime_to_image(uint64_t runtime_va) const;
    
    // Validation
    bool is_valid_file_offset(uint64_t offset) const;
    bool is_valid_rva(uint64_t rva) const;
    bool is_valid_image_va(uint64_t va) const;
    
    // Information
    uint64_t preferred_image_base() const { return preferred_base_; }
    uint64_t runtime_image_base() const { return runtime_base_; }
    bool is_rebased() const { return preferred_base_ != runtime_base_; }
    
private:
    uint64_t preferred_base_ = 0;
    uint64_t runtime_base_ = 0;
    uint64_t file_size_ = 0;
    
    struct SectionMap {
        SectionId id;
        uint64_t file_offset;
        uint64_t file_size;
        uint64_t virtual_addr;
        uint64_t virtual_size;
        uint64_t rva;
    };
    std::vector<SectionMap> sections_;
};

// ── Address Range ───────────────────────────────────────────────────────────────

/**
 * AddressRange - A contiguous region in a specific address space.
 */
struct AddressRange {
    QualifiedAddress start;
    QualifiedAddress end;  // Exclusive
    
    bool contains(QualifiedAddress addr) const;
    bool intersects(const AddressRange& other) const;
    std::optional<AddressRange> intersection(const AddressRange& other) const;
    uint64_t size() const;
    
    // Factory for common ranges
    static AddressRange from_section(const Section& section);
    static AddressRange from_function(const Function& fn, const Binary& binary);
};

// ── Memory Model ────────────────────────────────────────────────────────────────

/**
 * MemoryAccess - Describes how to access bytes at an address.
 */
struct MemoryAccess {
    enum class Source { 
        File,           // Direct from file on disk
        MemoryMap,      // Memory-mapped file
        RuntimeProcess  // Live debugged process
    };
    
    Source source = Source::File;
    QualifiedAddress address;
    const uint8_t* data = nullptr;  // Valid if mapped/loaded
    size_t size = 0;
    bool readable = false;
    bool writable = false;
    bool executable = false;
};

/**
 * MemoryModel - Unified view of binary memory.
 * 
 * Abstracts over:
 *   - PE file on disk
 *   - Memory-mapped view
 *   - Live debugged process
 *   - Firmware/flat binaries (no sections)
 */
class MemoryModel {
public:
    virtual ~MemoryModel() = default;
    
    // Read bytes at address (any space)
    virtual std::vector<uint8_t> read(QualifiedAddress addr, size_t len) const = 0;
    
    // Read into buffer (more efficient)
    virtual size_t read_into(QualifiedAddress addr, uint8_t* buffer, size_t len) const = 0;
    
    // Check accessibility
    virtual bool is_readable(QualifiedAddress addr) const = 0;
    virtual bool is_writable(QualifiedAddress addr) const = 0;
    virtual bool is_executable(QualifiedAddress addr) const = 0;
    
    // Get translation layer
    virtual const AddressTranslation& translation() const = 0;
    
    // Address space capabilities
    virtual bool supports_space(AddressSpace space) const = 0;
};

/**
 * PEMemoryModel - Memory model for PE files.
 */
class PEMemoryModel : public MemoryModel {
public:
    explicit PEMemoryModel(const Binary& binary, const BinaryFile& file);
    
    std::vector<uint8_t> read(QualifiedAddress addr, size_t len) const override;
    size_t read_into(QualifiedAddress addr, uint8_t* buffer, size_t len) const override;
    bool is_readable(QualifiedAddress addr) const override;
    bool is_writable(QualifiedAddress addr) const override;
    bool is_executable(QualifiedAddress addr) const override;
    const AddressTranslation& translation() const override { return translation_; }
    bool supports_space(AddressSpace space) const override;
    
private:
    const Binary& binary_;
    const BinaryFile& file_;
    AddressTranslation translation_;
};

/**
 * FirmwareMemoryModel - Memory model for raw firmware/flat binaries.
 * 
 * No sections, no RVAs - just file offsets and optional base address.
 */
class FirmwareMemoryModel : public MemoryModel {
public:
    explicit FirmwareMemoryModel(const BinaryFile& file, uint64_t base_address = 0);
    
    std::vector<uint8_t> read(QualifiedAddress addr, size_t len) const override;
    size_t read_into(QualifiedAddress addr, uint8_t* buffer, size_t len) const override;
    bool is_readable(QualifiedAddress addr) const override;
    bool is_writable(QualifiedAddress addr) const override;
    bool is_executable(QualifiedAddress addr) const override;
    const AddressTranslation& translation() const override { return translation_; }
    bool supports_space(AddressSpace space) const override;
    
private:
    const BinaryFile& file_;
    AddressTranslation translation_;
};

} // namespace atlus::ir
