#include "core/ir.h"
#include "core/error.h"
#include "core/loader.h"

namespace atlus::parsers {

// ELF format support
namespace elf {

// ELF header structures (simplified)
#pragma pack(push, 1)
struct Elf64_Ehdr {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct Elf64_Phdr {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
};

struct Elf64_Shdr {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
};

struct Elf64_Sym {
    uint32_t st_name;
    uint8_t  st_info;
    uint8_t  st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
};
#pragma pack(pop)

// ELF parser
class ELFParser {
public:
    Result<std::unique_ptr<ir::Binary>> parse(const BinaryFile& file) {
        if (file.size() < sizeof(Elf64_Ehdr)) {
            return ATLUS_MAKE_ERROR(ErrorCode::InvalidFormat, "File too small for ELF header");
        }
        
        const auto* ehdr = reinterpret_cast<const Elf64_Ehdr*>(file.bytes());
        
        // Check magic
        if (ehdr->e_ident[0] != 0x7F || 
            ehdr->e_ident[1] != 'E' ||
            ehdr->e_ident[2] != 'L' ||
            ehdr->e_ident[3] != 'F') {
            return ATLUS_MAKE_ERROR(ErrorCode::InvalidFormat, "Invalid ELF magic");
        }
        
        // Check 64-bit
        if (ehdr->e_ident[4] != 2) {  // ELFCLASS64
            return ATLUS_MAKE_ERROR(ErrorCode::UnsupportedFormat, "Only 64-bit ELF supported");
        }
        
        // Create binary
        auto binary = std::make_unique<ir::Binary>(file.path, 0, true);
        
        // Parse program headers (segments)
        for (uint16_t i = 0; i < ehdr->e_phnum; ++i) {
            uint64_t phdr_offset = ehdr->e_phoff + i * ehdr->e_phentsize;
            if (phdr_offset + sizeof(Elf64_Phdr) > file.size()) continue;
            
            const auto* phdr = reinterpret_cast<const Elf64_Phdr*>(file.bytes() + phdr_offset);
            
            if (phdr->p_type != 1) continue;  // PT_LOAD only
            
            // Create section for this segment
            ir::Section sec;
            sec.name = "LOAD" + std::to_string(i);
            sec.file_offset = {phdr->p_offset, ir::Address::Space::FileOffset};
            sec.rva = {phdr->p_vaddr, ir::Address::Space::RVA};
            sec.virtual_addr = {phdr->p_vaddr, ir::Address::Space::Virtual};
            sec.virtual_size = static_cast<uint32_t>(phdr->p_memsz);
            sec.raw_size = static_cast<uint32_t>(phdr->p_filesz);
            sec.is_readable = (phdr->p_flags & 4) != 0;
            sec.is_writable = (phdr->p_flags & 2) != 0;
            sec.is_executable = (phdr->p_flags & 1) != 0;
            
            binary->create_section(sec);
        }
        
        // Parse section headers
        for (uint16_t i = 0; i < ehdr->e_shnum; ++i) {
            uint64_t shdr_offset = ehdr->e_shoff + i * ehdr->e_shentsize;
            if (shdr_offset + sizeof(Elf64_Shdr) > file.size()) continue;
            
            const auto* shdr = reinterpret_cast<const Elf64_Shdr*>(file.bytes() + shdr_offset);
            
            // Skip null section
            if (shdr->sh_type == 0) continue;
            
            // Could create additional sections here
        }
        
        return binary;
    }
};

} // namespace elf

// Mach-O format support
namespace macho {

// Mach-O header structures (simplified)
#pragma pack(push, 1)
struct Macho64_Header {
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
};

struct LoadCommand {
    uint32_t cmd;
    uint32_t cmdsize;
};

struct SegmentCommand64 {
    uint32_t cmd;
    uint32_t cmdsize;
    char     segname[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    uint32_t maxprot;
    uint32_t initprot;
    uint32_t nsects;
    uint32_t flags;
};

struct Section64 {
    char     sectname[16];
    char     segname[16];
    uint64_t addr;
    uint64_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
};
#pragma pack(pop)

// Mach-O parser
class MachOParser {
public:
    static constexpr uint32_t MH_MAGIC_64 = 0xfeedfacf;
    static constexpr uint32_t CPU_TYPE_X86_64 = 0x01000007;
    
    Result<std::unique_ptr<ir::Binary>> parse(const BinaryFile& file) {
        if (file.size() < sizeof(Macho64_Header)) {
            return ATLUS_MAKE_ERROR(ErrorCode::InvalidFormat, "File too small for Mach-O header");
        }
        
        const auto* hdr = reinterpret_cast<const Macho64_Header*>(file.bytes());
        
        // Check magic
        if (hdr->magic != MH_MAGIC_64) {
            return ATLUS_MAKE_ERROR(ErrorCode::InvalidFormat, "Invalid Mach-O magic");
        }
        
        // Check architecture
        if (hdr->cputype != CPU_TYPE_X86_64) {
            return ATLUS_MAKE_ERROR(ErrorCode::UnsupportedFormat, "Unsupported CPU type");
        }
        
        // Create binary
        auto binary = std::make_unique<ir::Binary>(file.path, 0x100000000, true);
        
        // Parse load commands
        uint64_t cmd_offset = sizeof(Macho64_Header);
        for (uint32_t i = 0; i < hdr->ncmds && cmd_offset < file.size(); ++i) {
            const auto* cmd = reinterpret_cast<const LoadCommand*>(file.bytes() + cmd_offset);
            
            if (cmd->cmd == 0x19) {  // LC_SEGMENT_64
                const auto* seg = reinterpret_cast<const SegmentCommand64*>(cmd);
                
                ir::Section sec;
                sec.name = std::string(seg->segname, 16);
                // Remove null terminators
                size_t null_pos = sec.name.find('\0');
                if (null_pos != std::string::npos) {
                    sec.name.resize(null_pos);
                }
                
                sec.file_offset = {seg->fileoff, ir::Address::Space::FileOffset};
                sec.rva = {seg->vmaddr - 0x100000000, ir::Address::Space::RVA};  // Adjust for base
                sec.virtual_addr = {seg->vmaddr, ir::Address::Space::Virtual};
                sec.virtual_size = static_cast<uint32_t>(seg->vmsize);
                sec.raw_size = static_cast<uint32_t>(seg->filesize);
                
                // Parse protection flags
                sec.is_readable = (seg->initprot & 1) != 0;
                sec.is_writable = (seg->initprot & 2) != 0;
                sec.is_executable = (seg->initprot & 4) != 0;
                
                binary->create_section(sec);
                
                // Parse sub-sections
                const auto* sections = reinterpret_cast<const Section64*>(
                    reinterpret_cast<const uint8_t*>(seg) + sizeof(SegmentCommand64)
                );
                
                for (uint32_t j = 0; j < seg->nsects && 
                     cmd_offset + sizeof(SegmentCommand64) + (j+1) * sizeof(Section64) <= cmd_offset + cmd->cmdsize; 
                     ++j) {
                    // Could create sub-sections here
                }
            }
            
            cmd_offset += cmd->cmdsize;
        }
        
        return binary;
    }
};

} // namespace macho

// Unified format detection
enum class BinaryFormat {
    Unknown,
    PE,
    ELF,
    MachO,
    Raw
};

BinaryFormat detect_format(const BinaryFile& file) {
    if (file.size() < 4) return BinaryFormat::Raw;
    
    const uint8_t* data = file.bytes();
    
    // PE: MZ header
    if (data[0] == 'M' && data[1] == 'Z') {
        return BinaryFormat::PE;
    }
    
    // ELF: 0x7F 'ELF'
    if (data[0] == 0x7F && data[1] == 'E' && data[2] == 'L' && data[3] == 'F') {
        return BinaryFormat::ELF;
    }
    
    // Mach-O: 0xfeedfacf (64-bit) or 0xfeedface (32-bit)
    uint32_t magic = *reinterpret_cast<const uint32_t*>(data);
    if (magic == 0xfeedfacf || magic == 0xfeedface) {
        return BinaryFormat::MachO;
    }
    
    return BinaryFormat::Raw;
}

// Universal parser
class UniversalParser {
public:
    Result<std::unique_ptr<ir::Binary>> parse(const BinaryFile& file) {
        auto format = detect_format(file);
        
        switch (format) {
            case BinaryFormat::PE:
                // PE parsing is handled elsewhere
                return ATLUS_MAKE_ERROR(ErrorCode::NotImplemented, "Use PE parser directly");
                
            case BinaryFormat::ELF: {
                elf::ELFParser parser;
                return parser.parse(file);
            }
            
            case BinaryFormat::MachO: {
                macho::MachOParser parser;
                return parser.parse(file);
            }
            
            case BinaryFormat::Raw:
                // Create raw binary with user-provided base
                return create_raw_binary(file, 0);
                
            default:
                return ATLUS_MAKE_ERROR(ErrorCode::InvalidFormat, "Unknown binary format");
        }
    }
    
    Result<std::unique_ptr<ir::Binary>> create_raw_binary(
        const BinaryFile& file, 
        uint64_t base_address
    ) {
        auto binary = std::make_unique<ir::Binary>(file.path, base_address, true);
        
        // Create single section for entire file
        ir::Section sec;
        sec.name = ".raw";
        sec.file_offset = {0, ir::Address::Space::FileOffset};
        sec.rva = {0, ir::Address::Space::RVA};
        sec.virtual_addr = {base_address, ir::Address::Space::Virtual};
        sec.virtual_size = static_cast<uint32_t>(file.size());
        sec.raw_size = static_cast<uint32_t>(file.size());
        sec.is_readable = true;
        sec.is_writable = true;
        sec.is_executable = true;
        
        binary->create_section(sec);
        
        return binary;
    }
};

// Export the public API
BinaryFormat detect_binary_format(const BinaryFile& file) {
    return detect_format(file);
}

Result<std::unique_ptr<ir::Binary>> parse_elf(const BinaryFile& file) {
    elf::ELFParser parser;
    return parser.parse(file);
}

Result<std::unique_ptr<ir::Binary>> parse_macho(const BinaryFile& file) {
    macho::MachOParser parser;
    return parser.parse(file);
}

Result<std::unique_ptr<ir::Binary>> parse_raw(const BinaryFile& file, uint64_t base) {
    UniversalParser parser;
    return parser.create_raw_binary(file, base);
}

} // namespace atlus::parsers
