#include "core/pe_parser.h"
#include <cstring>

namespace atlus {

const PESection* PEInfo::find_section(const std::string& name) const {
    for (const auto& sec : sections)
        if (sec.name == name) return &sec;
    return nullptr;
}

// Minimal PE structures for manual parsing
#pragma pack(push, 1)
struct DOSHeader {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;
};

struct FileHeader {
    uint16_t machine;
    uint16_t num_sections;
    uint32_t timestamp;
    uint32_t symbol_table;
    uint32_t num_symbols;
    uint16_t optional_header_size;
    uint16_t characteristics;
};

struct DataDirectory {
    uint32_t rva;
    uint32_t size;
};

struct OptionalHeader32 {
    uint16_t magic;
    uint8_t major_linker;
    uint8_t minor_linker;
    uint32_t code_size;
    uint32_t data_size;
    uint32_t bss_size;
    uint32_t entry_point;
    uint32_t code_base;
    uint32_t data_base;
    uint32_t image_base;
    uint32_t section_align;
    uint32_t file_align;
    uint16_t major_os;
    uint16_t minor_os;
    uint16_t major_image;
    uint16_t minor_image;
    uint16_t major_subsystem;
    uint16_t minor_subsystem;
    uint32_t win32_version;
    uint32_t image_size;
    uint32_t headers_size;
    uint32_t checksum;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    uint32_t stack_reserve;
    uint32_t stack_commit;
    uint32_t heap_reserve;
    uint32_t heap_commit;
    uint32_t loader_flags;
    uint32_t num_data_dirs;
    DataDirectory data_dirs[16];
};

struct OptionalHeader64 {
    uint16_t magic;
    uint8_t major_linker;
    uint8_t minor_linker;
    uint32_t code_size;
    uint32_t data_size;
    uint32_t bss_size;
    uint32_t entry_point;
    uint32_t code_base;
    uint64_t image_base;
    uint32_t section_align;
    uint32_t file_align;
    uint16_t major_os;
    uint16_t minor_os;
    uint16_t major_image;
    uint16_t minor_image;
    uint16_t major_subsystem;
    uint16_t minor_subsystem;
    uint32_t win32_version;
    uint32_t image_size;
    uint32_t headers_size;
    uint32_t checksum;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    uint64_t stack_reserve;
    uint64_t stack_commit;
    uint64_t heap_reserve;
    uint64_t heap_commit;
    uint32_t loader_flags;
    uint32_t num_data_dirs;
    DataDirectory data_dirs[16];
};

struct SectionHeader {
    char name[8];
    uint32_t virtual_size;
    uint32_t virtual_address;
    uint32_t raw_size;
    uint32_t raw_address;
    uint32_t reloc_address;
    uint32_t line_numbers;
    uint16_t num_relocs;
    uint16_t num_lines;
    uint32_t characteristics;
};
#pragma pack(pop)

static constexpr uint16_t PE_MAGIC = 0x5A4D; // "MZ"
static constexpr uint32_t PE_SIGNATURE = 0x00004550; // "PE\0\0"
static constexpr uint16_t PE32_MAGIC = 0x10b;
static constexpr uint16_t PE32_PLUS_MAGIC = 0x20b;

atlus::PEInfo atlus::PEParser::parse(const BinaryFile& file) {
    PEInfo info;
    if (file.size() < sizeof(DOSHeader))
        return info;

    const auto* dos = reinterpret_cast<const DOSHeader*>(file.bytes());
    if (dos->e_magic != PE_MAGIC)
        return info;

    if (dos->e_lfanew + 4 > file.size())
        return info;

    const auto* pe_sig = reinterpret_cast<const uint32_t*>(file.bytes() + dos->e_lfanew);
    if (*pe_sig != PE_SIGNATURE)
        return info;

    size_t offset = dos->e_lfanew + 4;
    const auto* file_hdr = reinterpret_cast<const FileHeader*>(file.bytes() + offset);
    offset += sizeof(FileHeader);

    info.machine = file_hdr->machine;

    if (file_hdr->optional_header_size > 0) {
        const auto* opt_magic = reinterpret_cast<const uint16_t*>(file.bytes() + offset);
        if (*opt_magic == PE32_MAGIC) {
            info.is_64bit = false;
            const auto* opt = reinterpret_cast<const OptionalHeader32*>(file.bytes() + offset);
            info.entry_rva = opt->entry_point;
            info.image_base = opt->image_base;
            info.subsystem = opt->subsystem;
            offset += sizeof(OptionalHeader32);
        } else if (*opt_magic == PE32_PLUS_MAGIC) {
            info.is_64bit = true;
            const auto* opt = reinterpret_cast<const OptionalHeader64*>(file.bytes() + offset);
            info.entry_rva = opt->entry_point;
            info.image_base = opt->image_base;
            info.subsystem = opt->subsystem;
            offset += sizeof(OptionalHeader64);
        } else {
            offset += file_hdr->optional_header_size;
        }
    }

    for (uint16_t i = 0; i < file_hdr->num_sections; ++i) {
        const auto* sec = reinterpret_cast<const SectionHeader*>(file.bytes() + offset);
        offset += sizeof(SectionHeader);

        PESection pesec;
        pesec.name = std::string(sec->name, 8);
        // Trim nulls from name
        if (auto pos = pesec.name.find('\0'); pos != std::string::npos)
            pesec.name.resize(pos);
        pesec.vaddr = sec->virtual_address;
        pesec.vsize = sec->virtual_size;
        pesec.raw_offset = sec->raw_address;
        pesec.raw_size = sec->raw_size;
        pesec.flags = sec->characteristics;

        if (sec->raw_address + sec->raw_size <= file.size()) {
            pesec.data.assign(file.bytes() + sec->raw_address,
                            file.bytes() + sec->raw_address + sec->raw_size);
        }

        info.sections.push_back(std::move(pesec));
    }

    info.valid = true;
    return info;
}

std::optional<uint32_t> atlus::PEParser::rva_to_offset(const PEInfo& pe, uint32_t rva) {
    for (const auto& sec : pe.sections) {
        if (rva >= sec.vaddr && rva < sec.vaddr + sec.vsize) {
            return sec.raw_offset + (rva - sec.vaddr);
        }
    }
    return std::nullopt;
}

} // namespace atlus
