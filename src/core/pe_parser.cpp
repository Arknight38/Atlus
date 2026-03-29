#include "core/pe_parser.h"

#ifdef _MSC_VER
#pragma warning(push, 0)
#endif
#include <LIEF/PE.hpp>
#ifdef _MSC_VER
#pragma warning(pop)
#endif

#include <cstdint>
#include <memory>
#include <utility>

namespace atlus {

const PESection* PEInfo::find_section(const std::string& name) const {
    for (const auto& sec : sections)
        if (sec.name == name) return &sec;
    return nullptr;
}

atlus::PEInfo atlus::PEParser::parse(const BinaryFile& file) {
    PEInfo info;
    if (file.empty())
        return info;

    std::unique_ptr<LIEF::PE::Binary> binary = LIEF::PE::Parser::parse(file.data);
    if (!binary)
        return info;

    const auto& hdr = binary->header();
    const auto& opt = binary->optional_header();

    info.machine   = static_cast<uint16_t>(hdr.machine());
    info.is_64bit  = (opt.magic() == LIEF::PE::PE_TYPE::PE32_PLUS);
    info.entry_rva = opt.addressof_entrypoint();
    info.image_base = opt.imagebase();
    info.subsystem = static_cast<uint16_t>(opt.subsystem());

    for (const LIEF::PE::Section& section : binary->sections()) {
        PESection sec;
        sec.name        = section.name();
        sec.vaddr       = static_cast<uint32_t>(section.virtual_address());
        sec.vsize       = section.virtual_size();
        sec.raw_offset  = section.pointerto_raw_data();
        sec.raw_size    = section.sizeof_raw_data();
        sec.flags       = section.characteristics();

        const auto content = section.content();
        sec.data.assign(content.begin(), content.end());

        if (sec.data.empty() && sec.raw_size > 0) {
            const size_t end = size_t(sec.raw_offset) + size_t(sec.raw_size);
            if (end <= file.size()) {
                const auto* base = file.bytes() + sec.raw_offset;
                sec.data.assign(base, base + sec.raw_size);
            }
        }

        info.sections.push_back(std::move(sec));
    }

    if (binary->has_imports()) {
        for (const LIEF::PE::Import& imp : binary->imports()) {
            ImportEntry ie;
            ie.dll = imp.name();
            for (const LIEF::PE::ImportEntry& e : imp.entries()) {
                if (e.is_ordinal())
                    ie.functions.push_back("ord#" + std::to_string(e.ordinal()));
                else if (!e.name().empty())
                    ie.functions.push_back(e.name());
            }
            info.imports.push_back(std::move(ie));
        }
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
