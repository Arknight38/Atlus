#include "core/address_space.h"
#include <algorithm>

namespace atlus::ir {

const char* address_space_name(AddressSpace space) {
    switch (space) {
        case AddressSpace::None:     return "None";
        case AddressSpace::File:     return "File";
        case AddressSpace::Section:  return "Section";
        case AddressSpace::RVA:      return "RVA";
        case AddressSpace::Image:    return "Image";
        case AddressSpace::Runtime:  return "Runtime";
        default:                     return "Unknown";
    }
}

// AddressRange implementation
bool AddressRange::contains(QualifiedAddress addr) const {
    if (addr.space != start.space) return false;
    return addr.offset >= start.offset && addr.offset < end.offset;
}

bool AddressRange::intersects(const AddressRange& other) const {
    if (start.space != other.start.space) return false;
    return start.offset < other.end.offset && end.offset > other.start.offset;
}

std::optional<AddressRange> AddressRange::intersection(const AddressRange& other) const {
    if (!intersects(other)) return std::nullopt;
    
    AddressRange result;
    result.start.space = start.space;
    result.start.offset = std::max(start.offset, other.start.offset);
    result.end.space = end.space;
    result.end.offset = std::min(end.offset, other.end.offset);
    return result;
}

uint64_t AddressRange::size() const {
    return end.offset > start.offset ? end.offset - start.offset : 0;
}

AddressRange AddressRange::from_section(const Section& section) {
    AddressRange range;
    range.start = QualifiedAddress(section.virtual_addr);
    range.end = QualifiedAddress(section.virtual_addr.offset + section.virtual_size, AddressSpace::Image, SectionId());
    return range;
}

AddressRange AddressRange::from_function(const Function& fn, const Binary& binary) {
    AddressRange range;
    range.start = QualifiedAddress(fn.start_address);
    range.end = QualifiedAddress(fn.end_address);
    return range;
}

// AddressTranslation implementation
AddressTranslation::AddressTranslation() = default;

void AddressTranslation::initialize(const Binary& binary) {
    preferred_base_ = binary.image_base();
    runtime_base_ = preferred_base_;  // Initially the same
    file_size_ = 0;
    
    sections_.clear();
    for (const auto& section : binary.sections()) {
        SectionMap map;
        map.id = section->id;
        map.file_offset = section->file_offset.offset;
        map.file_size = section->raw_size;
        map.virtual_addr = section->virtual_addr.offset;
        map.virtual_size = section->virtual_size;
        map.rva = section->rva.offset;
        sections_.push_back(map);
        
        // Track total file size
        file_size_ = std::max(file_size_, map.file_offset + map.file_size);
    }
}

std::optional<QualifiedAddress> AddressTranslation::translate(
    QualifiedAddress from,
    AddressSpace to_space
) const {
    if (!from.valid()) return std::nullopt;
    
    // Same space - just copy
    if (from.space == to_space) return from;
    
    // Convert source to RVA as intermediate
    std::optional<uint64_t> rva;
    
    switch (from.space) {
        case AddressSpace::File:
            rva = file_to_rva(from.offset);
            break;
        case AddressSpace::RVA:
            rva = from.offset;
            break;
        case AddressSpace::Image:
            rva = from.offset - preferred_base_;
            break;
        case AddressSpace::Runtime:
            rva = from.offset - runtime_base_;
            break;
        case AddressSpace::Section:
            // Find section and convert
            for (const auto& sec : sections_) {
                if (sec.id == static_cast<uint32_t>(from.section) && 
                    from.offset < sec.virtual_size) {
                    rva = sec.rva + from.offset;
                    break;
                }
            }
            break;
        default:
            return std::nullopt;
    }
    
    if (!rva.has_value()) return std::nullopt;
    
    // Convert RVA to target space
    switch (to_space) {
        case AddressSpace::RVA:
            return QualifiedAddress(rva.value(), AddressSpace::RVA, SectionId());
        case AddressSpace::Image:
            return QualifiedAddress(preferred_base_ + rva.value(), AddressSpace::Image, SectionId());
        case AddressSpace::Runtime:
            return QualifiedAddress(runtime_base_ + rva.value(), AddressSpace::Runtime, SectionId());
        case AddressSpace::File:
            return file_to_image(rva.value()).has_value() 
                ? std::optional(QualifiedAddress(rva_to_file(rva.value()).value(), AddressSpace::File, SectionId()))
                : std::nullopt;
        case AddressSpace::Section: {
            auto sec_id = find_section_containing(QualifiedAddress(rva.value(), AddressSpace::RVA, SectionId()));
            if (!sec_id.has_value()) return std::nullopt;
            for (const auto& sec : sections_) {
                if (sec.id == static_cast<uint32_t>(sec_id.value())) {
                    uint64_t offset = rva.value() - sec.rva.offset;
                    return QualifiedAddress(offset, AddressSpace::Section, sec_id.value());
                }
            }
            return std::nullopt;
        }
        default:
            return std::nullopt;
    }
}

std::optional<uint64_t> AddressTranslation::file_to_image(uint64_t file_offset) const {
    auto rva = file_to_rva(file_offset);
    if (!rva) return std::nullopt;
    return preferred_base_ + rva.value();
}

std::optional<uint64_t> AddressTranslation::image_to_file(uint64_t va) const {
    if (va < preferred_base_) return std::nullopt;
    return rva_to_file(va - preferred_base_);
}

std::optional<uint64_t> AddressTranslation::rva_to_file(uint64_t rva_val) const {
    for (const auto& sec : sections_) {
        if (rva_val >= sec.rva && rva_val < sec.rva + sec.file_size) {
            return sec.file_offset + (rva_val - sec.rva);
        }
    }
    return std::nullopt;
}

std::optional<uint64_t> AddressTranslation::file_to_rva(uint64_t file_offset) const {
    for (const auto& sec : sections_) {
        if (file_offset >= sec.file_offset && file_offset < sec.file_offset + sec.file_size) {
            return sec.rva + (file_offset - sec.file_offset);
        }
    }
    return std::nullopt;
}

std::optional<SectionId> AddressTranslation::find_section_containing(QualifiedAddress addr) const {
    uint64_t rva_val;
    
    switch (addr.space) {
        case AddressSpace::RVA:
            rva_val = addr.offset;
            break;
        case AddressSpace::Image:
            rva_val = addr.offset - preferred_base_;
            break;
        case AddressSpace::Runtime:
            rva_val = addr.offset - runtime_base_;
            break;
        case AddressSpace::File: {
            auto rva = file_to_rva(addr.offset);
            if (!rva) return std::nullopt;
            rva_val = rva.value();
            break;
        }
        case AddressSpace::Section:
            return addr.section;  // Already a section
        default:
            return std::nullopt;
    }
    
    for (const auto& sec : sections_) {
        if (rva_val >= sec.rva && rva_val < sec.rva + sec.virtual_size) {
            return static_cast<SectionId>(sec.id);
        }
    }
    return std::nullopt;
}

void AddressTranslation::set_runtime_base(uint64_t actual_base) {
    runtime_base_ = actual_base;
}

std::optional<uint64_t> AddressTranslation::image_to_runtime(uint64_t va) const {
    return va - preferred_base_ + runtime_base_;
}

std::optional<uint64_t> AddressTranslation::runtime_to_image(uint64_t runtime_va) const {
    if (runtime_va < runtime_base_) return std::nullopt;
    return runtime_va - runtime_base_ + preferred_base_;
}

bool AddressTranslation::is_valid_file_offset(uint64_t offset) const {
    return offset < file_size_;
}

bool AddressTranslation::is_valid_rva(uint64_t rva) const {
    for (const auto& sec : sections_) {
        if (rva >= sec.rva && rva < sec.rva + sec.virtual_size) {
            return true;
        }
    }
    return false;
}

bool AddressTranslation::is_valid_image_va(uint64_t va) const {
    return is_valid_rva(va - preferred_base_);
}

// PEMemoryModel implementation
PEMemoryModel::PEMemoryModel(const Binary& binary, const BinaryFile& file)
    : binary_(binary), file_(file) {
    translation_.initialize(binary);
}

std::vector<uint8_t> PEMemoryModel::read(QualifiedAddress addr, size_t len) const {
    std::vector<uint8_t> result;
    result.resize(len);
    size_t read = read_into(addr, result.data(), len);
    result.resize(read);
    return result;
}

size_t PEMemoryModel::read_into(QualifiedAddress addr, uint8_t* buffer, size_t len) const {
    // Translate to file offset
    auto file_addr = translation_.translate(addr, AddressSpace::File);
    if (!file_addr.has_value()) return 0;
    
    uint64_t offset = file_addr->offset;
    if (offset >= file_.size()) return 0;
    
    size_t available = file_.size() - offset;
    size_t to_read = std::min(len, available);
    
    std::memcpy(buffer, file_.bytes() + offset, to_read);
    return to_read;
}

bool PEMemoryModel::is_readable(QualifiedAddress addr) const {
    auto section = translation_.find_section_containing(addr);
    if (!section.has_value()) return false;
    
    // In a real implementation, check section characteristics
    return true;
}

bool PEMemoryModel::is_writable(QualifiedAddress addr) const {
    auto section = translation_.find_section_containing(addr);
    if (!section.has_value()) return false;
    
    const Section* sec = binary_.get_section(section.value());
    return sec && sec->is_writable;
}

bool PEMemoryModel::is_executable(QualifiedAddress addr) const {
    auto section = translation_.find_section_containing(addr);
    if (!section.has_value()) return false;
    
    const Section* sec = binary_.get_section(section.value());
    return sec && sec->is_executable;
}

bool PEMemoryModel::supports_space(AddressSpace space) const {
    return space != AddressSpace::None;
}

// FirmwareMemoryModel implementation
FirmwareMemoryModel::FirmwareMemoryModel(const BinaryFile& file, uint64_t base_address)
    : file_(file) {
    // Simple flat model - file offset 0 maps to base_address
    // No sections, just raw bytes
}

std::vector<uint8_t> FirmwareMemoryModel::read(QualifiedAddress addr, size_t len) const {
    std::vector<uint8_t> result;
    result.resize(len);
    size_t read = read_into(addr, result.data(), len);
    result.resize(read);
    return result;
}

size_t FirmwareMemoryModel::read_into(QualifiedAddress addr, uint8_t* buffer, size_t len) const {
    // For firmware, assume address is direct file offset
    // (unless it's Image space, then subtract base)
    uint64_t offset = addr.offset;
    if (addr.space == AddressSpace::Image || addr.space == AddressSpace::RVA) {
        // These don't apply to firmware - need to know base
        return 0;
    }
    
    if (offset >= file_.size()) return 0;
    
    size_t available = file_.size() - offset;
    size_t to_read = std::min(len, available);
    
    std::memcpy(buffer, file_.bytes() + offset, to_read);
    return to_read;
}

bool FirmwareMemoryModel::is_readable(QualifiedAddress addr) const {
    return true;  // Firmware is fully accessible
}

bool FirmwareMemoryModel::is_writable(QualifiedAddress addr) const {
    return false;  // Flash/firmware is typically read-only
}

bool FirmwareMemoryModel::is_executable(QualifiedAddress addr) const {
    return true;  // Assume code can execute anywhere in firmware
}

bool FirmwareMemoryModel::supports_space(AddressSpace space) const {
    // Firmware only supports File and Section (treated as offset)
    return space == AddressSpace::File || space == AddressSpace::Section;
}

} // namespace atlus::ir
