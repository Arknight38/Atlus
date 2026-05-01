#include "core/disassembler.h"
#include "core/disassembly_cache.h"
#include <Zydis/Zydis.h>

namespace atlus {

bool Instruction::is_branch() const {
    return mnemonic == "jmp"  || mnemonic == "je"  || mnemonic == "jne" ||
           mnemonic == "jl"   || mnemonic == "jle" || mnemonic == "jg"  ||
           mnemonic == "jge"  || mnemonic == "jb"  || mnemonic == "jbe" ||
           mnemonic == "ja"   || mnemonic == "jae" || mnemonic == "jz"  ||
           mnemonic == "jnz"  || mnemonic == "js"  || mnemonic == "jns";
}
bool Instruction::is_call() const { return mnemonic == "call"; }
bool Instruction::is_ret()  const { return mnemonic == "ret" || mnemonic == "retn"; }

Disassembler::Disassembler(Mode mode) : mode_(mode) {
    // Initialize Zydis decoder
    ZydisDecoderInit(&decoder_,
        mode == Mode::X86_64 ? ZYDIS_MACHINE_MODE_LONG_64
                             : ZYDIS_MACHINE_MODE_LEGACY_32,
        mode == Mode::X86_64 ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32);
    
    // Initialize formatter for Intel syntax
    ZydisFormatterInit(&formatter_, ZYDIS_FORMATTER_STYLE_INTEL);
    ZydisFormatterSetProperty(&formatter_, ZYDIS_FORMATTER_PROP_FORCE_SEGMENT, ZYAN_TRUE);
    ZydisFormatterSetProperty(&formatter_, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE);
}

std::vector<Instruction> Disassembler::disassemble(
    const uint8_t* data,
    size_t         size,
    uint64_t       base_address,
    size_t         max_instructions
) const {
    std::vector<Instruction> result;
    
    size_t offset = 0;
    size_t count = 0;
    
    while (offset < size && count < max_instructions) {
        ZydisDecodedInstruction instr;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
        
        // Decode instruction
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder_, 
                                               data + offset, 
                                               size - offset, 
                                               &instr, 
                                               operands))) {
            // Invalid instruction, skip one byte and continue
            offset++;
            continue;
        }
        
        Instruction insn;
        insn.address = base_address + offset;
        insn.length = instr.length;
        insn.mnemonic = ZydisMnemonicGetString(instr.mnemonic);
        
        // Format operands
        char buffer[256];
        ZydisFormatterFormatInstruction(&formatter_, &instr, operands, 
                                        instr.operand_count_visible, buffer, 
                                        sizeof(buffer), insn.address, nullptr);
        insn.operands = buffer;
        
        // Copy raw bytes
        insn.bytes.assign(data + offset, data + offset + instr.length);
        
        result.push_back(insn);
        offset += instr.length;
        count++;
    }
    
    return result;
}

bool Disassembler::decode_one(
    const uint8_t* data,
    size_t         size,
    uint64_t       address,
    Instruction&   out
) const {
    ZydisDecodedInstruction instr;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder_, 
                                           data, 
                                           size, 
                                           &instr, 
                                           operands))) {
        return false;
    }
    
    out.address = address;
    out.length = instr.length;
    out.mnemonic = ZydisMnemonicGetString(instr.mnemonic);
    
    // Format operands
    char buffer[256];
    ZydisFormatterFormatInstruction(&formatter_, &instr, operands, 
                                    instr.operand_count_visible, buffer, 
                                    sizeof(buffer), address, nullptr);
    out.operands = buffer;
    
    // Copy raw bytes
    out.bytes.assign(data, data + instr.length);
    
    return true;
}

// ── Cache-aware disassembly ───────────────────────────────────────────────────

std::vector<Instruction> Disassembler::disassemble_cached(
    const uint8_t* data,
    size_t         size,
    uint64_t       base_address,
    const std::string& file_hash
) const {
    // Initialize cache on first use
    auto& cache = get_disassembly_cache();
    if (!cache.is_open()) {
        cache.open();
    }

    // Try to get from cache first
    DisassemblyBlock cached_block;
    if (cache.get_block(file_hash, base_address, cached_block)) {
        // Verify that raw bytes match (to detect stale cache)
        bool bytes_match = cached_block.size == size;
        if (bytes_match && size > 0) {
            bytes_match = (std::memcmp(cached_block.raw_bytes.data(), data, size) == 0);
        }

        if (bytes_match) {
            // Cache hit - return cached instructions
            return cached_block.instructions;
        }
    }

    // Cache miss - disassemble normally
    return disassemble(data, size, base_address, SIZE_MAX);
}

bool Disassembler::cache_result(
    const std::string& file_hash,
    uint64_t base_address,
    const uint8_t* data,
    size_t size,
    const std::vector<Instruction>& instructions
) const {
    auto& cache = get_disassembly_cache();
    if (!cache.is_open()) {
        if (!cache.open()) {
            return false;
        }
    }

    DisassemblyBlock block;
    block.address = base_address;
    block.size = size;
    block.raw_bytes.assign(data, data + size);
    block.instructions = instructions;

    return cache.put_block(file_hash, base_address, block);
}

} // namespace atlus
