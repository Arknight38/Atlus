#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <Zydis/Zydis.h>

namespace atlus {

struct Instruction {
    uint64_t    address;    // Virtual address of this instruction
    uint8_t     length;     // Byte length (1-15)
    std::string mnemonic;   // e.g. "mov", "call", "ret"
    std::string operands;   // Formatted operand string
    std::string text;       // Full formatted text: "mov rax, rbx"

    std::vector<uint8_t> bytes; // Raw bytes

    // True if this instruction unconditionally transfers control
    bool is_branch()  const;
    bool is_call()    const;
    bool is_ret()     const;
};

class Disassembler {
public:
    enum class Mode { X86_32, X86_64 };

    explicit Disassembler(Mode mode = Mode::X86_64);

    // Disassemble a flat byte buffer starting at base_address.
    // Stops at max_instructions or when bytes are exhausted.
    std::vector<Instruction> disassemble(
        const uint8_t* data,
        size_t         size,
        uint64_t       base_address,
        size_t         max_instructions = SIZE_MAX
    ) const;

    // Single-instruction decode. Returns false if decoding fails.
    bool decode_one(
        const uint8_t* data,
        size_t         size,
        uint64_t       address,
        Instruction&   out
    ) const;

private:
    Mode mode_;
    ZydisDecoder    decoder_;
    ZydisFormatter  formatter_;
};

} // namespace atlus
