#pragma once
#include <cstdint>
#include <array>

namespace atlus {

// Simple MD5 hash implementation
struct MD5Context {
    uint32_t state[4];
    uint32_t count[2];
    uint8_t buffer[64];
};

void md5_init(MD5Context* ctx);
void md5_update(MD5Context* ctx, const uint8_t* data, uint32_t len);
void md5_final(std::array<uint8_t, 16>& digest, MD5Context* ctx);

} // namespace atlus
