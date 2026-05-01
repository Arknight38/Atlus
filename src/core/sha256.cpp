#include "core/sha256.h"
#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace atlus {

static const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static inline uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
static inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z)  { return (x & y) ^ (~x & z); }
static inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
static inline uint32_t ep0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
static inline uint32_t ep1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
static inline uint32_t sig0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
static inline uint32_t sig1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

static void sha256_transform(uint32_t state[8], const uint8_t data[64]) {
    uint32_t m[64];
    for (int i = 0; i < 16; ++i) {
        m[i] = (uint32_t(data[i * 4]) << 24) | (uint32_t(data[i * 4 + 1]) << 16)
             | (uint32_t(data[i * 4 + 2]) << 8) | uint32_t(data[i * 4 + 3]);
    }
    for (int i = 16; i < 64; ++i) {
        m[i] = sig1(m[i - 2]) + m[i - 7] + sig0(m[i - 15]) + m[i - 16];
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (int i = 0; i < 64; ++i) {
        uint32_t t1 = h + ep1(e) + ch(e, f, g) + k[i] + m[i];
        uint32_t t2 = ep0(a) + maj(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static void sha256_init(uint32_t state[8]) {
    state[0] = 0x6a09e667; state[1] = 0xbb67ae85; state[2] = 0x3c6ef372; state[3] = 0xa54ff53a;
    state[4] = 0x510e527f; state[5] = 0x9b05688c; state[6] = 0x1f83d9ab; state[7] = 0x5be0cd19;
}

static void sha256_update(uint32_t state[8], uint64_t& bitlen, uint8_t buffer[64],
                          const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        buffer[bitlen / 8 % 64] = data[i];
        bitlen += 8;
        if ((bitlen / 8 % 64) == 0) {
            sha256_transform(state, buffer);
        }
    }
}

static void sha256_final(uint32_t state[8], uint64_t bitlen, uint8_t buffer[64], uint8_t hash[32]) {
    size_t padlen = (bitlen / 8 % 64 < 56) ? (56 - bitlen / 8 % 64) : (120 - bitlen / 8 % 64);
    uint8_t pad[128];
    pad[0] = 0x80;
    for (size_t i = 1; i < padlen; ++i) pad[i] = 0;
    sha256_update(state, bitlen, buffer, pad, padlen);

    uint8_t len_bits[8];
    uint64_t total_bits = bitlen;
    for (int i = 7; i >= 0; --i) {
        len_bits[i] = static_cast<uint8_t>(total_bits);
        total_bits >>= 8;
    }
    sha256_update(state, bitlen, buffer, len_bits, 8);

    for (int i = 0; i < 8; ++i) {
        hash[i * 4]     = uint8_t(state[i] >> 24);
        hash[i * 4 + 1] = uint8_t(state[i] >> 16);
        hash[i * 4 + 2] = uint8_t(state[i] >> 8);
        hash[i * 4 + 3] = uint8_t(state[i]);
    }
}

static std::array<uint8_t, 32> sha256_internal(const uint8_t* data, size_t len) {
    uint32_t state[8];
    uint8_t buffer[64];
    uint64_t bitlen = 0;
    std::memset(buffer, 0, sizeof(buffer));
    sha256_init(state);
    sha256_update(state, bitlen, buffer, data, len);
    std::array<uint8_t, 32> hash;
    sha256_final(state, bitlen, buffer, hash.data());
    return hash;
}

std::array<uint8_t, 32> sha256_bytes(const uint8_t* data, size_t len) {
    return sha256_internal(data, len);
}

std::array<uint8_t, 32> sha256_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return {};

    uint32_t state[8];
    uint8_t buffer[64];
    uint64_t bitlen = 0;
    std::memset(buffer, 0, sizeof(buffer));
    sha256_init(state);

    constexpr size_t chunk = 65536;
    std::vector<uint8_t> buf(chunk);
    while (file.good()) {
        file.read(reinterpret_cast<char*>(buf.data()), chunk);
        size_t n = static_cast<size_t>(file.gcount());
        if (n > 0) sha256_update(state, bitlen, buffer, buf.data(), n);
    }

    std::array<uint8_t, 32> hash;
    sha256_final(state, bitlen, buffer, hash.data());
    return hash;
}

std::string sha256_hex(const std::vector<uint8_t>& data) {
    return sha256_hex(data.data(), data.size());
}

std::string sha256_hex(const uint8_t* data, size_t len) {
    auto hash = sha256_internal(data, len);
    std::ostringstream oss;
    for (uint8_t b : hash) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return oss.str();
}

} // namespace atlus
