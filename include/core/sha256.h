#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace atlus {

std::array<uint8_t, 32> sha256_bytes(const uint8_t* data, size_t len);
std::array<uint8_t, 32> sha256_file(const std::string& path);
std::string sha256_hex(const std::vector<uint8_t>& data);
std::string sha256_hex(const uint8_t* data, size_t len);

} // namespace atlus
