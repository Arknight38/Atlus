#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace atlus {

struct BinaryFile {
    std::string          path;
    std::vector<uint8_t> data;

    bool   empty()                        const { return data.empty(); }
    size_t size()                         const { return data.size(); }
    const uint8_t* bytes()               const { return data.data(); }
    const uint8_t& operator[](size_t i)  const { return data[i]; }
};

class Loader {
public:
    // Load a raw binary from disk.
    // Returns an empty BinaryFile on failure; check file.empty().
    static BinaryFile load(const std::string& path);

    // Validate that a file exists and is readable before loading.
    static bool is_accessible(const std::string& path);
};

} // namespace atlus
