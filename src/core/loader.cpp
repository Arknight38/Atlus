#include "core/loader.h"
#include <fstream>
#include <filesystem>

namespace atlus {

BinaryFile Loader::load(const std::string& path) {
    BinaryFile file;
    file.path = path;

    std::ifstream ifs(path, std::ios::binary | std::ios::ate);
    if (!ifs) return file;

    auto size = ifs.tellg();
    if (size <= 0) return file;

    file.data.resize(static_cast<size_t>(size));
    ifs.seekg(0);
    ifs.read(reinterpret_cast<char*>(file.data.data()), size);
    return file;
}

bool Loader::is_accessible(const std::string& path) {
    return std::filesystem::exists(path) &&
           std::filesystem::is_regular_file(path);
}

} // namespace atlus
