#include <memory>
#include "MemoryExporter.h"

std::list<ProcMapEntry> MemoryExporter::get_memory_maps() const {
    std::list<ProcMapEntry> result;

    std::stringstream filename;
    filename << "/proc/" << pid << "/maps";

    std::ifstream t(filename.str());
    std::string map((std::istreambuf_iterator<char>(t)), std::istreambuf_iterator<char>());

    std::istringstream iss(map);
    for (std::string line; std::getline(iss, line);) {
        ProcMapEntry entry = {};
        auto minus = line.find('-');
        auto start_str = line.substr(0, minus);
        auto end_str = line.substr(minus + 1, line.find(' ') - minus - 1);

        std::stringstream ss;

        ss << std::hex << start_str;
        ss >> entry.start;
        ss.clear();
        ss << std::hex << end_str;
        ss >> entry.end;

        result.push_back(entry);
    }

    return result;
}

std::shared_ptr<uint8_t[]> MemoryExporter::get_memory_section(ProcMapEntry &entry) const {
    size_t len = entry.end - entry.start;
    auto result = std::shared_ptr<uint8_t[]>(new uint8_t[len]);
    struct iovec local = {};
    local.iov_base = result.get();
    local.iov_len = len;
    struct iovec remote = {};
    remote.iov_base = reinterpret_cast<void *>(entry.start);
    remote.iov_len = len;
    ssize_t read_len = process_vm_readv(this->pid, &local, 1, &remote, 1, 0);
    if (read_len != len) {
        // no partial reads if there is only a single iovec according to the man page
        std::cerr << "Failed to extract memory from process " << pid
                  << std::hex << " (" << entry.start << "-" << entry.end << "): " << std::dec << std::strerror(errno)
                  << std::endl;
        return nullptr;
    }
    return result;
}

void MemoryExporter::dump(const std::string &filename) const {
    auto map = get_memory_maps();

    std::ofstream file;
    file.open(filename, std::ios_base::binary);
    for (auto &entry: map) {
        auto memory = get_memory_section(entry);
        if (memory == nullptr) {
            continue;
        }
        file.write(reinterpret_cast<char *>(&entry.start), sizeof(entry.start));
        file.write(reinterpret_cast<char *>(&entry.end), sizeof(entry.end));
        file.write(reinterpret_cast<char *>(memory.get()), static_cast<std::streamsize>(entry.end - entry.start));
        file.flush();
    }
    file.close();
}
