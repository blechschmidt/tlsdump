#ifndef TLSDUMP_MEMORYEXPORTER_H
#define TLSDUMP_MEMORYEXPORTER_H

#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <list>
#include <sstream>

#include <sys/uio.h>

struct ProcMapEntry {
    uintptr_t start;
    uintptr_t end;

    [[nodiscard]] size_t size() const {
        return end - start;
    }
};

class MemoryExporter {
    pid_t pid;
public:
    explicit MemoryExporter(pid_t pid) {
        this->pid = pid;
    }

    [[nodiscard]] std::list<ProcMapEntry> get_memory_maps() const;

    std::shared_ptr<uint8_t[]> get_memory_section(ProcMapEntry &entry) const;

    void dump(const std::string &filename) const;
};


#endif //TLSDUMP_MEMORYEXPORTER_H
