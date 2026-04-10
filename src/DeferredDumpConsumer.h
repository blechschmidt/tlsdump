#ifndef TLSDUMP_DEFERREDDUMPCONSUMER_H
#define TLSDUMP_DEFERREDDUMPCONSUMER_H

#include "TlsDecryptor.h"
#include "DeferredDumpFormat.h"
#include <fstream>
#include <unordered_map>

class DeferredDumpConsumer : public TlsDecryptor {
    std::ofstream dump_file;
    uint32_t snapshot_count = 0;
    std::unordered_map<uint64_t, uint64_t> prev_page_hashes;

    void write_file_header();
    void write_metadata();
    void write_tls_record(DumpTlsRecordLabel label, const tls_record &record);
    void dump_memory();
    static uint64_t hash_page(const uint8_t *data, size_t len);

public:
    explicit DeferredDumpConsumer(pid_t pid, const std::string &dump_path);

    void find_master_secret() override;
    void find_tls13_secrets() override;
};

#endif //TLSDUMP_DEFERREDDUMPCONSUMER_H
