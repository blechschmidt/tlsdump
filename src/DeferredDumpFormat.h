#ifndef TLSDUMP_DEFERREDDUMPFORMAT_H
#define TLSDUMP_DEFERREDDUMPFORMAT_H

#include <cstdint>

static constexpr uint32_t DUMP_MAGIC = 0x44534C54; // "TLSD"
static constexpr uint16_t DUMP_VERSION = 1;
static constexpr size_t DUMP_PAGE_SIZE = 4096;

enum DumpRecordType : uint8_t {
    DUMP_TLS_METADATA     = 0x01,
    DUMP_TLS_RECORD_DATA  = 0x02,
    DUMP_MEMORY_SNAPSHOT  = 0x03,
    DUMP_MEMORY_DIFF      = 0x04,
};

enum DumpTlsRecordLabel : uint8_t {
    LABEL_DATA_RECORD           = 0,
    LABEL_TLS13_CLIENT_FINISHED = 1,
    LABEL_TLS13_CLIENT_APP_DATA = 2,
    LABEL_TLS13_SERVER_ENCRYPTED = 3,
    LABEL_TLS13_SERVER_APP_DATA = 4,
};

struct __attribute__((packed)) DumpFileHeader {
    uint32_t magic;
    uint16_t version;
    uint16_t flags;
};

struct __attribute__((packed)) DumpRecordHeader {
    uint8_t type;
    uint32_t length;
};

struct __attribute__((packed)) DumpTlsMetadata {
    uint8_t is_tls13;
    uint16_t cipher_suite;
    uint8_t client_random[32];
    uint8_t server_random[32];
};

struct __attribute__((packed)) DumpTlsRecord {
    uint8_t label_id;
    uint8_t content_type;
    uint16_t version;
    uint16_t data_length;
    // followed by data_length bytes
};

struct __attribute__((packed)) DumpMemoryHeader {
    uint32_t snapshot_index;
    uint32_t page_count;
};

struct __attribute__((packed)) DumpMemoryDiffHeader {
    uint32_t snapshot_index;
    uint32_t base_index;
    uint32_t changed_page_count;
};

struct __attribute__((packed)) DumpPageEntry {
    uint64_t address;
    // followed by DUMP_PAGE_SIZE bytes of data
};

#endif //TLSDUMP_DEFERREDDUMPFORMAT_H
