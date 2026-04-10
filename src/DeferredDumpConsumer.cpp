#include "DeferredDumpConsumer.h"
#include "MemoryExporter.h"

DeferredDumpConsumer::DeferredDumpConsumer(pid_t pid, const std::string &dump_path)
    : TlsDecryptor(pid) {
    dump_file.open(dump_path, std::ios::binary);
    write_file_header();
}

void DeferredDumpConsumer::write_file_header() {
    DumpFileHeader hdr = {DUMP_MAGIC, DUMP_VERSION, 0};
    dump_file.write(reinterpret_cast<const char *>(&hdr), sizeof(hdr));
}

void DeferredDumpConsumer::write_metadata() {
    DumpTlsMetadata meta = {};
    meta.is_tls13 = is_tls13 ? 1 : 0;
    meta.cipher_suite = cipher_suite;
    std::memcpy(meta.client_random, client_random, 32);
    std::memcpy(meta.server_random, server_random, 32);

    DumpRecordHeader rh = {DUMP_TLS_METADATA, sizeof(meta)};
    dump_file.write(reinterpret_cast<const char *>(&rh), sizeof(rh));
    dump_file.write(reinterpret_cast<const char *>(&meta), sizeof(meta));
}

void DeferredDumpConsumer::write_tls_record(DumpTlsRecordLabel label, const tls_record &record) {
    DumpTlsRecord tr = {};
    tr.label_id = label;
    tr.content_type = record.content_type;
    tr.version = record.version;
    tr.data_length = record.length;

    uint32_t payload_len = sizeof(tr) + record.length;
    DumpRecordHeader rh = {DUMP_TLS_RECORD_DATA, payload_len};
    dump_file.write(reinterpret_cast<const char *>(&rh), sizeof(rh));
    dump_file.write(reinterpret_cast<const char *>(&tr), sizeof(tr));
    dump_file.write(reinterpret_cast<const char *>(record.data), record.length);
}

uint64_t DeferredDumpConsumer::hash_page(const uint8_t *data, size_t len) {
    // FNV-1a 64-bit
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < len; i++) {
        h ^= data[i];
        h *= 0x100000001b3ULL;
    }
    return h;
}

void DeferredDumpConsumer::dump_memory() {
    MemoryExporter exporter(pid);
    auto maps = exporter.get_memory_maps();

    // Collect all pages
    struct PageData {
        uint64_t address;
        const uint8_t *data;
    };

    std::vector<std::shared_ptr<uint8_t[]>> mem_holders;
    std::vector<PageData> all_pages;
    std::vector<PageData> changed_pages;

    for (auto &map : maps) {
        auto mem = exporter.get_memory_section(map);
        if (!mem) continue;

        uintptr_t start = map.start & ~(DUMP_PAGE_SIZE - 1);
        uintptr_t end = (map.end + DUMP_PAGE_SIZE - 1) & ~(DUMP_PAGE_SIZE - 1);

        mem_holders.push_back(mem);

        for (uintptr_t addr = start; addr < end && addr < map.end; addr += DUMP_PAGE_SIZE) {
            size_t offset = addr - map.start;
            size_t page_len = std::min((size_t)DUMP_PAGE_SIZE, map.size() - offset);
            const uint8_t *page_data = mem.get() + offset;

            uint64_t h = hash_page(page_data, page_len);
            auto prev = prev_page_hashes.find(addr);

            all_pages.push_back({addr, page_data});

            if (prev == prev_page_hashes.end() || prev->second != h) {
                changed_pages.push_back({addr, page_data});
            }
            prev_page_hashes[addr] = h;
        }
    }

    if (snapshot_count == 0) {
        // Full snapshot
        DumpMemoryHeader mh = {snapshot_count, static_cast<uint32_t>(all_pages.size())};
        uint32_t payload = sizeof(mh) + all_pages.size() * (sizeof(DumpPageEntry) + DUMP_PAGE_SIZE);
        DumpRecordHeader rh = {DUMP_MEMORY_SNAPSHOT, payload};
        dump_file.write(reinterpret_cast<const char *>(&rh), sizeof(rh));
        dump_file.write(reinterpret_cast<const char *>(&mh), sizeof(mh));

        uint8_t zero_page[DUMP_PAGE_SIZE] = {};
        for (auto &p : all_pages) {
            DumpPageEntry pe = {p.address};
            dump_file.write(reinterpret_cast<const char *>(&pe), sizeof(pe));
            // Write full page, zero-padding if needed
            size_t actual = DUMP_PAGE_SIZE; // pages are aligned
            dump_file.write(reinterpret_cast<const char *>(p.data), actual);
        }
    } else {
        // Differential snapshot
        DumpMemoryDiffHeader dh = {snapshot_count, snapshot_count - 1,
                                   static_cast<uint32_t>(changed_pages.size())};
        uint32_t payload = sizeof(dh) + changed_pages.size() * (sizeof(DumpPageEntry) + DUMP_PAGE_SIZE);
        DumpRecordHeader rh = {DUMP_MEMORY_DIFF, payload};
        dump_file.write(reinterpret_cast<const char *>(&rh), sizeof(rh));
        dump_file.write(reinterpret_cast<const char *>(&dh), sizeof(dh));

        for (auto &p : changed_pages) {
            DumpPageEntry pe = {p.address};
            dump_file.write(reinterpret_cast<const char *>(&pe), sizeof(pe));
            dump_file.write(reinterpret_cast<const char *>(p.data), DUMP_PAGE_SIZE);
        }
    }

    dump_file.flush();
    snapshot_count++;
    std::cerr << "Memory snapshot " << (snapshot_count - 1) << " written ("
              << (snapshot_count == 1 ? all_pages.size() : changed_pages.size())
              << " pages)" << std::endl;
}

void DeferredDumpConsumer::find_master_secret() {
    std::cerr << "Deferred mode: dumping TLS 1.2 metadata and memory..." << std::endl;
    write_metadata();
    write_tls_record(LABEL_DATA_RECORD, data_record);
    dump_memory();
    this->finished = true;
}

void DeferredDumpConsumer::find_tls13_secrets() {
    std::cerr << "Deferred mode: dumping TLS 1.3 metadata and memory..." << std::endl;
    write_metadata();
    write_tls_record(LABEL_TLS13_CLIENT_FINISHED, tls13_client_finished);
    write_tls_record(LABEL_TLS13_CLIENT_APP_DATA, tls13_client_app_data);
    write_tls_record(LABEL_TLS13_SERVER_ENCRYPTED, tls13_server_encrypted);
    write_tls_record(LABEL_TLS13_SERVER_APP_DATA, tls13_server_app_data);
    dump_memory();
    this->finished = true;
}
