#include "DeferredExtractor.h"
#include "DeferredDumpFormat.h"
#include "TlsDecryptor.h"

extern "C" {
    #include "wireshark.h"
};

#include <filesystem>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <map>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <cstring>

struct DumpData {
    bool is_tls13 = false;
    uint16_t cipher_suite = 0;
    uint8_t client_random[32] = {};
    uint8_t server_random[32] = {};

    struct RecordData {
        uint8_t content_type;
        uint16_t version;
        std::vector<uint8_t> data;
    };

    RecordData data_record = {};
    RecordData tls13_records[4] = {}; // indexed by label_id - 1
    bool has_data_record = false;
    bool has_tls13_records[4] = {};

    // Reconstructed memory: map of page address -> page data
    std::map<uint64_t, std::vector<uint8_t>> pages;
};

static bool read_dump_file(const std::string &path, DumpData &dump) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        std::cerr << "Cannot open " << path << std::endl;
        return false;
    }

    DumpFileHeader fh;
    f.read(reinterpret_cast<char *>(&fh), sizeof(fh));
    if (fh.magic != DUMP_MAGIC || fh.version != DUMP_VERSION) {
        std::cerr << "Invalid dump file: " << path << std::endl;
        return false;
    }

    while (f) {
        DumpRecordHeader rh;
        f.read(reinterpret_cast<char *>(&rh), sizeof(rh));
        if (!f) break;

        switch (rh.type) {
            case DUMP_TLS_METADATA: {
                DumpTlsMetadata meta;
                f.read(reinterpret_cast<char *>(&meta), sizeof(meta));
                dump.is_tls13 = meta.is_tls13;
                dump.cipher_suite = meta.cipher_suite;
                std::memcpy(dump.client_random, meta.client_random, 32);
                std::memcpy(dump.server_random, meta.server_random, 32);
                break;
            }
            case DUMP_TLS_RECORD_DATA: {
                DumpTlsRecord tr;
                f.read(reinterpret_cast<char *>(&tr), sizeof(tr));
                std::vector<uint8_t> data(tr.data_length);
                f.read(reinterpret_cast<char *>(data.data()), tr.data_length);

                if (tr.label_id == LABEL_DATA_RECORD) {
                    dump.data_record = {tr.content_type, tr.version, std::move(data)};
                    dump.has_data_record = true;
                } else if (tr.label_id >= LABEL_TLS13_CLIENT_FINISHED &&
                           tr.label_id <= LABEL_TLS13_SERVER_APP_DATA) {
                    int idx = tr.label_id - 1;
                    dump.tls13_records[idx] = {tr.content_type, tr.version, std::move(data)};
                    dump.has_tls13_records[idx] = true;
                }
                break;
            }
            case DUMP_MEMORY_SNAPSHOT: {
                DumpMemoryHeader mh;
                f.read(reinterpret_cast<char *>(&mh), sizeof(mh));
                for (uint32_t i = 0; i < mh.page_count; i++) {
                    DumpPageEntry pe;
                    f.read(reinterpret_cast<char *>(&pe), sizeof(pe));
                    std::vector<uint8_t> page(DUMP_PAGE_SIZE);
                    f.read(reinterpret_cast<char *>(page.data()), DUMP_PAGE_SIZE);
                    dump.pages[pe.address] = std::move(page);
                }
                break;
            }
            case DUMP_MEMORY_DIFF: {
                DumpMemoryDiffHeader dh;
                f.read(reinterpret_cast<char *>(&dh), sizeof(dh));
                for (uint32_t i = 0; i < dh.changed_page_count; i++) {
                    DumpPageEntry pe;
                    f.read(reinterpret_cast<char *>(&pe), sizeof(pe));
                    std::vector<uint8_t> page(DUMP_PAGE_SIZE);
                    f.read(reinterpret_cast<char *>(page.data()), DUMP_PAGE_SIZE);
                    dump.pages[pe.address] = std::move(page);
                }
                break;
            }
            default:
                // Skip unknown record
                f.seekg(rh.length, std::ios::cur);
                break;
        }
    }
    return true;
}

static void write_hex(std::ostream &out, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        out << std::hex << std::setfill('0') << std::setw(2) << std::right
            << static_cast<unsigned int>(data[i]);
    }
}

static void extract_tls12(const DumpData &dump, std::ostream &out) {
    if (!dump.has_data_record) {
        std::cerr << "No data record in dump" << std::endl;
        return;
    }

    const SslCipherSuite *cs = ssl_find_cipher(dump.cipher_suite);
    if (!cs) {
        std::cerr << "Unknown cipher suite " << dump.cipher_suite << std::endl;
        return;
    }

    SslDecryptSession session = {};
    session.session.version = TLSV1DOT2_VERSION;
    session.state |= SSL_VERSION;
    session.client_random = {const_cast<uint8_t *>(dump.client_random), 32};
    session.server_random = {const_cast<uint8_t *>(dump.server_random), 32};
    session.state |= (SSL_CLIENT_RANDOM | SSL_SERVER_RANDOM | SSL_MASTER_SECRET);
    session.cipher_suite = cs;
    session.state |= SSL_CIPHER;

    auto dec_buffer = std::make_unique<uint8_t[]>(0xFFFF);
    StringInfo dec_out = {dec_buffer.get(), 0xFFFF};

    size_t concurrency = std::thread::hardware_concurrency();
    if (concurrency == 0) concurrency = 1;
    std::atomic<bool> found(false);
    std::mutex out_mutex;

    for (auto &[page_addr, page_data] : dump.pages) {
        if (found) break;
        if (page_data.size() < SSL_MASTER_SECRET_LENGTH) continue;

        size_t search_range = page_data.size() - SSL_MASTER_SECRET_LENGTH;
        size_t chunk_size = (search_range + concurrency - 1) / concurrency;
        std::vector<std::thread> threads;

        for (size_t t = 0; t < concurrency; t++) {
            size_t start = t * chunk_size;
            size_t end = std::min(start + chunk_size, search_range);
            threads.emplace_back([&, start, end]() {
                auto local_buf = std::make_unique<uint8_t[]>(0xFFFF);
                StringInfo local_out = {local_buf.get(), 0xFFFF};
                SslDecryptSession local_session = session;

                for (size_t i = start; i < end && !found.load(std::memory_order_relaxed); i++) {
                    local_session.master_secret = {const_cast<uint8_t *>(page_data.data()) + i, SSL_MASTER_SECRET_LENGTH};
                    ssl_generate_keyring_material(&local_session);
                    guint outl;
                    local_session.client_new.seq = 1;
                    local_session.client_new.cipher_suite = local_session.cipher_suite;
                    int result = ssl_decrypt_record(&local_session, &local_session.client_new, SSL_ID_APP_DATA,
                                                    dump.data_record.version, false,
                                                    dump.data_record.data.data(), dump.data_record.data.size(),
                                                    nullptr, 0, nullptr, &local_out, &outl);
                    gcry_cipher_close(local_session.client_new.evp);
                    gcry_cipher_close(local_session.server_new.evp);

                    if (result == 0) {
                        found.store(true, std::memory_order_relaxed);
                        std::lock_guard<std::mutex> lock(out_mutex);
                        out << "CLIENT_RANDOM ";
                        write_hex(out, dump.client_random, 32);
                        out << " ";
                        write_hex(out, page_data.data() + i, SSL_MASTER_SECRET_LENGTH);
                        out << std::endl;
                    }
                }
            });
        }
        for (auto &th : threads) th.join();
    }

    if (!found) std::cerr << "Master secret not found" << std::endl;
}

static bool try_decrypt_tls13_offline(uint16_t cipher_suite_num, uint8_t *candidate,
                                       const DumpData::RecordData &record, uint64_t seq,
                                       StringInfo *local_out) {
    const SslCipherSuite *cs = ssl_find_cipher(cipher_suite_num);
    if (!cs) return false;

    size_t secret_len = (cs->dig == DIG_SHA384) ? 48 : 32;

    SslDecoder decoder = {};
    if (tls13_init_decoder_from_secret(&decoder, cs, candidate, secret_len) != 0) return false;
    decoder.seq = seq;

    SslDecryptSession session = {};
    session.session.version = TLSV1DOT3_VERSION;
    session.session.tls13_draft_version = 0;
    session.cipher_suite = cs;

    guint outl;
    int result = ssl_decrypt_record(&session, &decoder, SSL_ID_APP_DATA,
                                     record.version, false,
                                     record.data.data(), record.data.size(),
                                     nullptr, 0, nullptr, local_out, &outl);
    gcry_cipher_close(decoder.evp);
    return result == 0;
}

static void extract_tls13(const DumpData &dump, std::ostream &out) {
    const SslCipherSuite *cs = ssl_find_cipher(dump.cipher_suite);
    if (!cs) {
        std::cerr << "Unknown cipher suite " << dump.cipher_suite << std::endl;
        return;
    }
    size_t secret_len = (cs->dig == DIG_SHA384) ? 48 : 32;

    struct Target {
        const char *label;
        int record_idx; // index into tls13_records
    };
    Target targets[] = {
        {"CLIENT_HANDSHAKE_TRAFFIC_SECRET", 0},
        {"CLIENT_TRAFFIC_SECRET_0", 1},
        {"SERVER_HANDSHAKE_TRAFFIC_SECRET", 2},
        {"SERVER_TRAFFIC_SECRET_0", 3},
    };

    size_t concurrency = std::thread::hardware_concurrency();
    if (concurrency == 0) concurrency = 1;
    std::mutex out_mutex;

    for (auto &target : targets) {
        if (!dump.has_tls13_records[target.record_idx]) {
            std::cerr << "Warning: no record for " << target.label << std::endl;
            continue;
        }
        const auto &record = dump.tls13_records[target.record_idx];

        std::cerr << "Searching for " << target.label << " ..." << std::endl;
        std::atomic<bool> found(false);

        for (auto &[page_addr, page_data] : dump.pages) {
            if (found) break;
            if (page_data.size() < secret_len) continue;

            size_t search_range = page_data.size() - secret_len;
            size_t chunk_size = (search_range + concurrency - 1) / concurrency;
            std::vector<std::thread> threads;

            for (size_t t = 0; t < concurrency; t++) {
                size_t start = t * chunk_size;
                size_t end = std::min(start + chunk_size, search_range);
                threads.emplace_back([&, start, end]() {
                    auto local_buf = std::make_unique<uint8_t[]>(0xFFFF);
                    StringInfo local_out = {local_buf.get(), 0xFFFF};

                    for (size_t i = start; i < end && !found.load(std::memory_order_relaxed); i++) {
                        bool ok = try_decrypt_tls13_offline(
                            dump.cipher_suite,
                            const_cast<uint8_t *>(page_data.data()) + i,
                            record, 0, &local_out);
                        if (ok) {
                            found.store(true, std::memory_order_relaxed);
                            std::lock_guard<std::mutex> lock(out_mutex);
                            out << target.label << " ";
                            write_hex(out, dump.client_random, 32);
                            out << " ";
                            write_hex(out, page_data.data() + i, secret_len);
                            out << std::endl;
                        }
                    }
                });
            }
            for (auto &th : threads) th.join();
        }

        if (!found) std::cerr << "Warning: " << target.label << " not found" << std::endl;
    }
}

int deferred_extract(const std::string &dump_dir, const std::string &output_file) {
    std::ofstream out_file;
    std::ostream *out = &std::cout;
    if (!output_file.empty()) {
        out_file.open(output_file);
        out = &out_file;
    }

    int count = 0;
    for (auto &entry : std::filesystem::directory_iterator(dump_dir)) {
        if (entry.path().extension() != ".tlsdump") continue;

        if (std::filesystem::file_size(entry.path()) == 0) continue;

        std::cerr << "Processing " << entry.path().filename() << " ..." << std::endl;
        DumpData dump;
        if (!read_dump_file(entry.path().string(), dump)) continue;
        if (dump.pages.empty()) continue;

        if (dump.is_tls13) {
            extract_tls13(dump, *out);
        } else {
            extract_tls12(dump, *out);
        }
        count++;
    }

    if (count == 0) {
        std::cerr << "No .tlsdump files found in " << dump_dir << std::endl;
        return 1;
    }

    out->flush();
    return 0;
}
