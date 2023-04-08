#ifndef TLSDUMP_TLSDECRYPTOR_H
#define TLSDUMP_TLSDECRYPTOR_H

#include <chrono>
#include <cstdint>

#include <sys/socket.h>
#include <sys/wait.h>
#include <thread>
#include <memory>

extern "C" {
    #include "wireshark.h"
};
#include "DataConsumer.h"
#include "MemoryExporter.h"
#include "Direction.h"

struct TlsDecryptor : DataConsumer {
    struct tls_record {
        uint8_t content_type;
        uint16_t version;
        uint16_t length;
        uint8_t *data;
    };

    struct stream_chunk {
        uint16_t read;
        struct tls_record record;
    };

    stream_chunk downchunk = {};
    stream_chunk upchunk = {};
    struct sockaddr_storage addr = {};

    uint8_t client_random[32] = {};
    uint8_t server_random[32] = {};
    bool has_data_record = false;
    uint16_t cipher_suite = 0;
    bool cipher_suite_set = false;
    bool client_hello_seen = false;
    bool server_hello_seen = false;
    size_t concurrency = 1;
    bool finished = false;
    std::ofstream output;

    tls_record data_record = {};

    SslDecryptSession decrypt_session = {};

    uint8_t decryption_buffer[0xFFFF] = {};


    StringInfo out = {decryption_buffer, 0xFFFF};

    TlsDecryptor(pid_t pid, std::string filename="");

    void set_concurrency(size_t concurrency);

    static bool has_full_record(stream_chunk &chunk);

    bool handle_full_record(stream_chunk &chunk, Direction dir);

    void append_records(const uint8_t *data, size_t len, Direction dir);

    void add_record(tls_record &record, Direction dir);

    [[nodiscard]] bool canDecrypt() const;

    void prepare_decryption();

    bool try_decrypt(uint8_t *master_secret);

    template<typename T>
    void write_keylog_data(T &stream, const uint8_t *master_secret);

    void read(uint8_t *buffer, size_t length) override;

    void write(uint8_t *buffer, size_t length) override;

    bool is_finished() const override;
};


#endif //TLSDUMP_TLSDECRYPTOR_H
