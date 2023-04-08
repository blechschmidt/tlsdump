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

    /**
     * Initialize a TLS decryptor, which is responsible for parsing TLS records supplied as raw read and write
     * data streams from the connection tracker.
     *
     * @param pid The PID of the target process (required to extract the memory for the master secret search).
     * @param filename The filename which to log the key material to.
     */
    explicit TlsDecryptor(pid_t pid, std::string filename="");

    /**
     * Set the number of processes to be used for searching the target process memory.
     *
     * @param concurrency The number of processes.
     */
    void set_concurrency(size_t concurrency);

    /**
     * This function detects whether the stream chunk contains a complete TLS record.
     *
     * @param chunk The chunk structure.
     * @return Whether it contains a complete TLS record.
     */
    static bool is_chunk_complete(stream_chunk &chunk);

    /**
     * This function is called as soon as a full TLS record has been received.
     *
     * @param chunk The stream chunk containing the full record.
     * @param dir The direction of the record.
     */
    void handle_full_record(stream_chunk &chunk, Direction dir);

    /**
     * This function is called by the ptrace handling functions whenever data is read or written.
     *
     * @param data The data buffer.
     * @param len The length of the data in the buffer.
     * @param dir The direction of the data in the data stream (outbound or inbound).
     */
    void handle_data(const uint8_t *data, size_t len, Direction dir);

    /**
     * This function will return true after the TLS handshake and a data record have been recorded.
     * It is only then that we have sufficient information to search for the master secret in the
     * memory of the target process.
     *
     * @return Whether the decryption process can be started.
     */
    [[nodiscard]] bool may_decrypt() const;

    /**
     * Initialize Wireshark structures used for decryption.
     */
    void prepare_decryption();

    /**
     *
     * @param master_secret The 48 byte long master secret used for the decryption attempt.
     * @return Whether the decryption attempt was successful, i.e. whether the correct master secret was supplied.
     */
    bool try_decrypt(uint8_t *master_secret);

    /**
     * Output the master secret to a specified output stream in NSS key log format.
     * The format is described at https://firefox-source-docs.mozilla.org/security/nss/legacy/key_log_format/index.html.
     *
     * @tparam T The stream type.
     * @param stream The stream which they keylog data is written to.
     * @param master_secret The 48 byte long master secret.
     */
    template<typename T>
    void write_keylog_data(T &stream, const uint8_t *master_secret);

    /**
     * When the connection tracker records a data read operation, it will call this function.
     *
     * @param buffer The data buffer.
     * @param length The length of the buffer.
     */
    void read(uint8_t *buffer, size_t length) override;

    /**
     * When the connection tracker records a data write operation, it will call this function.
     *
     * @param buffer The data buffer.
     * @param length The length of the buffer.
     */
    void write(uint8_t *buffer, size_t length) override;

    /**
     * This function signals whether the connection can be removed from the connection tracker.
     * It will return true after the TLS handshake and a data record have been recorded and
     * the process memory has been extracted and searched for the master secret.
     *
     * @return Whether the connection can be removed from the connection tracker.
     */
    bool is_finished() const override;

    /**
     * This function extracts the target process memory and searches the master secret.
     */
    void find_master_secret();
};


#endif //TLSDUMP_TLSDECRYPTOR_H
