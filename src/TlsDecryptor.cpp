#include "TlsDecryptor.h"
#include <csignal>

TlsDecryptor::TlsDecryptor(pid_t pid, std::string filename) : DataConsumer(pid) {
    concurrency = std::thread::hardware_concurrency();
    if (!filename.empty()) {
        this->output.open(filename);
    }
}

extern "C" void terminate(int) {
    std::_Exit(1);
}

void TlsDecryptor::find_master_secret() {
    prepare_decryption();

    std::cerr << "TLS handshake and data record captured. Probing memory ..." << std::endl;

    MemoryExporter exporter(pid);
    auto maps = exporter.get_memory_maps();

    bool done = false;
    for (auto &map: maps) {
        auto memory_ptr = exporter.get_memory_section(map);
        auto memory = memory_ptr.get();
        if (memory == nullptr || map.size() < SSL_MASTER_SECRET_LENGTH) {
            continue;
        }
        size_t chunk_size = (map.size() - SSL_MASTER_SECRET_LENGTH + concurrency - 1) / concurrency;
        pid_t pids[concurrency];
        for (size_t task_index = 0; task_index < concurrency; task_index++) {
            size_t start = task_index * chunk_size;
            size_t end = std::min(start + chunk_size, map.size() - SSL_MASTER_SECRET_LENGTH);

            // Threads would be a better solution here. However, there is some memory access
            // that causes corruption.
            // TODO: Use threads instead of forks.
            pid_t pid = fork();
            if (pid == 0) {
                std::signal(SIGUSR1, terminate);
                for (size_t i = start; i < end; i++) {
                    bool decrypted = try_decrypt(memory + i);
                    if (decrypted) {
                        // Other files may write to the same stream.
                        // TODO: Lock it somehow.
                        auto outstream = this->output.is_open() ? &this->output : &std::cout;
                        write_keylog_data(*outstream, memory + i);
                        std::signal(SIGUSR1, SIG_IGN);
                        abort_on_error(killpg(0, SIGUSR1));
                        std::_Exit(0);
                    }
                }
                std::_Exit(1);
            }
            pids[task_index] = pid;
        }

        for (size_t task_index = 0; task_index < concurrency; task_index++) {
            int status;
            abort_on_error(waitpid(pids[task_index], &status, 0));
            if (status == 0) {
                done = true;
            }
        }

        if (done) {
            break;
        }

    }
    this->finished = true;
    std::cerr << "Probing done" << std::endl;
}

void TlsDecryptor::handle_full_record(TlsDecryptor::stream_chunk &chunk, Direction dir) {
    switch (chunk.record.content_type) {
        case SSL_ID_HANDSHAKE: {
            if (chunk.record.length < 1) {
                break;
            }

            uint8_t handshake_type = chunk.record.data[0];

            if (handshake_type != SSL_HND_CLIENT_HELLO && handshake_type != SSL_HND_SERVER_HELLO) {
                break;
            }

            if (handshake_type == SSL_HND_CLIENT_HELLO && chunk.record.length >= 38) {
                client_hello_seen = true;
                std::memcpy(client_random, chunk.record.data + 6, 32);
                std::cerr << "CLIENT RANDOM:" << std::endl;
                hexdump(std::cerr, client_random, 32);

            }

            if (handshake_type == SSL_HND_SERVER_HELLO && chunk.record.length >= 40) {
                server_hello_seen = true;
                std::memcpy(server_random, chunk.record.data + 6, 32);
                std::cerr << "SERVER RANDOM:" << std::endl;
                hexdump(std::cerr, server_random, 32);

                uint8_t session_id_length = chunk.record.data[38];
                if (chunk.record.length > 38 + session_id_length + 2) {
                    cipher_suite = ((chunk.record.data[38 + session_id_length + 1] << 8)
                                    | (chunk.record.data[38 + session_id_length + 2]));
                    std::cerr << "CIPHER SUITE" << cipher_suite << std::endl;
                    cipher_suite_set = true;
                }
            }
            break;
        }
        case SSL_ID_APP_DATA: {
            data_record = chunk.record;
            has_data_record = true;
            break;
        }
    }

    if (may_decrypt()) {
        this->find_master_secret();
    }

    delete[] chunk.record.data;
    chunk = {};
}

void TlsDecryptor::handle_data(const uint8_t *data, size_t len, Direction dir) {
#define CONSUME_BYTE() len--; chunk.read++; data++;

    stream_chunk &chunk = dir == Direction::Out ? upchunk : downchunk;

    while (len > 0) {
        if (chunk.read == 0) {
            chunk.record.content_type = data[0];
            CONSUME_BYTE();
        } else if (chunk.read == 1) {
            chunk.record.version |= data[0] << 8;
            CONSUME_BYTE();
        } else if (chunk.read == 2) {
            chunk.record.version |= data[0];
            CONSUME_BYTE();
        } else if (chunk.read == 3) {
            chunk.record.length |= data[0] << 8;
            CONSUME_BYTE();
        } else if (chunk.read == 4) {
            chunk.record.length |= data[0];
            CONSUME_BYTE();
        } else {
            if (chunk.record.data == nullptr) {
                chunk.record.data = new uint8_t[chunk.record.length];
            }
            size_t offset = chunk.read - 5;
            uint16_t read = std::min((size_t) chunk.record.length - offset, len);
            std::memmove(chunk.record.data + offset, data, read);
            chunk.read += read;
            if (is_chunk_complete(chunk)) {
                handle_full_record(chunk, dir);
            }
            data += read;
            len -= read;
        }
    }
}

bool TlsDecryptor::may_decrypt() const {
    return client_hello_seen && server_hello_seen && cipher_suite_set && has_data_record;
}

void TlsDecryptor::prepare_decryption() {
    if (!may_decrypt()) {
        return;
    }
    decrypt_session.session.version = TLSV1DOT2_VERSION; //TLSV1DOT2_VERSION;
    // decrypt_session.cipher_suite->kex = KEX_TLS13; // Remove
    decrypt_session.state |= SSL_VERSION;

    decrypt_session.client_random = {client_random, 32};
    decrypt_session.server_random = {server_random, 32};
    decrypt_session.state |= (SSL_CLIENT_RANDOM | SSL_SERVER_RANDOM | SSL_MASTER_SECRET);

    decrypt_session.cipher_suite = ssl_find_cipher(cipher_suite);
    if (decrypt_session.cipher_suite == nullptr) {
        finished = true;
        return;
    }
    decrypt_session.state |= SSL_CIPHER;
}

bool TlsDecryptor::try_decrypt(uint8_t *master_secret) {
    decrypt_session.master_secret = {master_secret, SSL_MASTER_SECRET_LENGTH};
    ssl_generate_keyring_material(&decrypt_session);
    guint outl;
    decrypt_session.client_new.seq = 1;
    decrypt_session.client_new.cipher_suite = decrypt_session.cipher_suite;
    int result = ssl_decrypt_record(&decrypt_session, &decrypt_session.client_new, SSL_ID_APP_DATA,
                                    data_record.version, false,
                                    data_record.data, data_record.length, nullptr, 0, nullptr, &out, &outl);
    gcry_cipher_close(decrypt_session.client_new.evp);
    gcry_cipher_close(decrypt_session.server_new.evp);
    return result == 0;
}

void TlsDecryptor::read(uint8_t *buffer, size_t length) {
    DataConsumer::read(buffer, length);
    handle_data(buffer, length, Direction::In);
}

void TlsDecryptor::write(uint8_t *buffer, size_t length) {
    DataConsumer::write(buffer, length);
    handle_data(buffer, length, Direction::Out);
}

bool TlsDecryptor::is_finished() const {
    return this->finished;
}

bool TlsDecryptor::is_chunk_complete(TlsDecryptor::stream_chunk &chunk) {
    return chunk.read >= 5 && chunk.read - 5 == chunk.record.length;
}

void TlsDecryptor::set_concurrency(size_t concurrency) {
    this->concurrency = concurrency;
}

template<typename T>
void TlsDecryptor::write_keylog_data(T &stream, const uint8_t *master_secret) {
    std::ios_base::fmtflags f(stream.flags());
    stream << "CLIENT_RANDOM ";

    for (unsigned char i: client_random) {
        stream << std::hex << std::setfill('0') << std::setw(2) << std::right << static_cast<unsigned int>(i);
    }

    stream << " ";

    for (size_t i = 0; i < SSL_MASTER_SECRET_LENGTH; i++) {
        stream << std::hex << std::setfill('0') << std::setw(2) << std::right
               << static_cast<unsigned int>(master_secret[i]);
    }
    stream << std::endl;

    stream.flags(f);
    stream.flush();
}
