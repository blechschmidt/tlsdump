#ifndef TLSDUMP_DATACONSUMER_H
#define TLSDUMP_DATACONSUMER_H

#include <iostream>

#include <sys/socket.h>

#include "util.h"

class DataConsumer {
public:
    struct sockaddr_storage destination_address = {};
    pid_t pid = 0;

    explicit DataConsumer(pid_t pid) : pid(pid) {}

    virtual void read(uint8_t *buffer, size_t length) {
        std::cerr << "=== READ ===" << std::endl;
        hexdump(std::cerr, buffer, length);
    };

    virtual void write(uint8_t *buffer, size_t length) {
        std::cerr << "=== WRITE ===" << std::endl;
        hexdump(std::cerr, buffer, length);
    };

    [[nodiscard]] virtual bool is_finished() const {
        return true;
    }
};

#endif //TLSDUMP_DATACONSUMER_H
