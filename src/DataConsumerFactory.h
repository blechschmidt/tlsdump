#ifndef TLSDUMP_DATACONSUMERFACTORY_H
#define TLSDUMP_DATACONSUMERFACTORY_H

#include <string>
#include <memory>
#include "DataConsumer.h"
#include "TlsDecryptor.h"

class DataConsumerFactory {

protected:
    std::string filename;
public:
    virtual std::unique_ptr<DataConsumer> create(pid_t pid) = 0;
    virtual ~DataConsumerFactory() = default;
};

class TLSDecryptorFactory : public DataConsumerFactory {
    std::string filename;
public:
    TLSDecryptorFactory() = default;

    std::unique_ptr<DataConsumer> create(pid_t pid) override {
        return std::unique_ptr<DataConsumer>(new TlsDecryptor(pid, filename));
    }

    void set_filename(std::string &filename) {
        this->filename = filename;
    }
};

#endif //TLSDUMP_DATACONSUMERFACTORY_H
