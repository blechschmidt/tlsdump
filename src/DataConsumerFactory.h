#ifndef TLSDUMP_DATACONSUMERFACTORY_H
#define TLSDUMP_DATACONSUMERFACTORY_H

#include <atomic>
#include <string>
#include <memory>
#include "DataConsumer.h"
#include "TlsDecryptor.h"
#include "DeferredDumpConsumer.h"

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

class DeferredDumpFactory : public DataConsumerFactory {
    std::string dump_dir;
    std::atomic<uint32_t> counter{0};
public:
    explicit DeferredDumpFactory(const std::string &dump_dir) : dump_dir(dump_dir) {}

    std::unique_ptr<DataConsumer> create(pid_t pid) override {
        uint32_t id = counter.fetch_add(1);
        std::string path = dump_dir + "/conn_" + std::to_string(id) + "_" + std::to_string(pid) + ".tlsdump";
        return std::make_unique<DeferredDumpConsumer>(pid, path);
    }
};

#endif //TLSDUMP_DATACONSUMERFACTORY_H
