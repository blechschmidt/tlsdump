#include <csignal>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>

#include <unistd.h>
#include <gcrypt.h>

#include "PtraceConnectionTracker.h"
#include "util.h"
#include "DataConsumerFactory.h"
#include "DeferredExtractor.h"

pid_t start_process(char *file, char **argv) {
    pid_t child = abort_on_error(fork());
    if (child == 0) {
        abort_on_error(execvp(file, argv));
    }
    return child;
}

int main(int argc, char **argv) {
    pid_t process_pid = 0;
    std::string filename;
    std::string defer_dir;
    std::string extract_dir;

    gcry_check_version(NULL);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    abort_on_error(setpgid(0, 0));
    std::signal(SIGUSR1, SIG_IGN);

    if (argc < 2) {
        std::cerr << "Usage: tlsdump [-w keylogfile] [--defer dir | --extract dir] -- command ..." << std::endl;
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        std::string arg(argv[i]);
        if (arg == "--") {
            if (i == argc - 1) {
                std::cerr << "Missing argument" << std::endl;
                return 1;
            }
            process_pid = start_process(argv[i + 1], argv + i + 1);
            break;
        }
        if (arg == "-w" && i + 1 < argc) {
            filename = std::string(argv[++i]);
        } else if (arg == "--defer" && i + 1 < argc) {
            defer_dir = std::string(argv[++i]);
        } else if (arg == "--extract" && i + 1 < argc) {
            extract_dir = std::string(argv[++i]);
        }
    }

    // Stage 2: offline extraction
    if (!extract_dir.empty()) {
        return deferred_extract(extract_dir, filename);
    }

    if (process_pid == 0) {
        process_pid = std::stoi(argv[1]);
    }

    std::cerr << "Tracing PID " << process_pid << std::endl;

    std::unique_ptr<DataConsumerFactory> factory;
    if (!defer_dir.empty()) {
        // Stage 1: capture mode
        std::filesystem::create_directories(defer_dir);
        std::cerr << "Deferred mode: dumping to " << defer_dir << std::endl;
        factory = std::make_unique<DeferredDumpFactory>(defer_dir);
    } else {
        // Normal mode: inline key extraction
        if (!filename.empty()) {
            std::cerr << "Writing output to " << filename << std::endl;
        }
        auto f = std::make_unique<TLSDecryptorFactory>();
        f->set_filename(filename);
        factory = std::move(f);
    }

    PtraceConnectionTracker tracker(process_pid, std::move(factory));
    tracker.run();
    return 0;
}
