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
        std::cerr << "Usage:" << std::endl;
        std::cerr << "  tlsdump [options] [--] command [args...]" << std::endl;
        std::cerr << "  tlsdump [options] pid" << std::endl;
        std::cerr << "  tlsdump --extract <dir> [-w keylogfile]" << std::endl;
        std::cerr << std::endl;
        std::cerr << "Options:" << std::endl;
        std::cerr << "  -w <file>       Write key material to file instead of stdout" << std::endl;
        std::cerr << "  --defer <dir>   Dump TLS metadata and memory to dir (no key search)" << std::endl;
        std::cerr << "  --extract <dir> Search for keys in dump files from dir" << std::endl;
        return 1;
    }

    int cmd_start = 0; // index of first non-option argument (command or PID)
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
        } else if (!cmd_start) {
            cmd_start = i;
        }
    }

    // Stage 2: offline extraction
    if (!extract_dir.empty()) {
        return deferred_extract(extract_dir, filename);
    }

    if (process_pid == 0 && cmd_start > 0) {
        // If the first non-option argument looks like a PID, attach to it.
        // Otherwise, treat it as a command to execute.
        try {
            process_pid = std::stoi(argv[cmd_start]);
        } catch (std::invalid_argument &) {
            process_pid = start_process(argv[cmd_start], argv + cmd_start);
        }
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
