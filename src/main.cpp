#include <csignal>
#include <iostream>
#include <memory>
#include <string>

#include <unistd.h>

#include "PtraceConnectionTracker.h"
#include "util.h"
#include "DataConsumerFactory.h"

/**
 * Start a process in a fork.
 *
 * @param file The file as supplied to execvp.
 * @param argv The arguments of the process.
 * @return The PID of the process.
 */
pid_t start_process(char *file, char **argv) {
    pid_t child = abort_on_error(fork());
    if (child == 0) {
        abort_on_error(execvp(file, argv));
    }
    return child;
}

int main(int argc, char **argv) {
    pid_t process_pid;
    std::string filename;

    abort_on_error(setpgid(0, 0));
    std::signal(SIGUSR1, SIG_IGN);

    if (argc < 2) {
        std::cerr << "PID required" << std::endl;
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
        if (arg == "-w") {
            if (i == argc - 1) {
                std::cerr << "Missing argument" << std::endl;
                return 1;
            }
            filename = std::string(argv[i + 1]);
        }
    }
    if (process_pid == 0) {
        process_pid = std::stoi(argv[1]);
    }
    std::cerr << "Tracing PID " << process_pid << std::endl;
    if (!filename.empty()) {
        std::cerr << "Writing output to " << filename << std::endl;
    }
    auto factory = std::make_unique<TLSDecryptorFactory>();
    factory->set_filename(filename);
    PtraceConnectionTracker tracker(process_pid, std::move(factory));
    tracker.run();
    return 0;
}
