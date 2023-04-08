#ifndef TLSDUMP_PTRACECONNECTIONTRACKER_H
#define TLSDUMP_PTRACECONNECTIONTRACKER_H

#include "Direction.h"
#include "TlsDecryptor.h"
#include "util.h"
#include "DataConsumerFactory.h"

#include <unordered_map>

#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <unordered_set>


class PtraceConnectionTracker {
    pid_t pid;
    int status = 0;
    std::unordered_map<int, std::unique_ptr<DataConsumer>> streams;
    std::unordered_set<uint16_t> filtered_ports;
    struct user_regs_struct state = {};
    std::unique_ptr<DataConsumerFactory> factory;

    struct read_send_data {
        int socket;
        uint8_t *buffer;
        ssize_t buffer_len;
    };

public:
    explicit PtraceConnectionTracker(pid_t pid, std::unique_ptr<DataConsumerFactory> factory);

    /**
     *
     * @param port Add a port for filtering TCP
     */
    void filter_port(uint16_t port);

    /**
     * Run the tracer in a loop and hook the system calls. Will not return unless the tracee has exited.
     */
    void run();

private:
    /**
     * Copy memory from the tracee into the tracer (our process).
     *
     * @param destination The destination buffer.
     * @param address The source address in the tracee.
     * @param len The data length.
     */
    void tracee_memcpy(uint8_t *destination, uint8_t *address, size_t len) const;

    /**
     * Called when the tracee process performs a connect syscall.
     */
    void tracee_connect();

    /**
     * Called when the tracee performs a close syscall.
     */
    void tracee_close();

    /**
     * Called when the tracee performs a recvmsg or sendmsg syscall.
     *
     * @param dir Specifies whether it was a receive or send call.
     */
    void tracee_recvmsg_sendmsg(Direction dir);

    void tracee_read_send(Direction dir);

    bool tracee_finish_syscall();

    void removed_finished();

    template<typename T>
    T cast_syscall_result();
};

#endif //TLSDUMP_PTRACECONNECTIONTRACKER_H
