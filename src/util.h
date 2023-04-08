#ifndef TLSDUMP_UTIL_H
#define TLSDUMP_UTIL_H

#include <cinttypes>
#include <cstring>
#include <ios>
#include <iostream>
#include <iomanip>
#include <source_location>

/**
 * Syscall wrapper that aborts on failure, i.e. when the syscall returns -1.
 * Note: Will not work for syscalls that do not return -1 upon failure.
 *
 * @tparam T The return type of the libc wrapper function.
 * @param value The return value of the syscall.
 * @param location The code location for improved debugging.
 * @return The original value.
 */
template<typename T>
T abort_on_error(T value, const std::source_location &location = std::source_location::current()) {
    auto error_code = errno;
    if (value == -1) {
        std::cerr << "Error: "
                  << location.file_name() << ":"
                  << location.line() << ":"
                  << location.function_name() << " "
                  << error_code << ", " << std::strerror(error_code) << std::endl;
        std::exit(1);
    }
    return value;
}

/**
 * This function writes a hexdump to the specified stream.
 *
 * @tparam T The type of the stream.
 * @param stream The stream.
 * @param buffer The buffer.
 * @param len The buffer length.
 */
template<typename T>
void hexdump(T &stream, const uint8_t *buffer, size_t len) {
    const uint8_t *end = buffer + len;
    std::ios_base::fmtflags f(stream.flags());

    while (buffer < end) {
        const uint8_t *bufstart = buffer;
        for (size_t i = 0; i < 16; i++) {
            if (buffer < end) {
                stream << std::hex << std::setfill('0') << std::setw(2) << std::right << std::uppercase
                       << static_cast<unsigned int>(*(buffer++)) << " ";
            } else {
                stream << "   ";
            }
            if (i == 7) {
                stream << " ";
            }
        }
        stream << " |";

        stream.flags(f);

        buffer = bufstart;
        for (size_t i = 0; i < 16 && buffer < end; i++) {
            uint8_t value = *(buffer++);
            if (std::isprint(value)) {
                stream << value;
            } else {
                stream << ".";
            }
        }
        stream << "|" << std::endl;
    }

    stream.flags(f);
}

#endif //TLSDUMP_UTIL_H
