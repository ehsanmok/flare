/*
 * Tiny libc wrapper for flare's FileServer.
 *
 * Mojo's stdlib registers ``open`` / ``read`` / ``write`` / ``close``
 * with specific external_call signatures; calling those names again
 * from user code produces "existing function with conflicting
 * signature" errors during LLVM lowering. Wrapping them under
 * unique names keeps flare's static-file path independent of the
 * stdlib's internal FFI bindings.
 */

#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

int flare_fs_open_rdonly(const char* path) {
    return open(path, O_RDONLY);
}

int flare_fs_close(int fd) {
    return close(fd);
}

int64_t flare_fs_size(const char* path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    off_t s = lseek(fd, 0, SEEK_END);
    close(fd);
    return (int64_t)s;
}

int64_t flare_fs_pread(int fd, void* buf, size_t n, int64_t offset) {
    if (offset > 0) {
        if (lseek(fd, (off_t)offset, SEEK_SET) < 0) return -1;
    }
    ssize_t got = read(fd, buf, n);
    return (int64_t)got;
}

int flare_fs_access(const char* path) {
    return access(path, F_OK);
}
