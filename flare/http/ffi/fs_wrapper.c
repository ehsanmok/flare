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

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

int flare_fs_open_rdonly(const char* path) {
    return open(path, O_RDONLY | O_CLOEXEC);
}

int flare_fs_close(int fd) {
    return close(fd);
}

int64_t flare_fs_size(const char* path) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    off_t s = lseek(fd, 0, SEEK_END);
    close(fd);
    return (int64_t)s;
}

/* Read exactly ``n`` bytes at ``offset`` unless EOF comes first. A
 * single read() may return less than asked for, which silently
 * truncated large bodies. Returns the byte count, or -1 on error. */
int64_t flare_fs_pread(int fd, void* buf, size_t n, int64_t offset) {
    size_t done = 0;
    while (done < n) {
        ssize_t got = pread(fd, (char*)buf + done, n - done,
                            (off_t)(offset + (int64_t)done));
        if (got < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (got == 0) break;
        done += (size_t)got;
    }
    return (int64_t)done;
}

/* Open ``path`` for serving from ``root``. Returns an fd, or -1 when
 * the file does not exist, is not a regular file (directories used to
 * reach read() and fail with EISDIR, a 500), or resolves -- through
 * any symlink along the way -- to somewhere outside ``root``. On
 * success writes the size and mtime (Unix seconds). */
int flare_fs_open_regular(const char* path, const char* root,
                          int64_t* size_out, int64_t* mtime_out) {
    char real_root[PATH_MAX];
    char real_path[PATH_MAX];
    if (realpath(root, real_root) == NULL) return -1;
    if (realpath(path, real_path) == NULL) return -1;
    size_t rl = strlen(real_root);
    if (strncmp(real_path, real_root, rl) != 0) return -1;
    if (rl > 1 && real_path[rl] != '/' && real_path[rl] != '\0') return -1;
    int fd = open(real_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return -1;
    }
    *size_out = (int64_t)st.st_size;
    *mtime_out = (int64_t)st.st_mtime;
    return fd;
}

int flare_fs_access(const char* path) {
    return access(path, F_OK);
}

/* What is at ``path``, without following a final symlink: 0 nothing,
 * 1 a socket (its device and inode written out), 2 anything else, -1
 * any other lstat failure. Used by the UDS listener to tell a stale
 * socket from a live one or from a file that is not a socket at all. */
int flare_fs_lstat_kind(const char* path, uint64_t* dev, uint64_t* ino) {
    struct stat st;
    if (lstat(path, &st) != 0) return errno == ENOENT ? 0 : -1;
    if (dev) *dev = (uint64_t)st.st_dev;
    if (ino) *ino = (uint64_t)st.st_ino;
    return S_ISSOCK(st.st_mode) ? 1 : 2;
}
