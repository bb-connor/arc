#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef CHIO_DEMO_PYTHON_PATH
#error "CHIO_DEMO_PYTHON_PATH must be defined"
#endif

#ifndef CHIO_DEMO_PYTHON_SHA256
#error "CHIO_DEMO_PYTHON_SHA256 must be defined"
#endif

#ifndef CHIO_DEMO_SCRIPT_SHA256
#error "CHIO_DEMO_SCRIPT_SHA256 must be defined"
#endif

#define CHIO_DEMO_UID ((uid_t)10002)
#define CHIO_DEMO_GID ((gid_t)10002)
#define CHIO_DEMO_SCRIPT_PATH "/opt/chio/examples/mock_mcp_server.py"
#define SHA256_HEX_BYTES 64

static void fail(const char *message) {
    (void)fprintf(stderr, "MCP demo launcher denied: %s\n", message);
    _exit(126);
}

static int has_exact_empty_group_identity(uid_t expected_uid, gid_t expected_gid) {
    uid_t real_uid = 0;
    uid_t effective_uid = 0;
    uid_t saved_uid = 0;
    gid_t real_gid = 0;
    gid_t effective_gid = 0;
    gid_t saved_gid = 0;
    if (getresuid(&real_uid, &effective_uid, &saved_uid) != 0
        || getresgid(&real_gid, &effective_gid, &saved_gid) != 0
        || getgroups(0, NULL) != 0) {
        return 0;
    }
    return real_uid == expected_uid && effective_uid == expected_uid
        && saved_uid == expected_uid && real_gid == expected_gid
        && effective_gid == expected_gid && saved_gid == expected_gid;
}

static int open_verified_regular(const char *path, const char *expected_digest) {
    int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        fail("required target is unavailable");
    }

    struct stat metadata;
    if (fstat(descriptor, &metadata) != 0 || !S_ISREG(metadata.st_mode)
        || metadata.st_uid != 0 || (metadata.st_mode & (S_IWGRP | S_IWOTH)) != 0
        || metadata.st_size <= 0) {
        (void)close(descriptor);
        fail("required target metadata is invalid");
    }

    EVP_MD_CTX *context = EVP_MD_CTX_new();
    if (context == NULL || EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(context);
        (void)close(descriptor);
        fail("target digest initialization failed");
    }

    unsigned char buffer[16384];
    for (;;) {
        ssize_t length = read(descriptor, buffer, sizeof(buffer));
        if (length == 0) {
            break;
        }
        if (length < 0) {
            if (errno == EINTR) {
                continue;
            }
            EVP_MD_CTX_free(context);
            (void)close(descriptor);
            fail("target digest read failed");
        }
        if (EVP_DigestUpdate(context, buffer, (size_t)length) != 1) {
            EVP_MD_CTX_free(context);
            (void)close(descriptor);
            fail("target digest update failed");
        }
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_length = 0;
    if (EVP_DigestFinal_ex(context, digest, &digest_length) != 1
        || digest_length != 32) {
        EVP_MD_CTX_free(context);
        (void)close(descriptor);
        fail("target digest finalization failed");
    }
    EVP_MD_CTX_free(context);

    static const char hex[] = "0123456789abcdef";
    char encoded[SHA256_HEX_BYTES + 1];
    for (unsigned int index = 0; index < digest_length; ++index) {
        encoded[index * 2] = hex[digest[index] >> 4];
        encoded[index * 2 + 1] = hex[digest[index] & 0x0f];
    }
    encoded[SHA256_HEX_BYTES] = '\0';
    if (strlen(expected_digest) != SHA256_HEX_BYTES
        || strcmp(encoded, expected_digest) != 0) {
        (void)close(descriptor);
        fail("target digest mismatch");
    }
    if (lseek(descriptor, 0, SEEK_SET) != 0) {
        (void)close(descriptor);
        fail("target rewind failed");
    }
    return descriptor;
}

static int close_descriptor_range(unsigned int first, unsigned int last) {
    if (first > last || syscall(SYS_close_range, first, last, 0) == 0) {
        return 0;
    }
    if (errno == ENOSYS || errno == EPERM) {
        return 1;
    }
    fail("cannot close inherited descriptors");
    return 1;
}

static void close_unneeded_from_procfs(
    int python_descriptor,
    int script_descriptor
) {
    DIR *directory = opendir("/proc/self/fd");
    if (directory == NULL) {
        fail("cannot close inherited descriptors");
    }
    int directory_descriptor = dirfd(directory);
    if (directory_descriptor < 0) {
        fail("cannot inspect inherited descriptors");
    }

    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0) {
                fail("cannot inspect inherited descriptors");
            }
            break;
        }
        if (entry->d_name[0] < '0' || entry->d_name[0] > '9') {
            continue;
        }
        char *end = NULL;
        errno = 0;
        unsigned long value = strtoul(entry->d_name, &end, 10);
        if (errno != 0 || end == entry->d_name || *end != '\0' || value > INT_MAX) {
            fail("inherited descriptor entry is invalid");
        }
        int descriptor = (int)value;
        if (descriptor < 3 || descriptor == python_descriptor
            || descriptor == script_descriptor
            || descriptor == directory_descriptor) {
            continue;
        }
        if (close(descriptor) != 0) {
            fail("cannot close inherited descriptor");
        }
    }
    if (closedir(directory) != 0) {
        fail("cannot close descriptor directory");
    }
}

static void close_unneeded_descriptors(int python_descriptor, int script_descriptor) {
    if (python_descriptor < 3 || script_descriptor < 3
        || python_descriptor == script_descriptor) {
        fail("verified target descriptors are invalid");
    }

    unsigned int first = (unsigned int)python_descriptor;
    unsigned int second = (unsigned int)script_descriptor;
    if (first > second) {
        unsigned int swap = first;
        first = second;
        second = swap;
    }

    if (close_descriptor_range(3, first - 1)
        || close_descriptor_range(first + 1, second - 1)
        || close_descriptor_range(second + 1, UINT_MAX)) {
        close_unneeded_from_procfs(python_descriptor, script_descriptor);
    }
}

int main(int argc, char **argv) {
    (void)argv;
    if (argc != 1) {
        fail("invalid invocation identity or arguments");
    }
    int starts_as_root = has_exact_empty_group_identity(0, 0);
    int starts_as_target =
        has_exact_empty_group_identity(CHIO_DEMO_UID, CHIO_DEMO_GID);
    if (starts_as_root == starts_as_target) {
        fail("invalid invocation identity or arguments");
    }
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) {
        fail("cannot disable process dumps");
    }

    int python_descriptor =
        open_verified_regular(CHIO_DEMO_PYTHON_PATH, CHIO_DEMO_PYTHON_SHA256);
    int script_descriptor =
        open_verified_regular(CHIO_DEMO_SCRIPT_PATH, CHIO_DEMO_SCRIPT_SHA256);
    int script_flags = fcntl(script_descriptor, F_GETFD);
    if (script_flags < 0
        || fcntl(script_descriptor, F_SETFD, script_flags & ~FD_CLOEXEC) != 0) {
        fail("cannot bind the reviewed MCP script descriptor");
    }

    if (clearenv() != 0) {
        fail("cannot scrub the launcher environment");
    }
    if (starts_as_root
        && (setgroups(0, NULL) != 0
            || setresgid(CHIO_DEMO_GID, CHIO_DEMO_GID, CHIO_DEMO_GID) != 0
            || setresuid(CHIO_DEMO_UID, CHIO_DEMO_UID, CHIO_DEMO_UID) != 0)) {
        fail("cannot enter the untrusted MCP identity");
    }
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 || chdir("/opt/chio") != 0
        || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        fail("cannot enter the untrusted MCP identity");
    }
    if (!has_exact_empty_group_identity(CHIO_DEMO_UID, CHIO_DEMO_GID)
        || prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) != 0) {
        fail("untrusted MCP identity transition was incomplete");
    }

    close_unneeded_descriptors(python_descriptor, script_descriptor);
    char script_fd_path[64];
    int written = snprintf(
        script_fd_path,
        sizeof(script_fd_path),
        "/proc/self/fd/%d",
        script_descriptor
    );
    if (written <= 0 || (size_t)written >= sizeof(script_fd_path)) {
        fail("cannot encode the reviewed MCP script descriptor");
    }

    char *const child_argv[] = {
        (char *)CHIO_DEMO_PYTHON_PATH,
        (char *)"-I",
        (char *)"-B",
        script_fd_path,
        NULL,
    };
    char *const child_environment[] = {
        (char *)"HOME=/nonexistent",
        (char *)"LANG=C.UTF-8",
        (char *)"PATH=/usr/bin:/bin",
        (char *)"PYTHONDONTWRITEBYTECODE=1",
        NULL,
    };
    fexecve(python_descriptor, child_argv, child_environment);
    fail("reviewed MCP target execution failed");
}
