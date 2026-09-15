#if defined(__x86_64__)
static long invoke(long number, long first, long second, long third, long fourth) {
    long result;
    register long r10 __asm__("r10") = fourth;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(first), "S"(second), "d"(third), "r"(r10)
                     : "rcx", "r11", "memory");
    return result;
}
static long invoke5(long number, long first, long second, long third, long fourth, long fifth) {
    long result;
    register long r10 __asm__("r10") = fourth;
    register long r8 __asm__("r8") = fifth;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(first), "S"(second), "d"(third), "r"(r10), "r"(r8)
                     : "rcx", "r11", "memory");
    return result;
}
#define SYS_EXIT 60
#define SYS_READ 0
#define SYS_WRITE 1
#define SYS_CLOSE 3
#define SYS_OPENAT 257
#define SYS_SOCKET 41
#define SYS_CLONE 56
#define SYS_CONNECT 42
#define SYS_BIND 49
#define SYS_EXECVE 59
#define SYS_GETPPID 110
#define SYS_UNLINKAT 263
#define SYS_LINKAT 265
#define SYS_RENAMEAT2 316
#define SYS_EXECVEAT 322
#define SYS_RT_SIGACTION 13
#define SYS_PPOLL 271
__asm__(
    ".global _start\n"
    ".type _start,@function\n"
    "_start:\n"
    "mov %rsp, %rdi\n"
    "andq $-16, %rsp\n"
    "call probe_start\n"
);
#elif defined(__aarch64__)
static long invoke(long number, long first, long second, long third, long fourth) {
    register long x8 __asm__("x8") = number;
    register long x0 __asm__("x0") = first;
    register long x1 __asm__("x1") = second;
    register long x2 __asm__("x2") = third;
    register long x3 __asm__("x3") = fourth;
    __asm__ volatile("svc 0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3) : "memory");
    return x0;
}
static long invoke5(long number, long first, long second, long third, long fourth, long fifth) {
    register long x8 __asm__("x8") = number;
    register long x0 __asm__("x0") = first;
    register long x1 __asm__("x1") = second;
    register long x2 __asm__("x2") = third;
    register long x3 __asm__("x3") = fourth;
    register long x4 __asm__("x4") = fifth;
    __asm__ volatile("svc 0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4)
                     : "memory");
    return x0;
}
#define SYS_EXIT 93
#define SYS_READ 63
#define SYS_WRITE 64
#define SYS_CLOSE 57
#define SYS_OPENAT 56
#define SYS_SOCKET 198
#define SYS_CLONE 220
#define SYS_CONNECT 203
#define SYS_BIND 200
#define SYS_EXECVE 221
#define SYS_GETPPID 173
#define SYS_UNLINKAT 35
#define SYS_LINKAT 37
#define SYS_RENAMEAT2 276
#define SYS_EXECVEAT 281
#define SYS_RT_SIGACTION 134
#define SYS_PPOLL 73
__asm__(
    ".global _start\n"
    ".type _start,%function\n"
    "_start:\n"
    "mov x0, sp\n"
    "bl probe_start\n"
);
#else
#error unsupported architecture
#endif

#define AT_FDCWD -100
#define AT_REMOVEDIR 512
#define O_RDONLY 0
#define O_WRONLY 1
#define O_CREAT 64
#define AF_INET 2
#define AF_INET6 10
#define SOCK_STREAM 1
#define AT_EMPTY_PATH 4096
#define SIGTERM 15
#define SIG_IGN 1

struct kernel_sigaction {
    unsigned long handler;
    unsigned long flags;
    unsigned long restorer;
    unsigned long mask;
};

__attribute__((noreturn)) static void terminate(long status) {
    invoke(SYS_EXIT, status, 0, 0, 0);
    __builtin_unreachable();
}

static int starts_with(const char *value, const char *prefix) {
    while (*prefix != 0) {
        if (*value != *prefix) {
            return 0;
        }
        ++value;
        ++prefix;
    }
    return 1;
}

__attribute__((noreturn, used)) void probe_start(long *initial_stack) {
#if PROBE_MODE == 1
    terminate(0);
#elif PROBE_MODE == 2
    invoke(SYS_SOCKET, AF_INET, SOCK_STREAM, 0, 0);
    terminate(91);
#elif PROBE_MODE == 3
    static const char path[] = "/etc/passwd";
    long result = invoke(SYS_OPENAT, AT_FDCWD, (long)path, O_RDONLY, 0);
    terminate(result == -13 ? 0 : 92);
#elif PROBE_MODE == 4
    for (;;) {
        __asm__ volatile("" ::: "memory");
    }
#elif PROBE_MODE == 5
    invoke(SYS_CLONE, 0, 0, 0, 0);
    terminate(93);
#elif PROBE_MODE == 6
    static const char path[] = "/tmp/chio-cage-forbidden-create";
    long result = invoke(SYS_OPENAT, AT_FDCWD, (long)path, O_WRONLY | O_CREAT, 0600);
    terminate(result == -13 ? 0 : 94);
#elif PROBE_MODE == 7
    static const char path[] = "/tmp/chio-cage-allowed-write";
    static const char byte[] = "x";
    long descriptor = invoke(SYS_OPENAT, AT_FDCWD, (long)path, O_WRONLY, 0);
    if (descriptor < 0) {
        terminate(95);
    }
    long written = invoke(SYS_WRITE, descriptor, (long)byte, 1, 0);
    terminate(written == 1 ? 0 : 96);
#elif PROBE_MODE == 8
    static const char path[] = "/tmp/chio-cage-allowed-read";
    char byte;
    long descriptor = invoke(SYS_OPENAT, AT_FDCWD, (long)path, O_RDONLY, 0);
    if (descriptor < 0) {
        terminate(97);
    }
    long count = invoke(SYS_READ, descriptor, (long)&byte, 1, 0);
    terminate(count == 1 ? 0 : 98);
#elif PROBE_MODE == 9
    static const char path[] = "/tmp/chio-cage-allowed-read";
    long result = invoke(SYS_OPENAT, AT_FDCWD, (long)path, O_RDONLY, 0);
    terminate(result == -13 ? 0 : 99);
#elif PROBE_MODE == 10
#ifndef PROBE_PATH
#error PROBE_PATH is required for mode 10
#endif
    static const char path[] = PROBE_PATH;
    static const char empty[] = "";
    static char argument[] = "reexec-probe";
    static char *arguments[] = {argument, 0};
    static char *environment[] = {0};
    long close_result = invoke(SYS_CLOSE, 255, 0, 0, 0);
    if (close_result == 0) {
        terminate(100);
    }
    if (close_result != -9) {
        terminate(101);
    }
    for (long attempt = 0; attempt < 400; ++attempt) {
        long descriptor = invoke(SYS_OPENAT, AT_FDCWD, (long)path, O_RDONLY, 0);
        if (descriptor == -24) {
            long result = invoke5(
                SYS_EXECVEAT,
                255,
                (long)empty,
                (long)arguments,
                (long)environment,
                AT_EMPTY_PATH
            );
            terminate(result == -9 ? 0 : 102);
        }
        if (descriptor < 0) {
            terminate(103);
        }
        if (descriptor == 255) {
            invoke5(
                SYS_EXECVEAT,
                255,
                (long)empty,
                (long)arguments,
                (long)environment,
                AT_EMPTY_PATH
            );
            terminate(104);
        }
    }
    terminate(105);
#elif PROBE_MODE == 11
    static const char expected[] = "cage-stdio-probe";
    char input[sizeof(expected) - 1];
    long count = invoke(SYS_READ, 0, (long)input, sizeof(input), 0);
    if (count != (long)sizeof(input)) {
        terminate(106);
    }
    for (long index = 0; index < (long)sizeof(input); ++index) {
        if (input[index] != expected[index]) {
            terminate(107);
        }
    }
    long written = invoke(SYS_WRITE, 1, (long)input, sizeof(input), 0);
    terminate(written == (long)sizeof(input) ? 0 : 108);
#elif PROBE_MODE == 12
    for (long descriptor = 3; descriptor <= 255; ++descriptor) {
        if (invoke(SYS_CLOSE, descriptor, 0, 0, 0) != -9) {
            terminate(109);
        }
    }
    terminate(0);
#elif PROBE_MODE == 13
    static const char path[] = "/tmp/chio-cage-forbidden-write-existing";
    long result = invoke(SYS_OPENAT, AT_FDCWD, (long)path, O_WRONLY, 0);
    terminate(result == -13 ? 0 : 110);
#elif PROBE_MODE == 14
    static const char path[] = "/tmp/chio-cage-forbidden-remove";
    invoke(SYS_UNLINKAT, AT_FDCWD, (long)path, 0, 0);
    terminate(111);
#elif PROBE_MODE == 15
    static const char old_path[] = "/tmp/chio-cage-forbidden-rename-source";
    static const char new_path[] = "/tmp/chio-cage-forbidden-rename-target";
    invoke5(SYS_RENAMEAT2, AT_FDCWD, (long)old_path, AT_FDCWD, (long)new_path, 0);
    terminate(112);
#elif PROBE_MODE == 16
    static const char old_path[] = "/tmp/chio-cage-forbidden-link-source";
    static const char new_path[] = "/tmp/chio-cage-forbidden-link-target";
    invoke5(SYS_LINKAT, AT_FDCWD, (long)old_path, AT_FDCWD, (long)new_path, 0);
    terminate(113);
#elif PROBE_MODE == 17
    static const char path[] = "/tmp/chio-cage-symlink-escape";
    long result = invoke(SYS_OPENAT, AT_FDCWD, (long)path, O_RDONLY, 0);
    terminate(result == -13 ? 0 : 114);
#elif PROBE_MODE == 18
    static const unsigned char address[] = {
        AF_INET, 0, 0, 80, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0
    };
    invoke(SYS_CONNECT, 0, (long)address, sizeof(address), 0);
    terminate(115);
#elif PROBE_MODE == 19
    static const unsigned char address[] = {
        AF_INET, 0, 0, 0, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0
    };
    invoke(SYS_BIND, 0, (long)address, sizeof(address), 0);
    terminate(116);
#elif PROBE_MODE == 20
    static const unsigned char address[] = {
        AF_INET6, 0, 0, 80, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    invoke(SYS_CONNECT, 0, (long)address, sizeof(address), 0);
    terminate(117);
#elif PROBE_MODE == 21
    static const unsigned char address[] = {
        AF_INET6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    invoke(SYS_BIND, 0, (long)address, sizeof(address), 0);
    terminate(118);
#elif PROBE_MODE == 22
    invoke(SYS_GETPPID, 0, 0, 0, 0);
    terminate(119);
#elif PROBE_MODE == 23
    long argument_count = initial_stack[0];
    const char **environment = (const char **)&initial_stack[argument_count + 2];
    static const char *forbidden[] = {
        "CHIO_CAGE_PARENT_SECRET=", "LD_PRELOAD=", "LD_LIBRARY_PATH=", "DYLD_",
        "PYTHONPATH=", "PYTHONSTARTUP=", "NODE_OPTIONS=", "RUBYOPT=", "PERL5OPT=",
        "BASH_ENV=", "ENV=", 0
    };
    for (; *environment != 0; ++environment) {
        for (long index = 0; forbidden[index] != 0; ++index) {
            if (starts_with(*environment, forbidden[index])) {
                terminate(120);
            }
        }
    }
    terminate(0);
#elif PROBE_MODE == 24
    static const char path[] = "/bin/true";
    static char argument[] = "/bin/true";
    static char *arguments[] = {argument, 0};
    static char *environment[] = {0};
    invoke(SYS_EXECVE, (long)path, (long)arguments, (long)environment, 0);
    terminate(121);
#elif PROBE_MODE == 25
    static const struct kernel_sigaction ignored = {SIG_IGN, 0, 0, 0};
    static const char ready[] = "r";
    long result = invoke(
        SYS_RT_SIGACTION,
        SIGTERM,
        (long)&ignored,
        0,
        sizeof(unsigned long)
    );
    if (result != 0) {
        terminate(122);
    }
    if (invoke(SYS_WRITE, 1, (long)ready, 1, 0) != 1) {
        terminate(123);
    }
    for (;;) {
        invoke5(SYS_PPOLL, 0, 0, 0, 0, 0);
    }
#elif PROBE_MODE == 26
    static const char path[] = "/tmp/chio-cage-allowed-directory/existing.data";
    char byte;
    long descriptor = invoke(SYS_OPENAT, AT_FDCWD, (long)path, O_RDONLY, 0);
    if (descriptor < 0) {
        terminate(126);
    }
    long count = invoke(SYS_READ, descriptor, (long)&byte, 1, 0);
    terminate(count == 1 ? 0 : 127);
#elif PROBE_MODE == 27
    static const char path[] = "/tmp/chio-cage-allowed-directory/late-forbidden-link";
    long result = invoke(SYS_OPENAT, AT_FDCWD, (long)path, O_RDONLY, 0);
    terminate(result == -13 ? 0 : 128);
#else
#error invalid probe mode
#endif
}
