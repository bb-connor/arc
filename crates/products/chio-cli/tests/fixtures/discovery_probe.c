// Freestanding x86_64 MCP discovery peer. Every operation crosses the real cage.
#if !defined(__x86_64__)
#error native discovery qualification requires x86_64
#endif
static long call(long n, long a, long b, long c, long d) {
    long result;
    register long r10 __asm__("r10") = d;
    __asm__ volatile("syscall" : "=a"(result) : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10) : "rcx", "r11", "memory");
    return result;
}
static void stop(long code) { call(60, code, 0, 0, 0); for (;;) {} }
static void send(const char *s) {
    long length = 0;
    while (s[length]) ++length;
    while (length) { long n = call(1, 1, (long)s, length, 0); if (n <= 0) stop(91); s += n; length -= n; }
}
static void line(void) {
    char byte;
    do { if (call(0, 0, (long)&byte, 1, 0) != 1) stop(92); } while (byte != '\n');
}
static void mark(const char *path, const char *value, long length) {
    long fd = call(257, -100, (long)path, 1, 0);
    if (fd < 0 || call(1, fd, (long)value, length, 0) != length) stop(99);
    call(3, fd, 0, 0, 0);
}
void probe_start(long *stack) {
    if (stack[0] != 5) stop(93);
    const char **args = (const char **)&stack[1];
    long marker = call(257, -100, (long)args[1], 1, 0);
    if (marker < 0) stop(94);
    long pid = call(39, 0, 0, 0, 0);
    char digits[24]; long cursor = sizeof(digits);
    do { digits[--cursor] = '0' + pid % 10; pid /= 10; } while (pid);
    if (call(1, marker, (long)(digits + cursor), sizeof(digits) - cursor, 0) <= 0) stop(95);
    call(3, marker, 0, 0, 0);
    // Parent inspects actual UID/GID before releasing the process.
    long gate = call(257, -100, (long)args[3], 0, 0);
    if (gate < 0) stop(96);
    char ready;
    while (call(0, gate, (long)&ready, 1, 0) == 0) {
        struct { long seconds, nanos; } delay = {0, 1000000};
        call(271, 0, 0, (long)&delay, 0);
    }
    call(3, gate, 0, 0, 0);
    // This world-readable host canary is deliberately outside the manifest grants.
    if (call(257, -100, (long)args[2], 0, 0) != -13) stop(97);
    mark(args[1], "filesystem-denied", 17);
    if (args[4][0] == 'd' || args[4][0] == 'c') {
        // F_DUPFD and clearing FD_CLOEXEC must remain SIGSYS, not error returns.
        call(72, 1, args[4][0] == 'd' ? 0 : 2, 0, 0);
        mark(args[1], "fcntl-syscall-returned", 22);
        stop(98);
    }
    if (args[4][0] == 'f') {
        call(56, 17, 0, 0, 0);
        // Any return, including a refused clone without SIGSYS, fails the oracle.
        mark(args[1], "clone-syscall-returned", 22);
        stop(98);
    }
    if (args[4][0] == 's') {
        struct { long handler, flags, restorer, mask; } ignore = {1, 0, 0, 0};
        call(13, 15, (long)&ignore, 0, 8);
        for (;;) { call(271, 0, 0, 0, 0); }
    }
    // Both signed fcntl alternatives must work on the actual kernel filter.
    if (call(72, 1, 1, 0, 0) < 0 || call(72, 1, 2, 1, 0) != 0) stop(100);
    line();
    send("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"serverInfo\":{\"name\":\"confined\",\"version\":\"1\"}}}\n");
    line(); line();
    send("{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\"confined_probe\",\"inputSchema\":{\"type\":\"object\"},\"annotations\":{\"readOnlyHint\":true}}]}}\n");
    for (;;) { call(271, 0, 0, 0, 0); }
}
__asm__(".global _start\n.type _start,@function\n_start:\nmov %rsp,%rdi\nandq $-16,%rsp\ncall probe_start\n");
