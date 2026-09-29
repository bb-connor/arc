#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

static pthread_once_t initialized = PTHREAD_ONCE_INIT;
static int (*real_fsync)(int);
static int (*real_fdatasync)(int);
static long delay_ms;
static atomic_ulong fsync_calls;
static atomic_ulong fdatasync_calls;

static void initialize(void) {
    char *end = NULL;
    const char *configured = getenv("CHIO_DIAGNOSTIC_SYNC_DELAY_MS");
    delay_ms = configured ? strtol(configured, &end, 10) : -1;
    real_fsync = dlsym(RTLD_NEXT, "fsync");
    real_fdatasync = dlsym(RTLD_NEXT, "fdatasync");
    if (!configured || !*configured || !end || *end || delay_ms < 1 ||
        delay_ms > 1000 || !real_fsync || !real_fdatasync) {
        fputs("invalid slow-sync diagnostic configuration\n", stderr);
        _exit(127);
    }
}

static void delay(void) {
    pthread_once(&initialized, initialize);
    struct timespec remaining = {.tv_sec = delay_ms / 1000,
                                .tv_nsec = (delay_ms % 1000) * 1000000};
    while (nanosleep(&remaining, &remaining) != 0 && errno == EINTR) {}
}

int fsync(int fd) {
    delay();
    atomic_fetch_add(&fsync_calls, 1);
    return real_fsync(fd);
}

int fdatasync(int fd) {
    delay();
    atomic_fetch_add(&fdatasync_calls, 1);
    return real_fdatasync(fd);
}

__attribute__((destructor)) static void report(void) {
    fprintf(stderr, "[slow-sync] delay_ms=%ld fsync=%lu fdatasync=%lu\n",
            delay_ms, atomic_load(&fsync_calls), atomic_load(&fdatasync_calls));
}
