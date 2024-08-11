#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <ctime>
#include <array>
#include <vector>
#include <mutex>
#include <unistd.h>
#include <semaphore.h>
#include <signal.h>
#include <link.h>
#include <fcntl.h>
#include "index_allocator.h"

#define KERN_INVALID_ARGUMENT 4

extern "C" {

typedef void* task_t;
typedef uint32_t mach_port_t;
typedef mach_port_t semaphore_t;


task_t* mach_task_self_;
void* mach_host_self() {
    return nullptr;
}

#define REALTIME_CLOCK		0
#define CALENDAR_CLOCK		1
#define HIGHRES_CLOCK		2
struct mach_timespec {
    int tv_nsec;
    unsigned int tv_sec;
};
int host_get_clock_service(void* host, int clockId, mach_port_t* serv) {
    switch (clockId) {
        case REALTIME_CLOCK:
            *serv = (mach_port_t) CLOCK_MONOTONIC;
            return 0;
        case CALENDAR_CLOCK:
            *serv = (mach_port_t) CLOCK_REALTIME;
            return 0;
        case HIGHRES_CLOCK:
            *serv = (mach_port_t) CLOCK_MONOTONIC;
            return 0;
        default:
            return KERN_INVALID_ARGUMENT;
    }
}
int clock_get_time(mach_port_t serv, struct mach_timespec* ret) {
    int clock = (int) serv;
    struct timespec ts {};
    clock_gettime(clock, &ts);
    ret->tv_sec = ts.tv_sec;
    ret->tv_nsec = ts.tv_nsec;
    return 0;
}

void _NSGetEnviron() {
    abort();
}

int _NSGetExecutablePath(char* buf, uint32_t* bufsize) {
    auto ret = readlink("/proc/self/exe", buf, *bufsize);
    if (ret < 0 || ret >= *bufsize) {
        fprintf(stderr, "failed to read /proc/self/exe\n");
        abort();
    }
    buf[ret] = 0;
    *bufsize = ret;
    return 0;
}

void _ZNKSt3__120__vector_base_commonILb1EE20__throw_length_errorEv() {
    std::__throw_length_error("vector");
}

void posix_spawnattr_setbinpref_np() {
}

void select$1050() {
    abort();
}


typedef uint32_t darwin_sigset_t;

struct darwin_sigaction {
    void (*sa_handler_)(int);
    darwin_sigset_t sa_mask;
    int sa_flags;
};

static int darwin_sa_flags_to_host(int flags) {
    int host = 0;
    if (flags & 1) host |= SA_ONSTACK;
    if (flags & 2) host |= SA_RESTART;
    if (flags & 4) host |= SA_RESETHAND;
    if (flags & 8) host |= SA_NOCLDSTOP;
    if (flags & 0x10) host |= SA_NODEFER;
    if (flags & 0x20) host |= SA_NOCLDWAIT;
    if (flags & 0x40) host |= SA_SIGINFO;
//    if (flags & 0x100) host |= SA_USERTRAMP;
//    if (flags & 0x200) host |= SA_64REGSET;
    return host;
}
static int darwin_sa_flags_from_host(int host) {
    int flags = 0;
    if (host & SA_ONSTACK) flags |= 1;
    if (host & SA_RESTART) flags |= 2;
    if (host & SA_RESETHAND) flags |= 4;
    if (host & SA_NOCLDSTOP) flags |= 8;
    if (host & SA_NODEFER) flags |= 0x10;
    if (host & SA_NOCLDWAIT) flags |= 0x20;
    if (host & SA_SIGINFO) flags |= 0x40;
//    if (host & SA_USERTRAMP) flags |= 0x100;
//    if (host & SA_64REGSET) flags |= 0x200;
    return flags;
}

int darwin_sigaction(int sig, const struct darwin_sigaction* action, struct darwin_sigaction* original) {
    struct sigaction host_action {};
    struct sigaction host_original {};

    host_action.sa_handler = action->sa_handler_;
    host_action.sa_mask.__val[0] = action->sa_mask;
    host_action.sa_flags = darwin_sa_flags_to_host(action->sa_flags);

    int ret = sigaction(sig, &host_action, &host_original);
    if (ret)
        return ret;

    if (original) {
        original->sa_handler_ = host_original.sa_handler;
        original->sa_mask = host_original.sa_mask.__val[0];
        original->sa_flags = darwin_sa_flags_from_host(host_original.sa_flags);
    }

    return 0;
}


static IndexAllocator<sem_t> semaphores;
static std::mutex semaphoresMutex;

int semaphore_create(task_t task, semaphore_t* semaphore, int policy, int value) {
    std::lock_guard guard(semaphoresMutex);
    auto ret = semaphores.allocate();
    sem_init(&semaphores.get(ret), 0, value);
    *semaphore = ret;
    return 0;
}
int semaphore_destroy(task_t task, semaphore_t semaphore) {
    std::lock_guard guard(semaphoresMutex);
    sem_destroy(&semaphores.get(semaphore));
    semaphores.free(semaphore);
    return 0;
}
int semaphore_signal(semaphore_t semaphore) {
    sem_post(&semaphores.get(semaphore));
    return 0;
}
int semaphore_timedwait(semaphore_t semaphore, mach_timespec wait_time) {
    struct timespec host_wait_time { wait_time.tv_sec, wait_time.tv_nsec };
    int ret = sem_timedwait(&semaphores.get(semaphore), &host_wait_time);
    return ret; // TODO: translate!!
}
int semaphore_wait(semaphore_t semaphore) {
    int ret = sem_wait(&semaphores.get(semaphore));
    return ret; // TODO: translate!!
}

bool _ZN2QT30qt_mac_applicationIsInDarkModeEv() {
    return false;
}
void _ZN2QT5QMenu13setAsDockMenuEv() {
}

static_assert(sizeof(pthread_t) <= 8);
static_assert(sizeof(pthread_attr_t) <= 56);
static_assert(sizeof(pthread_mutexattr_t) <= 8);
static_assert(sizeof(pthread_mutex_t) <= 56);


void* objc_msgSend() {
    return NULL;
}
void* objc_alloc() {
    return NULL;
}
void objc_release() {
}
void* OBJC_CLASS_$_NSBundle;
void* NSApp;
void* OBJC_CLASS_$_NSMenuItem;
void* OBJC_CLASS_$_NSRunningApplication;

void NSRunCriticalAlertPanel() {
    abort();
}

void memset_pattern16(void *b, const void *pattern16, size_t len) {
    __int128_t v = *(__int128_t*) pattern16;
    auto target = (__int128_t*)b;
    auto end =  (__int128_t*)((uintptr_t)b+(len&~0xfLLu));
    for ( ; target < end; target++)
        *target = v;
    int finalLen = len & 0xf;
    for (int i = 0; i < finalLen; i++)
        ((uint8_t*)end)[i] = ((uint8_t*)&v)[i];
}

void* darwin_dlopen(const char* path, int mode) {
    printf("dlopen: %s\n", path);
    int host_mode = 0;
    if (mode & 1) host_mode |= RTLD_LAZY;
    if (mode & 2) host_mode |= RTLD_NOW;
    if (mode & 4) host_mode |= RTLD_LOCAL;
    if (mode & 8) host_mode |= RTLD_GLOBAL;
    if (mode & 0x10) host_mode |= RTLD_NOLOAD;
    if (mode & 0x80) host_mode |= RTLD_NODELETE;
    return dlopen(path, host_mode);
}

}