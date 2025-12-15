/**
 * Adapted from MUSL implementation of sigaction for x86_64
 */

#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sched.h>
#include <signal.h>
#include <ucontext.h>
#include <errno.h>
#include <syscall.h>

#define SA_RESTORER   0x04000000

struct k_sigaction {
    void (*handler)(int);

    unsigned long flags;
#ifdef SA_RESTORER
    void (*restorer)(void);
#endif
    unsigned mask[2];
#ifndef SA_RESTORER
    void *unused;
#endif
};

static int unmask_done = 0;
static unsigned long handler_set[_NSIG / (8 * sizeof(long))];
#define SIGPT_SET \
((sigset_t *)(const unsigned long [_NSIG/8/sizeof(long)]){ \
[sizeof(long)==4] = 3UL<<(32*(sizeof(long)>4)) })
void __restore_rt();
#define __restore __restore_rt
volatile int __eintr_valid_flag;
asm (
    ".global __restore_rt\n"
    ".hidden __restore_rt\n"
    ".type __restore_rt,@function\n"
    "__restore_rt:\n"
    "mov $15, %rax\n"
    "syscall\n"
    ".size __restore_rt,.-__restore_rt"
);

static inline int a_cas(volatile int *p, int t, int s) {
    __asm__ __volatile__ (
        "lock ; cmpxchg %3, %1"
        : "=a"(t), "=m"(*p) : "a"(t), "r"(s) : "memory" );
    return t;
}

static inline int a_fetch_or(volatile int *p, int v) {
    int old;
    do old = *p;
    while (a_cas(p, old, old | v) != old);
    return old;
}

static inline void a_or(volatile int *p, int v) {
    a_fetch_or(p, v);
}

static inline void a_or_64(volatile uint64_t *p, uint64_t v) {
    union {
        uint64_t v;
        uint32_t r[2];
    } u = {v};
    if (u.r[0]) a_or((int *) p, u.r[0]);
    if (u.r[1]) a_or((int *) p + 1, u.r[1]);
}

static inline void a_or_l(volatile void *p, long v) {
    if (sizeof(long) == sizeof(int)) a_or(p, v);
    else a_or_64(p, v);
}

static inline void a_store(volatile int *p, int x) {
    __asm__ __volatile__(
        "mov %1, %0 ; lock ; orl $0,(%%rsp)"
        : "=m"(*p) : "r"(x) : "memory" );
}


int sigaction_raw(int sig, const struct sigaction *restrict sa, struct sigaction *restrict old) {
    struct k_sigaction ksa, ksa_old;
    int r;

    if (sa) {
        if ((uintptr_t) sa->sa_handler > 1ul) {
            a_or_l(handler_set + (sig - 1) / (8 * sizeof(long)),
                   1l << (sig - 1) % (8 * sizeof(long)));

            /* If pthread_create has not yet been called,
             * implementation-internal signals might not
             * yet have been unblocked. They must be
             * unblocked before any signal handler is
             * installed, so that an application cannot
             * receive an illegal sigset_t (with them
             * blocked) as part of the ucontext_t passed
             * to the signal handler. */
            if (!unmask_done) {
                syscall(SYS_rt_sigprocmask, SIG_UNBLOCK,
                        SIGPT_SET, 0, _NSIG / 8);
                unmask_done = 1;
            }

            if (!(sa->sa_flags & SA_RESTART)) {
                a_store(&__eintr_valid_flag, 1);
            }
        }
        ksa.handler = sa->sa_handler;
        ksa.flags = sa->sa_flags;
#ifdef SA_RESTORER
        ksa.flags |= SA_RESTORER;
        ksa.restorer = (sa->sa_flags & SA_SIGINFO) ? __restore_rt : __restore;
#endif
        memcpy(&ksa.mask, &sa->sa_mask, _NSIG / 8);
    }

    r = (int) syscall(SYS_rt_sigaction, sig, sa ? &ksa : 0, old ? &ksa_old : 0, _NSIG / 8);
    if (old && !r) {
        old->sa_handler = ksa_old.handler;
        old->sa_flags = (int) ksa_old.flags;
        memcpy(&old->sa_mask, &ksa_old.mask, _NSIG / 8);
    }
    return r;
}

sighandler_t signal_raw(int signum, sighandler_t handler) {
    struct sigaction sa_old, sa = {.sa_handler = handler, .sa_flags = SA_RESTART | SA_ONSTACK};

    errno = 0;
    sigaction_raw(signum, &sa, &sa_old);
    if (errno)
        return SIG_ERR;

    return sa_old.sa_handler;
}
