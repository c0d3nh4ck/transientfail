#define _GNU_SOURCE
#include <dlfcn.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "libtrap.h"

#ifdef __x86_64__
#define INSTPTR REG_RIP
#define STACKPTR REG_RSP
#else
#define INSTPTR REG_EIP
#define STACKPTR REG_ESP
#endif

static void child_process(ucontext_t *uc, void *faulting_address, uintptr_t ip) {

    printf("[+]  In the child process!\n");

}


// Original signal / sigaction
static sighandler_t (*orig_signal)(int, sighandler_t) = NULL;
static int (*orig_sigaction)(int, const struct sigaction *, struct sigaction *) = NULL;

// fault handler for SIGTRAP 
static void sigtrap_fault_handler(int signum, siginfo_t *info, void *context) {

    pid_t child_pid;
    void *faulting_address = info->si_addr;
    ucontext_t *uc = context;
    uintptr_t ip = uc->uc_mcontext.gregs[INSTPTR];

    child_pid = fork();

    // child thread 
    if (!child_pid) {
        child_process(uc, faulting_address, ip);
        return;
    }

    // parent regular execution continues
    printf("[+] forked child process, now in parent thread!\n");
}



__attribute__((constructor))
void initialize_trap(void) {

    struct sigaction sa_sigtrap;

    // Hook signal and sigaction
    orig_signal = dlsym(RTLD_NEXT, "signal");
    if (orig_signal == signal)
        orig_signal = NULL;
    orig_sigaction = dlsym(RTLD_NEXT, "sigaction");
    if (orig_sigaction == sigaction)
        orig_sigaction = NULL;

    // Register signal handler
    memset(&sa_sigtrap, 0, sizeof(sa_sigtrap));
    sa_sigtrap.sa_sigaction = sigtrap_fault_handler;
    sa_sigtrap.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESTART;
    sigemptyset(&sa_sigtrap.sa_mask);

    sigaction_raw(SIGTRAP, &sa_sigtrap, NULL);
}