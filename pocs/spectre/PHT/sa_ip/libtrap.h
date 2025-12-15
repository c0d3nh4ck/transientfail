#ifndef CRUCIBLE_INTERNAL_H
#define CRUCIBLE_INTERNAL_H

#define _GNU_SOURCE
#include <ucontext.h>
#include <signal.h>

sighandler_t signal_raw (int signum, sighandler_t handler);
int sigaction_raw(int sig, const struct sigaction *restrict sa, struct sigaction *restrict old);

#endif