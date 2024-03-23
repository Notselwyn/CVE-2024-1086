// This program, and the other programs and scripts ("programs", "these programs") in this software directory/folder/repository ("repository") are published, developed and distributed for educational/research purposes only. I ("the creator") do not condone any malicious or illegal usage of these programs, as the intend is sharing research and not doing illegal activities with it. I am not legally responsible for anything you do with these programs.

#ifndef ENV_H
#define ENV_H

#include "config.h"

void setup_env();

#if CONFIG_VERBOSE_
#define PRINTF_VERBOSE(...) printf(__VA_ARGS__)
#else
#define PRINTF_VERBOSE(...)
#endif

void setup_log(const char *name);

#endif