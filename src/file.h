// This program, and the other programs and scripts ("programs", "these programs") in this software directory/folder/repository ("repository") are published, developed and distributed for educational/research purposes only. I ("the creator") do not condone any malicious or illegal usage of these programs, as the intend is sharing research and not doing illegal activities with it. I am not legally responsible for anything you do with these programs.

#ifndef FILE_H
#define FILE_H

#include <stddef.h>

#define WRITE_FILE_STR(filename, buf) write_file(filename, buf, strlen(buf))

int read_file(const char *filename, void *buf, size_t buflen);
void write_file(const char *filename, const char *buf, size_t buflen, unsigned int flags);

#endif