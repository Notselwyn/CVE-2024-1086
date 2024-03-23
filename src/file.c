// This program, and the other programs and scripts ("programs", "these programs") in this software directory/folder/repository ("repository") are published, developed and distributed for educational/research purposes only. I ("the creator") do not condone any malicious or illegal usage of these programs, as the intend is sharing research and not doing illegal activities with it. I am not legally responsible for anything you do with these programs.

#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include "file.h"

// micro function (don't print "doing X..." status)
// removes error checking boilerplate
void write_file(const char *filename, const char *buf, size_t buflen, unsigned int flags)
{
    int fd;

    fd = open(filename, O_WRONLY | O_CREAT | flags, 0755);
    if (fd < 0)
    {
        perror("open$write_file");
        exit(EXIT_FAILURE);
    }

    if (write(fd, buf, buflen) != buflen)
    {
        perror("write$write_file");
        exit(EXIT_FAILURE);
    }

    close(fd);
}


int read_file(const char *filename, void *buf, size_t buflen)
{
    int fd;
    int retv;

    fd = open(filename, O_RDONLY);
    if (fd < 0)
    {
        perror("open$read_file");
        exit(EXIT_FAILURE);
    }

    retv = read(fd, buf, buflen);
    if (retv < 0)
    {
        perror("read$read_file");
        exit(EXIT_FAILURE);
    }

    close(fd);

    return retv;
}