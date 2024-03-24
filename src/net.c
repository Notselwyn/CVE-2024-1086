// This program, and the other programs and scripts ("programs", "these programs") in this software directory/folder/repository ("repository") are published, developed and distributed for educational/research purposes only. I ("the creator") do not condone any malicious or illegal usage of these programs, as the intend is sharing research and not doing illegal activities with it. I am not legally responsible for anything you do with these programs.

#include <netinet/ip.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <fcntl.h>


#include "net.h"
#include "env.h"

static char intermed_buf[1 << 19]; // simply pre-allocate intermediate buffers

static int sendto_ipv4_ip_sockfd;
static int sendto_ipv4_udp_client_sockfd;
static int sendto_ipv4_udp_server_sockfd;
static int sendto_ipv4_tcp_client_sockfd;
static int sendto_ipv4_tcp_server_sockfd;
static int sendto_ipv4_tcp_server_connection_sockfd;

static void sendto_noconn(struct sockaddr_in *addr, const char* buf, size_t buflen, int sockfd)
{
    PRINTF_VERBOSE("[*] doing sendto...\n");
	if (sendto(sockfd, buf, buflen, 0, (struct sockaddr*)addr, sizeof(*addr)) == -1) {
		perror("sendto");
		exit(EXIT_FAILURE);
	}
}

// code from https://android.googlesource.com/platform/system/core/+/refs/heads/main/libnetutils/packet.c#62
static uint32_t ip_checksum(void *buffer, unsigned int count, uint32_t startsum)
{
    uint16_t *up = (uint16_t *)buffer;
    uint32_t sum = startsum;
    uint32_t upper16;

    while (count > 1) {
        sum += *up++;
        count -= 2;
    }
    
    if (count > 0)
        sum += (uint16_t) *(uint8_t *)up;
    
    while ((upper16 = (sum >> 16)) != 0)
        sum = (sum & 0xffff) + upper16;

    return sum;
}

static inline uint32_t ip_finish_sum(uint32_t sum)
{
    return ~sum & 0xffff;
}

void send_ipv4_ip_hdr(const char* buf, size_t buflen, struct ip *ip_header)
{
	size_t ip_buflen = sizeof(struct ip) + buflen;
    struct sockaddr_in dst_addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr =  inet_addr("127.0.0.2")  // 127.0.0.1 will not be ipfrag_time'd
	};

    memcpy(intermed_buf, ip_header, sizeof(*ip_header));
	memcpy(&intermed_buf[sizeof(*ip_header)], buf, buflen);

	// checksum needds to be 0 before
	((struct ip*)intermed_buf)->ip_sum = 0;
	((struct ip*)intermed_buf)->ip_sum = ip_finish_sum(ip_checksum(intermed_buf, ip_buflen, 0));

	PRINTF_VERBOSE("[*] sending IP packet (%ld bytes)...\n", ip_buflen);

	sendto_noconn(&dst_addr, intermed_buf, ip_buflen, sendto_ipv4_ip_sockfd);
}

void send_ipv4_udp(const char* buf, size_t buflen)
{
    struct sockaddr_in dst_addr = {
		.sin_family = AF_INET,
        .sin_port = htons(45173),
		.sin_addr.s_addr = inet_addr("127.0.0.1")
	};

	sendto_noconn(&dst_addr, buf, buflen, sendto_ipv4_udp_client_sockfd);
}

void send_ipv4_tcp(const char* buf, size_t buflen)
{
	send(sendto_ipv4_tcp_client_sockfd, buf, buflen, 0);
}

void recv_ipv4_udp(int content_len)
{
    PRINTF_VERBOSE("[*] doing udp recv...\n");
    recv(sendto_ipv4_udp_server_sockfd, intermed_buf, content_len, 0);

	PRINTF_VERBOSE("[*] udp packet preview: %02hhx\n", intermed_buf[0]);
}

void recv_ipv4_tcp()
{
    PRINTF_VERBOSE("[*] doing tcp recv...\n");
    recv(sendto_ipv4_tcp_server_connection_sockfd, intermed_buf, sizeof(intermed_buf), 0);
}

int get_udp_server_sockfd(short port)
{
    int sockfd;
    struct sockaddr_in server_addr = {
		.sin_family = AF_INET,
        .sin_port = htons(port),
		.sin_addr.s_addr = inet_addr("127.0.0.1")
	};

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("socket$server");
        exit(EXIT_FAILURE);
    }

    if (bind(sockfd, (const struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("bind$server");
        exit(EXIT_FAILURE);
    }

    return sockfd;
}

int get_tcp_server_sockfd(short port)
{
    int sockfd;
    struct sockaddr_in server_addr = {
		.sin_family = AF_INET,
        .sin_port = htons(port),
		.sin_addr.s_addr = inet_addr("127.0.0.1")
	};

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket$tcp_server");
        exit(EXIT_FAILURE);
    }

    if (bind(sockfd, (const struct sockaddr *)&server_addr, sizeof(server_addr)) != 0) {
        perror("bind$tcp_server");
        exit(EXIT_FAILURE);
    }

    // allow N requests to be buffered
    if ((listen(sockfd, 99)) != 0) { 
        printf("listen$tcp_server\n"); 
        exit(EXIT_FAILURE); 
    }

    return sockfd;
}

void populate_sockets()
{
    struct sockaddr_in tcp_dst_addr = {
		.sin_family = AF_INET,
        .sin_port = htons(45174),
		.sin_addr.s_addr = inet_addr("127.0.0.1")
	};

	memset(intermed_buf, '\x00', sizeof(intermed_buf));

    sendto_ipv4_ip_sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sendto_ipv4_ip_sockfd == -1) {
        perror("socket$ip");
        exit(EXIT_FAILURE);
    }

    sendto_ipv4_udp_client_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sendto_ipv4_udp_client_sockfd == -1) {
        perror("socket$udp");
        exit(EXIT_FAILURE);
    }

    sendto_ipv4_tcp_client_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sendto_ipv4_tcp_client_sockfd == -1) {
        perror("socket$tcp");
        exit(EXIT_FAILURE);
    }
    
    sendto_ipv4_udp_server_sockfd = get_udp_server_sockfd(45173);
    sendto_ipv4_tcp_server_sockfd = get_tcp_server_sockfd(45174);

    connect(sendto_ipv4_tcp_client_sockfd, (struct sockaddr*)&tcp_dst_addr, sizeof(tcp_dst_addr));
    sendto_ipv4_tcp_server_connection_sockfd = accept(sendto_ipv4_tcp_server_sockfd, NULL, NULL);
}