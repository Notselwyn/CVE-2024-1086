// This program, and the other programs and scripts ("programs", "these programs") in this software directory/folder/repository ("repository") are published, developed and distributed for educational/research purposes only. I ("the creator") do not condone any malicious or illegal usage of these programs, as the intend is sharing research and not doing illegal activities with it. I am not legally responsible for anything you do with these programs.

#ifndef NET_H
#define NET_H

void send_ipv4_udp(const char* buf, size_t buflen);
void recv_ipv4_udp();
void send_ipv4_tcp(const char* buf, size_t buflen);
void recv_ipv4_tcp();
void send_ipv4_ip_hdr(const char* buf, size_t buflen, struct ip *ip_header);
void populate_sockets();

#endif
