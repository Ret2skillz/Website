+++
title = 'Linux Kernel PoC (CVE-2025-39946)'
date = 2026-02-14T12:51:42+01:00
tags = ["pwn", "exploit", "CVE", "PoC", "Kernel"]
categories = ["Exploit"]
+++

It's been a long time since I made a post on this blog. In the fall of 2025 after completing the three stars challenges on hackropole, I took a bit of a break from doing any challenges. Now in 2026 I decided to go full tryhard mode again. Amongst my different goals are hitting 100% on the app-system (pwn) category on root-me (and maybe HacktheBox too). But more importantly I will start seriously focusing on CTFs and real life binary exploitation.

For this I decided to do two things :
1. Audit C/C++ code on github.
2. Look at recent CVEs, mostly starting with Linux Kernel.

This is my first entry of articles exploring a recent vulnerability on the linux kernel.

# TLDR
1. [Introduction](#introduction)
2. [Debug Environnement](#debug-environnement)
3. [The Commit](#the-commit)
4. [Understanding the vulnerability](#understanding-the-vulnerability)
    1. [Integer Overflow](#integer-overflow) 
    2. [Out of Bounds write](#out-of-bounds-write)
5. [First Exploit](#leak-with-integer-overflow)
6. [Final exploit strategy](#out-of-bounds-write)
7. [Conclusion](#conclusion)

## Introduction

To better find Linux Kernel recent CVEs I decided to look at kCTF, the CTF of google about kernel exploitation.

You can find their sheet of recent entries [here](https://docs.google.com/spreadsheets/d/e/2PACX-1vS1REdTA29OJftst8xN5B5x8iIUcxuK6bXdzF8G1UXCmRtoNsoQ9MbebdRdFnj6qZ0Yd7LwQfvYC2oF/pubhtml#gid=2095368189)

The kCTF is interesting because :
1. There's a whole bunch of vulnerabilities to pick at the same place with their displayed commit.
2. There's a captured flag time, this is supposed to show exploitation, so normally you can see vulnerabilities that are exploitable and not just crashes.

For my first Kernel CVE, I chose to find an article already exploring the same CVE so I could go back to the article if I was stuck. I found the following [article](https://faith2dxy.xyz/2025-10-02/kCTF-TLS-nday-analysis/) (the whole blogis amazing!) about **CVE-2025-39946**.

## Debug Environnement

First of all before we can do anything, we need to have a good setup to debug the kernel. As the article didn't detail any steps I had to google them myself so I thought it would be a good idea to detail them more in this article.
Note that you should have **qemu-system** installed.

The first step is to fetch the kernel source from [kernel.org](https://kernel.org), for this CVE we need version **6.12.48** you can fetch it from this specific [link](wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.12.48.tar.xz), you can just extract the archive to get the code.

Then we need to compile the kernel with debug options. You can use following commands
```bash
cd linux-6.12.48

# Start with default config
make defconfig

# Open menuconfig
make menuconfig
```
Or after the **make defconfig** you can edit the **.config** file. The only important options are : **CONFIG_TLS=y** since it's important for the vulnerability. You can then add debug options like : 

    CONFIG_DEBUG_INFO=y

    CONFIG_DEBUG_KERNEL=y

    CONFIG_KGDB=y

    CONFIG_KGDB_SERIAL_CONSOLE=y

    CONFIG_FRAME_POINTER=y

Then compile it
```bash
make -j$(nproc)
# Results: arch/x86/boot/bzImage and vmlinux

#vmlinux will be the file we debug
```

The next steps is to compile utility files
```bash
cd ~/kernel-research
wget https://busybox.net/downloads/busybox-1.36.1.tar.bz2
tar -xf busybox-1.36.1.tar.bz2
cd busybox-1.36.1

make defconfig
make menuconfig

# In menuconfig enable:
# - Settings → [*] Build static binary (no shared libs)
# Save and exit

# ============================================
# 4. BUSYBOX - Compile
# ============================================
make -j$(nproc)
make install

# Results: _install/ directory with all utilities
```
Then creating the initramfs directory, with the init file for the kernel (note the importance of adding connection in the init).
```bash
cd ~/kernel-research
mkdir -p initramfs
cd initramfs

# Copy BusyBox
cp -r ../busybox-1.36.1/_install/* .

# Create directories
mkdir -p dev proc sys tmp etc

# Create init script with networking
cat > init << 'EOF'
#!/bin/sh

mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev

ifconfig lo 127.0.0.1 up
ifconfig eth0 up
udhcpc -i eth0

echo "Kernel debugging environment ready"
echo "Run your exploit with: /exploit"

exec /bin/sh
EOF

chmod +x init
```
Finally you can create a simple **make.sh** script for building your exploit
```bash
#!/bin/bash
# Compile your exploit statically
gcc -static -o initramfs/exploit exploit.c
echo "Exploit compiled and placed in initramfs/"
```
A **pack.sh** to pack the whole initramfs into a .tgz file
```bash
#!/bin/bash
cd initramfs
find . -print0 | cpio --null -ov -H newc | gzip -9 > ../initramfs.tgz
cd ..
echo "Initramfs packed successfully"
```
Finally the final **run.sh** to run the two script and the qemu-system command. The only option I added on qemu is kernel rebooting after panic to make it more convenient. The last option **-s -S** is so we can debug it.
```bash
#!/bin/bash

# Pack initramfs
./make.sh
./pack.sh

# Run QEMU
qemu-system-x86_64 \
    -enable-kvm \
    -cpu host \
    -smp 1 \
    -kernel ./bzImage \
    -initrd ./initramfs.tgz \
    -nographic \
    -append "console=ttyS0 oops=panic panic=1 panic_on_oops=1 nokaslr quiet" -m 512M \
    -netdev user,id=mynet0 \
    -device virtio-net-pci,netdev=mynet0 \
    -s -S
```
After launching everything you can run **gdb ./vmlinux**, and attach to the kernel with **target remote :1234**. I use as always gef, with the bata24 variant that has lot of useful kernel commands.

Now finally we can start analysing the actual vulnerability 

## The Commit

You can find the commit [here](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=0aeb54ac4cd5cf8f60131b4d9ec0b6dc9c27b20d)
```
tls: make sure to abort the stream if headers are bogus
Normally we wait for the socket to buffer up the whole record
before we service it. If the socket has a tiny buffer, however,
we read out the data sooner, to prevent connection stalls.
Make sure that we abort the connection when we find out late
that the record is actually invalid. Retrying the parsing is
fine in itself but since we copy some more data each time
before we parse we can overflow the allocated skb space.

Constructing a scenario in which we're under pressure without
enough data in the socket to parse the length upfront is quite
hard. syzbot figured out a way to do this by serving us the header
in small OOB sends, and then filling in the recvbuf with a large
normal send.

Make sure that tls_rx_msg_size() aborts strp, if we reach
an invalid record there's really no way to recover.

Reported-by: Lee Jones <lee@kernel.org>
Fixes: 84c61fe1a75b ("tls: rx: do not use the standard strparser")
Reviewed-by: Sabrina Dubroca <sd@queasysnail.net>
Signed-off-by: Jakub Kicinski <kuba@kernel.org>
Link: https://patch.msgid.link/20250917002814.1743558-1-kuba@kernel.org
Signed-off-by: Paolo Abeni <pabeni@redhat.com>
```
## Understanding the vulnerability

