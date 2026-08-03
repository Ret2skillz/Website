+++
title = 'FCSC 2026 Boring'
date = 2026-08-02T10:24:02+02:00
tags = ["pwn", "Sandbox"]
categories = ["Hackropole"]
+++

**Challenge Name : Not So Boring**  
**Difficulty : ★★★**  
**Number of solves : 7**

This post is in my series of writeup on FCSC 2026, since it's been long since I did the competition I restarted doing the challenges recently, as well as the 2 I didn't solve during the competition.  
Not So Boring was a 3 Star challenge and the least solved challenge of this year.  
You can find the files of the challenge [here](https://github.com/Ret2skillz/CTFs/blob/main/FCSC2026/NotSoBoring/). Note that I changed the local getflag so that it reads the flag.txt in current directory instead of /flag.txt, on the docker-compose.yml it reads the right flag.

## TLDR ##
- The challenge reimplements the Boring challenge but with adding a sandbox
- The sandbox acts as an IPC with a parent supervising the child and polling for events and a shared memory
- There is a seccomp, hook of some libc functions 
- Decompilation of libsandbox allow to see a race condition
- Use the overflow to create a read to send shellcode into writable memory
- Use an open and pwrite call to write the shellcode into rx memory by writing into /proc/self/mem
- Use a write syscall to trigger supervisor polling event
- Abuse the race to jump on a different address in libc with a gadget allowing us to jmp where we want
- Loop back to main in supervisor mode bypassing the sandbox
- Simple system(/getflag) for the win

# Chal Analysis #
This challenge is actually exactly the same challenge as Boring with an added sandbox.  
You can find the writeup [here](https://ret2skillz.pages.dev/writeups/fcsc2026_boring/), but basically we have leak of libc and canary and a simple overflow. One thing to note is that the overflow is often messing with stuff if ropchain is too long.  
Also the flag is now in /flag.txt as mode 400 owned by root, so dropping in a shell as ctf is useless as we won't be able to read the flag, that's why we get provided with a getflag binary in **/**. Our goal is to manage to execute it.

# Sandbox Analysis
## Seccomp and Hooks
First of all we can see that the sandbox hooks some libc functions. Those functions are what will normally trigger polls from the supervisor (as we will see later);
```C
#ifndef HOOKS_H
#define HOOKS_H

#include <sys/types.h>
#include <sys/utsname.h>
#include <stdio.h>

// Function pointers for original libc functions
typedef int (*system_func_t)(const char *);
typedef int (*execve_func_t)(const char *, char *const [], char *const []);
typedef int (*open_func_t)(const char *, int, ...);
typedef FILE *(*popen_func_t)(const char *, const char *);
typedef int (*chmod_func_t)(const char *, mode_t);
typedef int (*uname_func_t)(struct utsname *);
typedef ssize_t (*getrandom_func_t)(void *, size_t, unsigned int);
typedef int (*unlink_func_t)(const char *pathname);

#endif // HOOKS_H
```
There's also (of course) a seccomp provided.
```C
#include "seccomp.h"
#include "logging.h"
#include <seccomp.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int g_error_pipe = -1;

// Signal handler for SIGSYS
static void handle_seccomp_violation(int signum, siginfo_t *info, void *ctx) {
    if (signum == SIGSYS && g_error_pipe != -1) {
        int syscall_num = info->si_syscall;
        if (write(g_error_pipe, &syscall_num, sizeof(int)) != sizeof(int)) {
            goto end;
        }
    }
    end:
    _exit(EXIT_FAILURE);
}

static void setup_seccomp_monitor(void) {
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = handle_seccomp_violation;
    sigaction(SIGSYS, &sa, NULL);
}

static void setup_seccomp_filter(void) {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_TRAP);
    if (!ctx) _exit(EXIT_FAILURE);

    // Allow basic, harmless syscalls

    // I/O
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pwrite64), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pread64), 0);
    
    // File operations
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
    
    // Memory
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
    
    // Exit
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

    if (seccomp_load(ctx) < 0) _exit(EXIT_FAILURE);
    seccomp_release(ctx);
}

void setup_seccomp(void) {
    setup_seccomp_monitor();
    setup_seccomp_filter();
}

void print_seccomp_violation(int syscall_num) {
    char *name = seccomp_syscall_resolve_num_arch(SCMP_ARCH_NATIVE, syscall_num);
    LOG_CRIT("Seccomp violation. Syscall %d (%s) was blocked.", 
            syscall_num, name ? name : "Unknown");
    free(name);
}
```
As you can see open,read,write is authorised but useless since flag owned by root. There's not really any tricks I saw in bypassing this seccomp, the goal is not seccomp bypass.

## Core functionalities
This is the code of core.c.
```C
void __attribute__((constructor)) init_sandbox(void) {
    // Prevent recursion in case of subsequent forks
    if (getenv("SANDBOX_ACTIVE")) return;

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    
    // Setup IPC channel
    setup_ipc();

    // Setup signaling channels
    int pipe_err[2], pipe_notify[2];
    if (pipe(pipe_err) == -1 || pipe(pipe_notify) == -1) {
        LOG_CRIT("Failed to initialize signaling pipes");
        _exit(EXIT_FAILURE);
    }

    pid_t pid = fork();
    if (pid < 0) {
        LOG_CRIT("Failed to fork");
        _exit(EXIT_FAILURE);
    }

    if (pid == 0) {
        // Sandboxed process execution
        setenv("SANDBOX_ACTIVE", "1", 1);
        
        close(pipe_err[0]);
        close(pipe_notify[0]);
        
        g_ipc_notify_pipe = pipe_notify[1];
        g_error_pipe = pipe_err[1];

        // Setup SECCOMP rules
        setup_seccomp();

        return; 
    } else {
        // Supervisor Execution
        close(pipe_err[1]);
        close(pipe_notify[1]);
        
        run_supervisor(pid, pipe_err[0], pipe_notify[0]);
        
        __builtin_unreachable();
    }
}
```
It starts by checking the SANDBOX_ACTIVATE is set. And setup the ipc. It uses a fork to create a supervising parent and a child. We can observe that the seccomp is only effective on the sandboxed child. The parent act as the supervisor with the run_supervisor function.
```C
static void run_supervisor(pid_t child_pid, int err_pipe_fd, int notify_pipe_fd) {
    struct pollfd fds[2];
    int status;
    int running = 1;

    // Monitor seccomp traps
    fds[0].fd = err_pipe_fd;
    fds[0].events = POLLIN;

    // Monitor incoming IPC requests
    fds[1].fd = notify_pipe_fd;
    fds[1].events = POLLIN;

    while (running) {
        int ret = poll(fds, 2, -1);
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }

        // Polling seccomp policy violations
        if (fds[0].revents & POLLIN) {
            int syscall_num;
            if (read(fds[0].fd, &syscall_num, sizeof(int)) == sizeof(int)) {
                print_seccomp_violation(syscall_num);
            }
            running = 0; // Fail-secure
        } else if (fds[0].revents & POLLHUP) {
            running = 0; // Disconnect
        }

        // Polling IPC notifications
        if (fds[1].revents & POLLIN) {
            char dummy;
            if (read(fds[1].fd, &dummy, 1) == 1) {
                if (g_shm_mailbox->is_ready) {
                    handle_ipc_command(&g_shm_mailbox->message);
                    
                    // Release mailbox lock for subsequent operations
                    g_shm_mailbox->is_ready = 0; 
                }
            }
        }
    }

    waitpid(child_pid, &status, 0);
    
    // Forward the sandbox exit code
    if (WIFEXITED(status)) {
        _exit(WEXITSTATUS(status));
    } else {
        _exit(EXIT_FAILURE);
    }
}
```
What it does is poll for events on the child. If it see a seccomp violation it prints a log about it. If it gets an IPC notification and if the shared memory is marked as is_ready it calls handle_ipc_command.

Then the final important code comes from ipc.c.
```C
void setup_ipc(void) {
    g_shm_mailbox = mmap(NULL, sizeof(ipc_mailbox_t), 
                         PROT_READ | PROT_WRITE, 
                         MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    if (g_shm_mailbox == MAP_FAILED) {
        LOG_CRIT("Failed to allocate shared memory mailbox (%s)", strerror(errno));
        _exit(EXIT_FAILURE);
    }
}
```
This function does a mmap **RW** of a shared memory zone between the parent and child. This is the only zone allowing parent and child to communicate or share same "data".  The ipc_mailbox_t structure has an int is_ready serving for the supervisor to know it needs to treat the IPC communication.
```C
void sandbox_send(ipc_message_t *msg, size_t msg_len) {
    if (!g_shm_mailbox || g_ipc_notify_pipe == -1) 
        _exit(EXIT_FAILURE);

    // Wait until supervisor is ready to receive a new message
    while (g_shm_mailbox->is_ready == 1)
        __asm__ volatile("pause");

    // Load message into shared memory
    memcpy(&g_shm_mailbox->message, msg, msg_len);
    g_shm_mailbox->is_ready = 1;

    // Notify the supervisor
    char signal_byte = 1;
    if (write(g_ipc_notify_pipe, &signal_byte, 1) != 1) {
        _exit(EXIT_FAILURE);
    }
```
This function send data with memcpy in the shared mailbox message zone before notifying the supervisor with a write syscall.
```C
// --- Supervisor Logic ---
void handle_ipc_command(ipc_message_t *msg) {
    switch (msg->command) {
        case CMD_SYSTEM:
            LOG_CRIT("system('%s') attempted /!\\", msg->data.system.path);
            break;
        case CMD_EXECVE:
            LOG_CRIT("execve('%s') attempted /!\\", msg->data.execve.path);
            break;
        case CMD_OPEN:
            LOG_CRIT("open('%s', %d) attempted /!\\", msg->data.open.path, msg->data.open.flags);
            break;
        case CMD_POPEN:
            LOG_CRIT("popen('%s') attempted /!\\", msg->data.popen.path);
            break;
        case CMD_CHMOD:
            LOG_CRIT("chmod('%s', %d) attempted /!\\", msg->data.chmod.path, msg->data.chmod.mode);
            break;
        
        case CMD_UNAME: {
            // Malwares are using uname to fingerprint the kernel version
            // Let's fool them !!
            struct utsname *u = &msg->data.uname.buf;
            strncpy(u->sysname, "Linux", sizeof(u->sysname) - 1);
            strncpy(u->nodename, "sandbox", sizeof(u->nodename) - 1);
            strncpy(u->release, "5.15.0-sandbox", sizeof(u->release) - 1);
            strncpy(u->version, "#1 SMP Sandbox", sizeof(u->version) - 1);
            strncpy(u->machine, "x86_64", sizeof(u->machine) - 1);
            break;
        }
        case CMD_GETRANDOM: {
            // Ransomwares may use getrandom to generate keys
            // Let's make the randomness deterministic so I can recover my files
            size_t request_len = msg->data.getrandom.buflen;
            size_t max_len = sizeof(msg->data.getrandom.buf);
            if (request_len > max_len) request_len = max_len;

            // Fill with deterministic randomness
            unsigned char *buf = (unsigned char *)(msg->data.getrandom.buf);
            for (size_t i = 0; i < request_len; i++) {
                buf[i] = rand() % 256;
            }
            msg->data.getrandom.buflen = request_len;
            break;
        }
        case CMD_UNLINK: {
            LOG_CRIT("unlink('%s') attempted !", msg->data.unlink.path);
            break;
        }
        default:
            LOG_CRIT("Command not supported. This should never happen!");
            break;
    }
}
```
Finally this function take shared mailbox command as a number and either block it or changes its behavior.

## Sumarising the sandbox
To summarise what the sandbox does.  
1. Hook some libc functions
2. Fork with the parent acting as supervisor and the child being sandboxed and with seccomp
3. Create a shared mailbox mmaped memory for the child to send IPC notifs to the parent, the parent then treats them.

## Vulnerability
It took me a long time to actually find the vulnerability in this challenge. I could not see anything vulnerable at first glance so I tried to enumerate the interesting things most likely paths.  
First of all I know that in such cases of sandboxes/IPC the most likely vulnerability could be a race condition, however I could not see it in the code.  
I thought that being able to disable SANDBOX_ACTIVE could be nice, but I did not see a way to disable it for the child. 
I thought a race condition could happen on several functions modifying is_ready at same time, however I did not see how and more importantly not how it would be useful.
Finally, I tried opening /proc/parent/mem to write directly in file but it's actually blocked on the environement of the challenge (and if you didn't disable some securities on your linux).
Thankfully those failed trials did help me when I tried scenarios of exploitation, but after staring again and again at the code I was clueless about any kind of vulnerability.  

I then spent a lot of time in gdb to try understand the program better and how the sandbox was actually working. After breaking and stepping into all the possible functions is when I finally observed weird stuff in **handle_ipc_command**.  
1. Rdi points to shared_mailbox+8 which is the number of the command we send to IPC meaning we control [rdi]
2. The function directly used it as a way to calculate the address to jump to  
So I decided to open IDA to see more clearly the disassembly of this function.

## Disassembly
Finally in IDA is where you can see the vulnerability in the image.  
![disassembly](/images/FCSC2026/NotSoBoring/disas.png)  
As you can see it starts normally by comparing **[rdi]** with 0x7, if it's above it takes the failed path.  
However, it access **[rdi]** again on the right path!!  
It moves **[rdi]** into rax and calculates based on **[rdx+rax*4]** the address to jump to. It means that we can trigger the right path before changing the value of **[rdi]** that we control to jump where we want. We will simply need to adjust our calculations to land on the right address.

## Leaks
Remember that we have libc leaks. The other libraries, and more importantly the shared memory is at fixed offsets from the libc. The offsets are however different between local and remote (docker). This could be solved by leaking from **/proc/self/maps** however since the docker is provided I simply chose to debug it to see the offsets on remote (the provided docker is modified to allow that).

## Exploitation ##
So we have a race condition, but now we need find the way to actually execute unsandboxed code.  
My first problem was managing to trigger the race. We know we have to poll the supervisor for it to call **handle_ipc_command** then race the command so that it eventually jumps to a different location.

## Conclusion ##
For a one star challenge I thought the vulnerabilities were not the most obvious ones usually found in easy challenges. But there wasn't much difficulty in this challenge. Its harder version was way more interesting.
