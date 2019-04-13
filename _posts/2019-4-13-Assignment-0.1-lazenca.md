---
title: 0-1 lazenca notes
tags: assingment0 lazenca shellcode
---
## The basics technics of Shellcode

### Shellcode

#### 0. Basic knowledge

- Attack where attackers opens "shell" to control target system
- Is a small program written in machine code
- is not completely executable: doesn't have to care about memory positioning
- usually is written in high-level language and then converted to low-level language for execution 

#### 1. Assembly code

#### 1-0. Basic instructions:

|Instruction (Intel)|Meaning|
|--|--|
|MOV dest, source|copy source to destination|
|PUSH value|save value to stack|
|POP register|save value from top of the stack to register|
|CALL function_name(address)|save the address of next instruction (for return) and jump to function address|
|RET|pop return address from stack and jump|
|INC dest|increase destination by 1|
|DEC dest|decrease destination by 1|
|ADD dest, value|add value to destination|
|SUB dest, value|subtract value from destination|
|OR dest, value|do a bitwise-OR calculation and save result to destination|
|AND dest, value|do a bitwise-AND calculation and save result to destination|
|XOR dest, value|do a bitwise-XOR calculation and save result to destination|
|LEA dest, source|load source address to destination|

#### 1-1. INT 0x80 & SYSCALL

```nasm
INT 0x80
SYSCALL
```

|Instruction| Meaning| Architecture|
|--|--|--|
|INT <operand 1>|Call to interrupt|x86, x86_64
|SYSCALL|System call|x86_64|

These two instructions are used to call system function
- "INT 0x80" calls system function saved in EAX register
- "SYSCALL"  calls system functions saved in RAX register


#### 1-2. Linux System Call in Assembly
To build a shellcode, we need system functions that are usable in assembly language.

C language provides standard-library for convinience and compatibility. It provides various system calls for different architectures, making it able to be compiled in various systems.

Assembly language however,  doesn't have such compatibility. Meaning that different calls are used for different architectures.

System calls differ from OS and architectures. Following file provides system call name and number for current system:
```
32bit: /usr/include/x86_64-linux-gnu/asm/unistd_32.h
64bit: /usr/include/x86_64-linux-gnu/asm/unistd_64.h
```
Arguments in system call:

|-|32bit|64bit|
|--|--|--|
|System call|EAX|RAX|
|Arg1|EBX|RDI|
|Arg2|ECX|RSI|
|Arg3|EDX|RDX|
|Arg4|ESI|R10|
|Arg5|EDI|R8|
|Arg6|EBP|R9|

#### 1-3 Example
32bit:
```nasm
section .data                           ; 데이터 세그먼트
    msg db  "Hello, world!",0x0a, 0x0d  ; 문자열과 새 줄 문자, 개행 문자 바이트
  
section .text                           ; 텍스트 세그먼트
    global  _start                      ; ELF 링킹을 위한 초기 엔트리 포인트
  
_start:
    ; SYSCALL: write(1,msg,14)
    mov eax, 4      ; 쓰기 시스템 콜의 번호 '4' 를 eax 에 저장합니다.
    mov ebx, 1      ; 표준 출력를 나타내는 번호 '1'을 ebx에 저장합니다.
    mov ecx, msg    ; 문자열 주소를 ecx에 저장니다.
    mov edx, 14     ; 문자열의 길이 '14'를 edx에 저장합니다.
    int 0x80        ; 시스템 콜을 합니다.
  
    ; SYSCALL: exit(0)
    mov eax, 1      ; exit 시스템 콜의 번호 '1'을 eax 에 저장합니다.
    mov ebx, 0      ; 정상 종료를 의미하는 '0'을 ebx에 저장 합니다.
    int 0x80        ; 시스템 콜을 합니다.
```
64bit:
```nasm
section .data                               ; 데이터 세그먼트
    msg db      "hello, world!",0x0a, 0x0d  ; 문자열과 새 줄 문자, 개행 문자 바이트
 
section .text                               ; 텍스트 세그먼트
    global _start                           ; ELF 링킹을 위한 초기 엔트리 포인트
 
_start:
    ; SYSCALL: write(1,msg,14)
    mov     rax, 1      ; 쓰기 시스템 콜의 번호 '1' 를 rax 에 저장합니다.
    mov     rdi, 1      ; 표준 출력를 나타내는 번호 '1'을 rdi에 저장합니다.
    mov     rsi, msg    ; 문자열 주소를 rsi에 저장니다.
    mov     rdx, 14     ; 문자열의 길이 '14'를 rdx에 저장합니다.
    syscall             ; 시스템 콜을 합니다.
 
    ; SYSCALL: exit(0)
    mov    rax, 60      ; exit 시스템 콜의 번호 '60'을 eax 에 저장합니다.
    mov    rdi, 0       ; 정상 종료를 의미하는 '0'을 ebx에 저장 합니다.
    syscall             ; 시스템 콜을 합니다.
```

#### 1-4 Change to shellcode format
The example code above is not shellcode for following reasons:
- doesn't fully function as a standalone
- requires linking process 

To change this code to shellcode format:
- remove 'text' and 'data' segments
- use 'call' instruction to call helloworld function
- save target string (string used in 'write' function) after the call. 

Target string address has to be passed to write call, however without data-segment, MOV instruction cannot be used. To solve this problem, we have to make use of CALL and RET. When CALL is used, the address of the next instruction is pushed to the stack. We can pop this address and pass it to 'write'.

Conversion result:
```nasm
BITS 32                         ; nasm에게 32비트 코드임을 알린다
  
call helloworld                 ; 아래 mark_below의 명령을 call한다.
db "Hello, world!", 0x0a, 0x0d  ; 새 줄 바이트와 개행 문자 바이트
  
helloworld:
    ; ssize_t write(int fd, const void *buf, size_t count);
    pop ecx         ; 리턴 주소를 팝해서 exc에 저장합니다.
    mov eax, 4      ; 시스템 콜 번호를 씁니다.
    mov ebx, 1      ; STDOUT 파일 서술자
    mov edx, 15     ; 문자열 길이
    int 0x80        ; 시스템 콜: write(1,string, 14)
  
    ; void _exit(int status);
    mov eax,1       ;exit 시스템 콜 번호
    mov ebx,0       ;Status = 0
    int 0x80        ;시스템 콜: exit(0)
```

We can use this code for testing shellcode:
```c
#include<stdio.h>
#include<string.h>
 
unsigned char shellcode [] = "SHELLL CODE";
unsigned char code[];
 
void main(){
    int len = strlen(shellcode);
    printf("Shellcode len : %d\n",len);
    strcpy(code,shellcode);
    (*(void(*)()) code)();
}
```

By building and executing, we can see that our shellcode has errors:
```shell
lazenca0x0@ubuntu:~/ASM$ gcc -o shellcode -fno-stack-protector -z execstack --no-pie -m32 shellcode.c
test.c:5:15: warning: array 'code' assumed to have one element
 unsigned char code[];
               ^
lazenca0x0@ubuntu:~/ASM$ ./shellcode
Shellcode len : 2
Segmentation fault (core dumped)
lazenca0x0@ubuntu:~/ASM$
```

The error is caused by null-bytes inside shellcode.

1.First null-byte is from CALL instruction:

This can be solved by jumping to last function (which is after the helloworld function) and then calling helloworld. This removes the null byte because the relative address of helloworld becomes negative.

solution:
```nasm
BITS 32         ; nasm에게 32비트 코드임을 알린다
 
jmp short last  ; 맨 끝으로 점프한다.
helloworld:
    ; ssize_t write(int fd, const void *buf, size_t count);
    pop ecx     ; 리턴 주소를 팝해서 exc에 저장합니다.
    mov eax, 4  ; 시스템 콜 번호를 씁니다.
    mov ebx, 1  ; STDOUT 파일 서술자
    mov edx, 15 ; 문자열 길지
    int 0x80    ; 시스템 콜: write(1,string, 14)
 
    ; void _exit(int status);
    mov eax,1   ;exit 시스템 콜 번호
    mov ebx,0   ;Status = 0
    int 0x80    ;시스템 콜: exit(0)
  
last:
    call helloworld ; 널 바이트를 해결하기 위해 위로 돌아간다.
    db "Hello, world!", 0x0a, 0x0d  ; 새 줄 바이트와 개행 문자 바이트
```

2.Other null bytes are from MOV instructions:

This is caused by register being larger than input. Which causes the register to keep the value before MOV. This can be solved by initializing the register with 0 beforehand.

solution:
```nasm
BITS 32         ; nasm에게 32비트 코드임을 알린다
 
jmp short last  ; 맨 끝으로 점프한다.
helloworld:
    ; ssize_t write(int fd, const void *buf, size_t count);
    pop ecx     ; 리턴 주소를 팝해서 exc에 저장합니다.
    xor eax,eax ; eax 레지스터의 값을 0으로 초기화합니다.
    mov al, 4   ; 시스템 콜 번호를 씁니다.
    xor ebx,ebx ; ebx 레지스터의 값을 0으로 초기화합니다.
    mov bl, 1   ; STDOUT 파일 서술자
    xor edx,edx ; edx 레지스터의 값을 0으로 초기화합니다.
    mov dl, 15  ; 문자열 길지
    int 0x80    ; 시스템 콜: write(1,string, 14)
 
    ; void _exit(int status);
    mov al,1    ;exit 시스템 콜 번호
    xor ebx,ebx ;Status = 0
    int 0x80    ;시스템 콜: exit(0)
  
last:
    call helloworld ; 널 바이트를 해결하기 위해 위로 돌아간다.
    db "Hello, world!", 0x0a, 0x0d  ; 새 줄 바이트와 개행 문자 바이트
```

## Return to Shellcode
### 0. Basic knowledge
Definition: Overwriting the return address with shellcode address, leading it to be executed.

|Instruction|What it does|
|--|--|
|CALL operation|PUSH return_address<br>JMP operation|
|RET|POP RIP<br>JMP RIP|

- CALL pushes the next instruction address to stack and jumps to destination address.
- RET  pops the instruction address from stack to eip and jumps to address.

Thus, by changing the return address, we can change the program flow.

### 1. Proof of concept
```c
#include <stdio.h>
#include <unistd.h>
 
void vuln(){
    char buf[50];
    printf("buf[50] address : %p\n",buf);
    read(0, buf, 100);
}
 
void main(){
    vuln();
}
```
by reading 100 bytes to array of size 50, it causes stack-overflow, allowing attacker to overwrite the return address.
