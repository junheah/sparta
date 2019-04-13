---
title: Assignment 0-2
tags: assingment0 dalgona bof
---
## Buffer Overflow Foundation (Dalgona) ~p.27

### 0. 8086 Memory Architecture

||
|-|
|<center><br><br><br>Available<br>Space<br><br><br></center>|
|<center>Kernel</center>|

Upon system initialization, kernel is loaded to memory and usable memory is scanned.

#### 0-0. Segment:

When a process is started, operating system binds it to a 'segment' and puts it into memory.

When segments are loaded into memory:

||
|-|
|<center>Segment 3</center>|
|<center>Available<br>Space</center>|
|<center>Segment 2</center>|
||
|<center>Segment 1</center>|
||
||
|<center>Kernel</center>|

Structure of a segment:

||
|-|
|<center>Stack</center>|
|<center>Data</center>|
|<center>Code</center>|

- code segment:
	- contains instructions
	- uses logical address : since the physical address is only known after execution

> how to get physical address from segments:
> 1. get offset from segment selector
> 2. calculate physical address ( = offset + logical address )

- data segment:
	- contains data used for program execution
	- splits into 4 data segments: data structure, data module, dynamic data, shared data
- stack segment:
	- contains handler, task, program
	- can create multiple stacks
	- can switch between stacks
	- stores local variables
	- stores buffer
	- has a fixed size: decided upon creation

### 1. 8086 CPU Registers

Memory located inside CPU, used for reading and saving instructions/data of a program

#### 1-0. General-Purpose register

- stores operand for arithmetic/logical operations, address calculation and memory pointers 
- can be controlled by programmers
- was called `AX,BX,CX,DX,...` in 16 bits, is now called `EAX,EBX,ECX,EDX,...` in 32 bits (E for Extended)

|Register|purpose|
|-|-|
|EAX|stores operand and operation result|
|EBX|pointer that points to data inside DS segment|
|ECX|counter used in string processing or loops|
|EDX|I/O pointer|
|ESI|points at data inside DS register's data segment, points at source when processing strings|
|EDI|points at data inside ES register's data segment, points at destination when processing strings|
|ESP|points at top of SS register's stack segment|
|EBP|points at a data inside SS register's stack segment|

#### 1-1. Segment register

stores the address of code/data/stack segment

|Register|segment|
|-|-|
|CS|code|
|DS,ES,FS,GS|data|
|SS|stack|

#### 1-2. Program status and control register

- stores flags that are used to determine current program's condition
- upon system reset : 0x00000002
- 1, 3, 5, 15, 21-31 bits are reserved and cannot be controlled by software

Status flags:

|flag|Meaning|Condition|
|-|-|-|
|CF|Carry flag|when carry occurs
|PF|Parity flag|if number of set bits in result is even
|AF|Adjust flag|
|ZF|Zero flag|when result is zero, when if condition is met
|SF|Sign flag|MSB of result (positive:0, negative:1)
|OF|Overflow flag|
|DF|Direction flag|

System flags:

|flag|Meaning|
|-|-|
|IF|Interrupt enable flag|
|TF|Trap flag|
|IOPL|I/O privilege level field|
|NT|Nested task flag|
|RF|Resume flag|
|VM|Virtual-8086 mode flag|
|AC|Alignment check flag|
|VIF|Virtual interrupt flag|
|VIP|Virtual interrupt pending flag|
|ID|Identification flag|

#### 1-3. Instruction pointer

- stores the address of next instruction
- also stores addresses containing JMP, jcc, CALL , IRET instructions
- cannot be accessed via software : only via control-transfer instructions

### 2. What happens to segment upon program execution?

#### 2-0. example program

```c
void function(int a,int b, int c){
	char buffer1[15];
	char buffer2[10];
}

void main(){
	function(1,2,3);
}
```

> compiling with option -S ouputs asm code

Assembly code:

< main >:

```nasm
push ebp                  ;1.to save the previous function data 
mov ebp, esp              ;2.first two lines are called "function prologue"
sub esp, 8h               ;3.extend stack by 8 bytes
and esp, fffffff0h        ;4.sets last 4 bits of esp to 0
mov eax, 0h					
sub esp, eax
sub esp, 4h               ;5.extend stack by 4 bytes
push 3h                   ;6.params are pushed to stack in reverse order
push 2h
push 1h
call 0x80482f4 <function> ;7.function is called: pushes next instruction address to stack (return address)
add esp, 10h              ;11.shrink stack by 16 bytes
leave                     ;12.main function epilogue
ret
nop
```

< function >:

```nasm
push ebp                  ;8.function prologue
mov ebp, esp
sub esp, 28h              ;9.extend stack by 40 bytes
leave                     ;10.function epilogue
ret
```

step 9: why 40 bytes, not 25 bytes?

>because stack uses 4bytes as unit (WORD)
>> 15 bytes : 4 x 4 = 16 bytes
>> 10 bytes : 4 x 3 = 12 bytes
>> = 28 bytes
>
>+offset caused by gcc version (gcc 2.96+ uses 16 bytes as unit)
>= 40 bytes

function prologue:

```nasm
push ebp
mov ebp, esp
```

function epilouge:

```nasm
leave
ret		;≒ pop eip
```

leave:

```nasm
;does the reverse of function prologue
mov esp, ebp
pop ebp
```
