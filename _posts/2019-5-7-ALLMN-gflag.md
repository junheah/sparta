---
title: ALLMN - Gflag
tags: allmn ctf misc writeup
---
## ALLMN CTF writeup
### Misc - gflag

문제 내용은 다음과 같다
```markdown
My brother likes esoteric programming. He sent me this file but I don't see what it is for. Could you help me ?

[GFlag files](https://static.ctf.insecurity-insa.fr/a7572eb34ba9700b39f1ba7f5869bf301b67d406.tar.gz)
```
제공된 파일 gflag을 보자
```
M73 P0 R2
M201 X9000 Y9000 Z500 E10000
M203 X500 Y500 Z12 E120
M204 P2000 R1500 T2000
M205 X10.00 Y10.00 Z0.20 E2.50
M205 S0 T0
M107
M115 U3.1.0
M83
M204 S2000 T1500
M104 S215
M140 S60
M190 S60
M109 S215
G28 W
G80
...
```
이 파일은 확장자가 생략되어 있고, file 명령어를 사용해도 ``ASCII text`` 라고만 알려준다

헤더를 생략한 svg 파일이라 예상하고 다음과 같이 바꾸었다
```svg
<svg xmlns="http://www.w3.org/2000/svg">
    <path fill="#000" stroke="#000" d="M73 P0 R2"/>
    <path fill="#000" stroke="#000" d="M201 X9000 Y9000 Z500 E10000"/>
    <path fill="#000" stroke="#000" d="M203 X500 Y500 Z12 E120"/>
    <path fill="#000" stroke="#000" d="M204 P2000 R1500 T2000"/>
    <path fill="#000" stroke="#000" d="M205 X10.00 Y10.00 Z0.20 E2.50"/>
    
    ...
</svg>
``` 
아쉽게도 실패했다

svg 외에는 딱히 생각이 나질 않아 한 줄을 그대로 복사하여 구글에 검색해 보았더니
3d 프린터에 사용되는 sd 카드의 메모리 덤프가 결과로 나왔고,
해당 파일이 gcode 파일임을 알 수 있었다.

gcode를 시각화 해주는 온라인 툴을 사용했더니

![flag](/assets/images/allmn_gflg_flag.PNG)

플래그가 나왔다




