---
title: De1CTF - Mine Sweeping
tags: de1ctf ctf misc writeup
---

```
enjoy the game :)

[Mine Sweeping.zip](https://share.weiyun.com/5c2K8Is)

[Mine Sweeping.zip](https://drive.google.com/open?id=1qzuIMdFolHVr_qxMxUcRQRlbrwb1SRR8)
```
Mine Sweeping.zip:
```
2019-03-05  오후 06:59           650,752 Mine Sweeping.exe
2019-07-27  오전 03:17    <DIR>          Mine Sweeping_Data
2019-07-27  오전 03:17    <DIR>          MonoBleedingEdge
2019-03-05  오후 07:00         1,458,120 UnityCrashHandler64.exe
2019-03-05  오후 07:00        22,887,880 UnityPlayer.dll
2019-03-05  오후 06:54            42,704 WinPixEventRuntime.dll
```
실행화면:

![](/sparta/assets/images/de1_mine.png)

유니티 엔진으로 제작한 지뢰찾기 게임이다.

처음에는 디버거로 삽질을 하다가, 진전이 없어 ``unity game disassembly``라 검색해봤다.

데이터 폴더의 ``Assembly-CSharp.dll``을 보면 된다고 해서, ILSpy로 decompile 해봤다.

```csharp
// Caller
using UnityEngine;

public class Caller : MonoBehaviour
{
	public GameObject resetButton;

	private void Start(){}

	private void Update(){}

	public void CallResetMap()
	{
		Grids._instance.ResetMap();
		resetButton = GameObject.FindGameObjectWithTag("resetButton");
		resetButton.SetActive(value: false);
	}
}
```
Caller는 게임 루프인듯 하다.

```csharp
// Grids
using System;
using UnityEngine;

public class Grids : MonoBehaviour
{
	public static Grids _instance;
	public const int w = 29;
	public const int h = 29;
	public Elements[,] eleGrids = new Elements[29, 29];
	public bool bGameEnd;
	public GameObject resetButton;
	public GameObject alleles;
	public int[,] DevilsInHeaven = new int[29, 29] {...};

	private void Start(){...}

	public int CountAdjcentNum(int x, int y){...}

	public bool MineAt(int nX, int nY)
	{
		if (0 <= nX && nX < 29 && 0 <= nY && nY < 29)
		{
			return eleGrids[nX, nY].bIsMine;
		}
		return false;
	}

	public void Flush(int nX, int nY, bool[,] visited){...}

	public bool GameWin(){...}

	public void GameLose(){...}

	public void ChangeMap(){...}

	public void ResetMap(){...}
}

```
Grids에는 29*29의 2차원 Element 어레이인 eleGrids가 있다. 멤버함수인 mineAt은 이 eleGrids(Element)의 bIsMine 값을 리턴한다.

```csharp
// Elements
using UnityEngine;

public class Elements : MonoBehaviour
{
	public Sprite[] Athene;
	public Sprite Thor;
	public Sprite Hodur;
	public Sprite Baldr;
	public Sprite Khaos;
	public GameObject resetButton;
	public static int[,] AreYouFerryMen = new int[29, 29] {...};
	public static int[,] MayWorldBeAtPeace = new int[29, 29] {...};
	public bool bIsMine;
	public bool bIsOpen;

	private void Awake()
	{
		int num = (int)base.transform.position.x;
		int num2 = (int)base.transform.position.y;
		bIsMine = ((((MayWorldBeAtPeace[num, num2] ^ AreYouFerryMen[num, num2]) - 233) / 2333 == 1) ? true : false);
		Grids._instance.eleGrids[(int)base.transform.position.x, (int)base.transform.position.y] = this;
		Grids._instance.DevilsInHeaven[(int)base.transform.position.x, (int)base.transform.position.y] = (bIsMine ? 1 : 0);
		resetButton = GameObject.FindGameObjectWithTag("resetButton");
		if ((bool)resetButton)
		{
			resetButton.SetActive(value: false);
		}
	}

	private void Start(){...}

	public void SafeAndThunder(int adjcent){...}

	public void DawnsLight(){...}

	public void LayersOfFear(){...}

	private void OnMouseUpAsButton(){...}
}
```
Element의 bIsMine은 멤버 함수 Awake가 설정해 준다.

이 부분을 자바에서 재현해봤다.
```java
// Main.java
public class Main{
    public static void main(String[] args){
        int[][] MayWorldBeAtPeace = {...};
        int[][] AreYouFerryMen = {...};
        for (int num = 0; num < 29; num++) {
			for (int num2 = 0; num2 < 29; num2++) {
				boolean isMine = ((((MayWorldBeAtPeace[num][num2] ^ AreYouFerryMen[num][num2]) - 233) / 2333 == 1) ? true : false);
				if(isMine)
					System.out.print("0 ");
				else
					System.out.print("  ");
			}
			System.out.println();
		}
    }
}
```
출력:
```
0 0 0 0 0 0 0   0   0   0 0 0           0   0 0 0 0 0 0 0
0           0     0 0     0           0 0   0           0
0   0 0 0   0     0 0 0     0       0   0   0   0 0 0   0
0   0 0 0   0   0       0 0     0     0 0   0   0 0 0   0
0   0 0 0   0         0   0     0 0 0 0 0   0   0 0 0   0
0           0     0 0       0       0 0     0           0
0 0 0 0 0 0 0   0   0   0   0   0   0   0   0 0 0 0 0 0 0
                      0 0     0       0                   
    0   0 0 0   0 0   0   0 0           0 0       0     0
    0           0             0   0   0 0   0 0     0   0
0 0   0   0 0     0       0 0   0 0 0 0 0 0           0 0
    0   0 0   0   0     0   0 0   0 0   0   0 0 0 0   0   
0 0 0 0     0   0   0 0 0     0 0     0     0             
      0 0         0 0 0 0         0       0 0 0       0 0
  0 0 0 0   0   0 0 0 0 0     0     0   0 0 0       0 0 0
      0   0       0   0 0 0                 0 0 0       0
  0     0   0 0   0 0       0 0   0 0   0 0 0   0 0     0
    0 0   0           0     0   0 0   0   0 0       0 0 0
0     0 0   0 0   0 0 0   0       0       0   0 0 0   0 0
  0       0     0   0   0     0 0     0 0   0             
0       0 0 0 0     0         0 0       0 0 0 0 0   0 0 0
                0   0 0   0 0   0       0       0     0 0
0 0 0 0 0 0 0             0 0   0 0 0 0 0   0   0   0 0 0
0           0   0     0   0 0   0   0   0       0     0 0
0   0 0 0   0   0 0     0 0 0           0 0 0 0 0 0   0   
0   0 0 0   0         0   0     0 0 0           0         
0   0 0 0   0   0 0   0 0       0       0 0     0       0
0           0     0   0 0 0       0 0         0       0   
0 0 0 0 0 0 0         0 0     0       0 0   0   0     0 0
```
QR 코드 모양이 나와서 이를 이미지 형식으로 출력했다.
```java
// Main.java
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.awt.Color;
import java.awt.Graphics;

public class Main{
    public static void main(String[] args){
        int[][] MayWorldBeAtPeace = {...};
        int[][] AreYouFerryMen = {...};
        BufferedImage output = new BufferedImage(29*10, 29*10, BufferedImage.TYPE_INT_RGB);
        Graphics canvas = output.getGraphics();
        for (int num = 0; num < 29; num++) {
            for (int num2 = 0; num2 < 29; num2++) {
                boolean isMine = ((((MayWorldBeAtPeace[num][num2] ^ AreYouFerryMen[num][num2]) - 233) / 2333 == 1) ? true : false);
                if(isMine)
                    canvas.setColor(Color.BLACK);
                else
                    canvas.setColor(Color.WHITE);
                canvas.fillRect(num*10, num2*10, 10, 10);
            }
        }
        try {
            ImageIO.write(output, "jpg", new File("output.jpg"));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
```
출력:

![QR](/sparta/assets/images/de1_mine_qr.jpg)

스캔해서 나오는 링크를 따라가면 플래그가 나온다.
```
de1ctf{G3t_F1@g_AFt3R_Sw3ep1ng_M1n3s}
```
