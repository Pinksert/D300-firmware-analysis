# 尼康 D300 官方固件解析（Nikon D300 Firmware Analysis）

尼康 **D300**（2007 年发布）官方固件的逆向解析。官方固件以两个独立镜像发布：

- **A 固件**（`A3000111.bin`，约 512 KB）：IO 协处理器，负责测光 / 对焦 / 按键等。
- **B 固件**（`B3000111.bin`，约 7 MB）：主控，负责 UI、图像处理与多语言文本。

本仓库中的固件均为**明文**，未做任何加密——与后续 D300S 的加密固件形成鲜明对比。

## 文件说明

| 文件 | 说明 |
|---|---|
| `A3000111.bin` | D300 A 固件原始镜像（明文，约 512 KB） |
| `B3000111.bin` | D300 B 固件原始镜像（明文，约 7 MB） |
| `D300_NT(Sc)04.pdf` | D300 官方说明书（简体中文，452 页，供交叉印证固件发现） |

## 处理器平台（解析结论）

- 架构：Fujitsu **FR 系列 32 位 RISC，大端**；RTOS = Softune REALOS/FR（micro-ITRON）。
- A 处理器 ≈ 富士通 MB91360 系列（512 KB Flash）；B 处理器同为 FR 但不同型号，带外部存储器总线（XIP）。
- 整机至少 3 颗处理器：EXPEED 图像 ASIC ＋ 主控 MCU(B) ＋ 协处理器 MCU(A)。

## 相关

- B 站专栏系列：[AI 把尼康 D300 的官方固件拆开了：7MB 全是明文，一点加密都没有](https://www.bilibili.com/opus/1257497777850548249)

- D300S 下篇 · 加密固件解析：<https://www.bilibili.com/opus/1257549137054793745>（对应仓库：<https://github.com/Pinksert/D300S-firmware-analysis>）
## 免责声明

本仓库内容仅供学习与研究使用。固件版权归尼康（Nikon）所有，请勿用于任何商业或侵权行为。

## 固件 bin 文件分析报告

分析对象：`D300Update/A3000111.bin` 与 `D300Update/B3000111.bin`（来自 F-D300-V111W.exe） · 分析方式：静态二进制分析（熵扫描 / 字符串提取 / 校验和验证）

- **A3000111.bin 大小**：512 KiB + 2 B

- **B3000111.bin 大小**：7 MiB

- **固件版本**：Ver. 1.11

- **CPU 架构**：Fujitsu FR

- **CRC-16 校验**：两个文件均通过

- **加密状态**：明文（未加密）

### 一、总体结论

这是 **Nikon D300 数码单反 Ver.1.11 固件升级包**解包后的两个主体镜像文件。尼康把相机固件拆成两块独立烧写的映像：

- **Firmware A（A3000111.bin）**——主控 CPU 的**程序代码**映像，512 KiB。里面是 Fujitsu FR 系列处理器的机器码、RTOS 内核、引导与升级逻辑，以及用于固件校验/解密的 **CIPHERUNICORN-S** 密码库。
- **Firmware B（B3000111.bin）**——**资源/数据**映像，7 MiB。里面是菜单 UI 的多语言文本表、图像处理参数表、ICC 色彩配置文件、DPOF/PictBridge 打印脚本、GPS 与无线传输（WT-4）相关字符串，以及一块高熵压缩数据。
两个文件**均未加密**，尾部各带 2 字节 CRC-16 校验，且校验值**完全匹配**，说明文件完整未被篡改。

### 二、校验和机制（已验证）

两个文件的**最后 2 字节**是 CRC-16 校验值，算法为 **CRC-16/CCITT-FALSE**（多项式 `0x1021`，初值 `0x0000`，非反射，无输出异或），以**大端序**存放，覆盖范围是整个文件**除最后 2 字节外**的全部数据。

| 文件 | 文件长度 | 参与校验长度 | 存储值 | 计算值 | 结果 |
| --- | --- | --- | --- | --- | --- |
| `A3000111.bin` | `0x80002` | `0x80000` | `4F 36` | `4F 36` | ✔ 通过 |
| `B3000111.bin` | `0x700000` | `0x6FFFFE` | `9F 23` | `9F 23` | ✔ 通过 |
| `D300_NT(Sc)04.pdf` | D300 官方说明书（简体中文，452 页，供交叉印证固件发现） |

Python 验证：`binascii.crc_hqx(data[:-2], 0)`

### 三、A3000111.bin（Firmware A）解析

#### 3.1 文件头（0x00 – 0x3F，共 64 字节）

```
00000000  01 11 00 00 13 04 19 13  44 33 30 30 20 46 69 72  |........D300 Fir|
00000010  6d 77 61 72 65 20 41 20  43 6f 70 79 72 69 67 68  |mware A Copyrigh|
00000020  74 20 4e 69 6b 6f 6e 20  43 6f 72 70 2e 00 06 0f  |t Nikon Corp....|
00000030  00 00 00 00 00 00 00 00  00 00 00 00 00 00 17 00  |................|
```

| 偏移 | 长度 | 原始字节 | 含义 |
| --- | --- | --- | --- |
| `0x00` | 2 | `01 11` | 固件版本号，BCD 编码 → Ver. 1.11 |
| `0x02` | 2 | `00 00` | 保留字段 |
| `0x04` | 4 | `13 04 19 13` | 构建日期戳，BCD → 2013/04/19（末字节 0x13 疑为内部构建序号） |
| `0x08` | 37+1 | `"D300 Firmware A Copyright Nikon Corp." + 00` | 机型与版权标识串，0x2C 处 NUL 结束 |
| `0x2D` | 17 | `06 0F 00 … 00` | 头部参数区（含义未明，多为 0） |
| `0x3E` | 2 | `17 00` | 小端 16 位值 = 0x0017 (23)，疑为头部长度/条目数 |

#### 3.2 区域布局

| 偏移范围 | 大小 | 香农熵 | 性质 |
| --- | --- | --- | --- |
| `0x00000 – 0x00040` | `64 B` | — | 文件头（见上表） |
| `0x00040 – 0x60000` | `≈384 KiB` | 6.63 – 6.78 | FR 机器码主体（程序） |
| `0x60000 – 0x70000` | `64 KiB` | 6.02 | 数据表，约 26% 为 0x00 |
| `0x70000 – 0x80000` | `64 KiB` | 4.57 | 稀疏数据表 + 41% 0xFF 填充 |
| `0x80000 – 0x80002` | `2 B` | 1.00 | CRC-16 = 0x4F36 |

注：0x6487C、0x6547C 处各有一段 0xBD0 字节的 0x00 块，0x72394、0x75A31、0x78A5E、0x7F080 处有多段 0xFF 填充，符合 "代码段 + 数据段 + 对齐填充" 的典型嵌入式映像布局。

#### 3.3 关键内嵌字符串

| 偏移 | 内容 | 说明 |
| --- | --- | --- |
| `0x000008` | `D300 Firmware A Copyright Nikon Corp.` | 固件标识 |
| `0x06352C` | `CIPHERUNICORN-S COPYRIGHT (C) NEC CORPORATION 2006` | NEC CipherUNICORN-S 分组密码库——尼康用于后期机型（D300S/D3S 以后）的固件加密/签名校验，此处是 A 固件中的解密验证例程 |
| `0x07E471` | `Softune REALOS/FR is Realtime OS for FR Family, based on micro-ITRON COPYRIGHT(C) FUJITSU LIMITED 1994-1999` | REALOS/FR 实时操作系统（micro-ITRON 标准）——确认 CPU 为富士通 FR 系列 |

### 四、B3000111.bin（Firmware B）解析

#### 4.1 头部特征

B 文件**没有** A 那样的 ASCII 明文头，0x00 处直接就是机器码：

```
00000000  9f 80 50 00 00 00 c0 11  15 01 87 10 9f 8f 00 00  |..P.............|
00000010  84 00 9f 80 00 0e fc 00  b3 00 9b 00 06 00 9b 41  |................|
```

版本信息以**签名块**形式放在映像中部：

```
00182C37  44 33 30 30 46 69 72 6d  77 61 72 65 53 69 67 6e  |D300FirmwareSign|
00182C47  61 74 75 72 65 00                                |ature.          |
00182C50  56 65 72 2e 31 2e 31 31  20 20 44 33 30 30 20 32  |Ver.1.11  D300 2|
00182C60  30 31 33 2f 30 34 2f 31  31 20 66 6f 72 20 6d 61  |013/04/11 for ma|
00182C70  73 73 20 70 72 6f 64 75  63 74 69 6f 6e 00       |ss production.  |
```

**签名串** `D300FirmwareSignature`（位于 0x182C37）

**版本串** `Ver.1.11  D300 2013/04/11 for mass production`（位于 0x182C50）

#### 4.2 区域布局（64 KiB 分块熵值）

| 偏移范围 | 大小 | 熵 | 内容 |
| --- | --- | --- | --- |
| `0x000000 – 0x0152DC` | `≈86 KiB` | 6.71 | 启动/初始化代码（含 REALOS/FR 版权串 @0x00073D） |
| `0x0152DC – 0x0AFBF0` | `618 KiB` | 0 | 全 0xFF 填充（地址空洞 / 分区对齐） |
| `0x0AFBF0 – 0x00B0000` | `≈1 KiB` | — | 小参数表（00 1C 2C 50 / 00 04 04 F8 等重复条目） |
| `0x00A0000 – 0x00B0000` | `64 KiB` | 0.16 | 稀疏表（98.4% 为 0xFF） |
| `0x00B0000 – 0x00E0000` | `192 KiB` | 0 | 全 0xFF 填充 |
| `0x00E0000 – 0x0227E14` | `≈1.29 MiB` | 6.4 – 6.7 | 主代码段 + 图像处理参数表 |
| `0x0227E14 – 0x022F534` | `≈30 KiB` | 0 | 0xFF 填充 |
| `0x0240000 – 0x0330000` | `≈960 KiB` | 1.9 – 5.9 | 低熵数据表（大量 0x00），含 0x19868A / 0x19DB12 等 0x00 区 |
| `0x0346330 – 0x0470000` | `≈1.14 MiB` | 4.8 – 5.9 | 多语言 UI 文本表（15 个语言包） |
| `0x04D0000 – 0x050E60F` | `≈253 KiB` | 7.69 – 7.92 | 高熵压缩/加密数据块（近乎随机，为压缩资源如字库/图形） |
| `0x050E60F – 0x06FFFFE` | `≈1.94 MiB` | 0 | 全 0xFF 填充 |
| `0x06FFFFE – 0x0700000` | `2 B` | — | CRC-16 = 0x9F23 |

#### 4.3 多语言 UI 文本表

文本区起点附近可以找到一段「语言选择菜单」的原生语言名列表，共出现 **15 次**（即 15 个语言包各自存了一份）：

```
Deutsch English Espa\xa4\x00ol Fran\x9c\x00ais Italiano Nederlands Svenska 0F 07
8c 2d b0 2f 28 c3 30 ac 2d 29 c9 0e db 0e e8 0f bb 26 a5 23 ba 1e fc 1e b1 21 c1 1d ...
```

已确认存在下列语言包（按块起始偏移）：

| 块偏移 | 语言 | 样例文本 |
| --- | --- | --- |
| `0x346330` | （资源/共用块） | `Mass Storage / MTP/PTP / PictBridge / 3.5x5 in.` |
| `0x3527B0` | Deutsch（德文） | `Fertig · Kommentar eingeben · Zurücksetzen · Spiegel hochklappen` |
| `0x368457` | English（英文） | `Done · Input comment · Attach comment · Start printing` |
| `0x3792EB` | Español（西班牙文） | `Hecho · Introducir comentario · Iniciar impresión` |
| `0x38CE99` | Suomi（芬兰文） | `Valmis · Lisää selitys · Aloita tulostus` |
| `0x39F5BF` | Français（法文） | `Terminé · Joindre une légende · Lancer l'impression` |
| `0x3B4863` | Italiano（意大利文） | `Esegui · Scrivi commento · Avvia stampa` |
| `0x3E9C77` | Nederlands（荷兰文） | `Gereed · Commentaar invoeren · Start met printen` |
| `0x3FC3C0` | Polski（波兰文） | `Gotowe · Wpisz komentarz · Rozpocznij druk` |
| `0x410D90` | Português（葡萄牙文） | `Efectuado · Inserir legenda · Iniciar impressão` |
| `0x42599F` | Русский（俄文，非拉丁编码） | 字符以 2 字节转义序列存储 |
| `0x44478A` | Svenska（瑞典文） | `Klar · Ange kommentar · Starta utskrift` |
| `0x3C87F2 / 0x3DA0DB / 0x4562E8` | 中日韩（CJK，非拉丁编码） | 字符以 2 字节转义序列存储 |

> 文本编码说明：UI 文本并非标准 ASCII/UTF-8，而是尼康自定义的压缩编码：常用 ASCII 字符占 1 字节；带重音的拉丁字母（ñ、ç、ê、ö、å 等）以及西里尔、CJK 字符使用双字节转义序列（如 a4 00 = ñ、9c 00 = ç、9f 00 = ê），0F 07 等为特殊符号/分隔标记。因此直接用 strings 只能看到拼接在一起的文本碎片。

#### 4.4 资源与功能性字符串（抽样）

| 类别 | 位置 | 内容 |
| --- | --- | --- |
| 机型标识 | `0x1802EC …` | `NIKON D300、NIKON CORPORATION` |
| 白平衡 | `0x1805A0 …` | `MERCURY LAMP / DAYLIGHT FL / DAY WHITE FL / COOL WHT FL / WHITE FL / WARM WHT FL / SODIUM LAMP / FLUORESCENT / INCANDESCENT / SHADE / CLOUDY / FLASH / SUNNY` |
| 拍摄模式 | `0x180C14 …` | `LANDSCAPE / PORTRAIT / ACTION PRG / CREATIVE PRG / SHUTTER / APERTURE / PROGRAM / MATRIX / CENTER` |
| 润饰菜单 | `0x1807E8 …` | `IMAGE OVERLAY / COLOR BALANCE / WARM FILTER / SKYLIGHT / CYANOTYPE / D-LIGHTING / SMALL PICTURE / SEPIA / RED-EYE / REAR SLOW` |
| 闪光控制 | `0x17BD3C …` | `Optional / Built-in / M&Comdr. / TTL&Comdr. / RPT / A / AA / TTL` |
| 优化校准 | `0x1862BC …` | `PICTURE CNTRL / SHARPENING / CONTRAST / BRIGHTNESS / SATURATION / QUICK ADJUST / COLOR SPACE / WHITE BALANCE` |
| 兼容机型表 | `0x18098C …` | `NIKON D40X / D40 / D80 / D200 / D100 / D3 / D2Hs / D2H / D2Xs / D2X / D300` |
| ICC 色彩配置 | `0x185524 …` | `mntrRGB XYZ / acspAPPL / Nikon Adobe RGB 4.0.0.3000 / Nikon Inc. & Nikon Corporation 2002` |
| DPOF 打印 | `0x185800 …` | `PRT QTY=001 · GEN CRT="NIKON D300" · GEN REV=01.10 · A:\MISC\AUTPRINT.MRK · IMG FMT=EXIF2` |
| GPS 记录 | `0x185CE8 …` | `HEADING : / TIME(UTC) : / ALTITUDE : / LONGITUDE : / LATITUDE : / COPYRIGHT : / ARTIST :` |
| PictBridge / DPS | `0x18F0F0 / 0x1A1E18 …` | `HDISCVRY.DPS / HREQUEST.DPS / HRSPONSE.DPS · configurePrintService · getCapability · notifyDeviceStatus` |
| 无线传输 (WT-4) | `0x185078 …` | `SSID · WEP · WPA-PSK · WPA2-PSK · TKIP · AES · FTP · PASV · Proxyserver · MAC-Adresse` |
| 文件系统路径 | `0x18300C …` | `A:\DCIM\100ND300\ · A:\NIKON001.DSC · DSC_1234 · NCSETUP1.BIN · PICCON%02d.NCP · WLANQUE2.BIN` |
| 第三方库 | `0x0014B98` | `Copyright (c) 2000-2007 by FotoNation. All rights reserved. · RedEye Library v.2.10.0.0` |

### 五、与 D300SUpdate/D300S102.bin 的对比

同目录下的 `D300SUpdate/D300S102.bin` 揭示了尼康固件打包方式的演进：

| 项目 | D300 (V1.11) | D300S (V1.02) |
| --- | --- | --- |
| 文件数 | 2 个（A + B 分开） | 1 个（A + B 合并） |
| 总大小 | `0x80002 + 0x700000` | `0x780002` |
| 关系 | `0x700000 (B) + 0x80000 (A) + 2 (CRC) = 0x780002 ✔ 完全吻合` |  |
| 内容 | 明文，可直接看到字符串与代码 | 已加密/混淆，开头为 32 字节 0x20 填充 + Pr1 魔数，其后为高熵数据 |
| CRC 验证 | 通过 | 不适用（密文上 CRC 不匹配，说明 CRC 在加密前计算或对明文计算） |

而 **A 固件中携带的 CIPHERUNICORN-S（NEC）密码库**，正是尼康从这一代产品开始引入的固件加密体系——同一份 A 固件里既有用于校验新版加密固件的解密例程，也解释了为什么 D300S 之后的 bin 文件不再是可读明文。

### 六、平台信息汇总

| 项目 | 结论 |
| --- | --- |
| 处理器 | Fujitsu FR 系列（FR-Family，32 位 RISC，大端序，16/32 位混合指令） |
| 操作系统 | Softune REALOS/FR，符合 micro-ITRON 标准（富士通 1994–1999） |
| 开发工具链 | Fujitsu Softune |
| 第三方组件 | FotoNation RedEye Library v2.10.0.0（红眼消除）、NEC CIPHERUNICORN-S（分组密码） |
| 校验算法 | CRC-16/CCITT-FALSE（poly 0x1021，init 0x0000，大端存放于文件末 2 字节） |
| 填充字节 | 未使用区域为 0xFF（Flash 擦除态），少量 0x00 |
| 功能覆盖 | 多语言 UI、优化校准、白平衡、闪光/CLS 指令、LiveView、多重曝光、间隔拍摄、GPS、WT-4 无线/FTP、PictBridge/DPOF 打印 |

### 七、附：可复现的分析方法

```
# 1. CRC-16 校验（两个文件均通过）
import binascii, os
d = open('D300Update/A3000111.bin','rb').read()
print(hex(binascii.crc_hqx(d[:-2], 0)), d[-2:].hex())   # 0x4f36  '4f36'

# 2. 分块香农熵 → 定位代码段 / 数据表 / 填充区 / 压缩包
# 3. 连续相同字节 runs → 定位 0xFF 空洞
# 4. 正则 [\x20-\x7e]{5,} 提取 ASCII 串；带重音与 CJK 为双字节转义
```
