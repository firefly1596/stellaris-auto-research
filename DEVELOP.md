# 二次开发指南

> 读者：要改这份代码的人。这一份可以用技术术语。
> 游戏版本锚定 **Stellaris 4.5.4 (Cygnus)**，build `4394a9a4797b27029182f9dba4431b4f`，EXE SHA256 `10D2613A392FE8AC7982701899DC2E43EBF4C1C721EA1BAEBA6C3FB25DB36EB1B`。
> 本文所有结论都标了可复核的位置。凡是没实测过的，明写「未验证」。

---

## 目录

- [1. 环境与构建](#1-环境与构建)
- [2. 代码结构](#2-代码结构)
- [3. 三个构建开关](#3-三个构建开关)
- [4. 技术核心](#4-技术核心)
- [5. 数据流：一次决策发生了什么](#5-数据流一次决策发生了什么)
- [6. 配置语义在哪、怎么改](#6-配置语义在哪怎么改)
- [7. 怎么加日志](#7-怎么加日志)
- [8. 已知风险](#8-已知风险)
- [9. 真实踩过的坑](#9-真实踩过的坑)
- [10. 测试](#10-测试)
- [11. 跨版本适配](#11-跨版本适配)

---

## 1. 环境与构建

### 1.1 需要什么

| 项 | 值 |
|---|---|
| 编译器 | MinGW-w64 g++，需支持 C++17 |
| 本机实测版本 | `g++.exe (MinGW-W64 x86_64-ucrt-posix-seh, built by Brecht Sanders, r3) 16.2.0` |
| 路径（本机） | `_stellaris_eval\tools\mingw\mingw64\bin\g++.exe` |
| 链接库 | `-lkernel32 -lbcrypt` |
| Shell | `.sh` 脚本用 bash（MSYS2 / Git Bash） |

`-lbcrypt` 是必需的：`ar_gate.h` 用 BCrypt 算游戏 EXE 的 SHA256。

### 1.2 两条构建命令（实测）

```bash
cd release_v1/src

# 使用版（无探针）
g++ -std=c++17 -O2 -shared -static -static-libgcc -static-libstdc++ \
    -DAR_BUILD_WITH_PROBES=0 \
    -o auto_research.dll auto_research.cpp -lkernel32 -lbcrypt
# → 828,061 B

# 维护版（带探针）
g++ -std=c++17 -O2 -shared -static -static-libgcc -static-libstdc++ \
    -o auto_research_debug.dll auto_research.cpp -lkernel32 -lbcrypt
# → 848,758 B
```

**实测记录（2026-11-20）**：从 `release_v1/src` 用上面两条命令重建，得到 **828,061 B / 848,758 B**，与 `release_v1/bin` 里发布的两份**大小完全相同**。但 SHA256 不同：

| | 发布版 | 本次重建 |
|---|---|---|
| 使用版 | `CAB01140…A7B7` | `096F79C7…7DE8` |
| 维护版 | `0F06E3C7…7D81` | `E13EEBC3…3149` |

⇒ **MinGW 构建不可复现**。见 [§8 R4](#r4-mingw-构建不可复现) 与 [§9 坑 4](#坑-4mingw-的-data-段每次不同)。

唯一无害的编译警告（两版都有）：
```
auto_research.cpp:737:21: warning: 'g_arTramp' initialized and declared 'extern'
```

### 1.3 ⚠️ MSYS 的 `%TEMP%` 可能不可写

本机实测：`C:\Users\rty\AppData\Local\Temp` 对 g++ **不可写**，直接编译会报
```
g++.exe: Cannot create temporary file in C:\Users\rty\AppData\Local\Temp\: Permission denied
```
`_stellaris_eval\tech_probe\build_and_test.sh` 已经处理了这一点（第 30-37 行：把 `TMP`/`TEMP`/`TMPDIR` 指向 `../../_tmp_arbuild`）。如果你自己写脚本，必须照做。

`release_v1/src/build.sh` **没有**做这一步 —— 它在正常环境可用，在受限环境会失败。手工构建时自己设环境变量：
```bash
export TMP=/d/tmp TMPDIR=/d/tmp TEMP=/d/tmp
```

### 1.4 `build.sh` 用法

```bash
./build.sh          # 构建两个版本
./build.sh use      # 只构建使用版
./build.sh debug    # 只构建维护版
./build.sh test     # 构建两个版本 + 跑全部测试
GXX=/path/to/g++.exe ./build.sh    # g++ 不在 PATH 时
```

`build.sh test` 的产物大小参考值写死在脚本里（828,061 / 848,758）。**这两个值只在 MinGW GCC 16.2.0 + 当前源码下成立**，换编译器版本会变。

### 1.5 ⚠️ `build.sh test` 的一处缺陷（未修，如实记录）

`run_tests()` 用 `./"$t.exe" 2>&1` 直接跑，**不给 `config_filetest` 传 `--dir`**。而该测试默认用 `GetTempPathA()` 得到目录再 `CreateDirectoryA`：

- `%TEMP%` 可写 → 28/28 通过
- `%TEMP%` 不可写（本机沙箱就是） → **9 passed, 19 failed**，`exit=1`，`build.sh test` 报 FAIL

本机实测对照：

| 调用方式 | 结果 |
|---|---|
| `./config_filetest.exe`（用 `%TEMP%`，本机不可写） | `9 passed, 19 failed`，exit 1 |
| `./config_filetest.exe --dir <可写目录>` | `28 passed, 0 failed`，exit 0 |
| `TMP=<可写目录> ./config_filetest.exe` | `28 passed, 0 failed` |

**⇒ 这不是功能缺陷，是测试环境依赖。** 681 项测试的正确跑法见 [§10](#10-测试)。

---

## 2. 代码结构

### 2.1 文件清单

`release_v1/src/` 下 13 个 `.cpp` + 11 个 `.h`。`auto_research.cpp` 与 `_stellaris_eval\tech_probe\auto_research.cpp` **SHA256 完全相同**（`07FB5F32…90A8`），11 个头文件也全部逐字节相同。

| 文件 | 大小 | 职责 |
|---|---|---|
| `auto_research.cpp` | 217,766 B | DLL 主体：hook 安装、接管决策、日志、VEH、环形缓冲、配置 Win32 适配 |
| `ar_config.h` | 20,375 B | **配置语义唯一真值**：解析、`PickBest`、热重载状态机（纯逻辑，不带 `windows.h`） |
| `ar_config_win32.h` | 2,865 B | `arcfg::IFileSource` 的 Win32 实现（`GetFileAttributesExA` + `fopen`） |
| `ar_anchor.h` | 15,948 B | 锚点定义：字符串锚 / 调用链 / 长特征码 / 函数长度，四类判据的数据结构 |
| `ar_resolve.h` | 37,674 B | 地址解析编排：把「在哪」与「怎么装」彻底分开 |
| `ar_resolve_win32.h` | 7,039 B | `IAnchorImage` 的 Win32 实现（包装运行中的游戏进程） |
| `ar_gate.h` | 20,961 B | 版本闸门：决定「这份 DLL 敢不敢在这个进程里装 hook」 |
| `ar_gate_win32.h` | 11,195 B | `IImage` 的 Win32 实现（PE / .pdata / SHA256 / buildId） |
| `ar_layout.h` | 13,590 B | L1 结构偏移自动推导（候选卡组），替代写死常量 |
| `ar_lde.h` | 10,423 B | 极简 x86-64 指令长度解码器（只为「找 rip 相对引用」服务） |
| `ar_tech_names.h` | 36,105 B | 678 条 `tech_key → 中文名` 映射（自动生成，来源 `log_tool/tech_names.json`） |
| `ar_version.h` | 6,635 B | 版本闸门常量表（**自动生成，不要手改**） |
| `build.sh` | 4,141 B | 构建脚本 |

`ar_version.h` 由脚本生成，不是手写：
```bash
node gen_version_h.js "<path>\stellaris.exe"
```

### 2.2 `auto_research.cpp` 的模块划分

`auto_research.cpp` 共 **4,821 行**（2026-11-20 版本）。按文件内的分区顺序：

| 区块 | 行号 | 内容 |
|---|---|---|
| 文件头注释 + includes | 1–36 | 见 [§2.4](#24-️-文件头--注释里有三处过时描述) |
| 中文化表 | 38–71 | `ArAreaZh`(49) / `ArActionZh`(58) |
| 环形缓冲 | 97–157 | `RingPush`(122) / `RingDump`(139)，`AR_RING_CAP=200` / `AR_RING_LINE=160`(115-116) |
| 计数器 + `CrashWrite` | 159–187 | 并列 / `[PICK]` 计数器提为全局(164-169)、上次状态快照(170-176)、`s_seenSoft[8]`(186) |
| `CrashHandler` | 189–324 | 异常码三段判定(231)、完整崩溃块(250-320) |
| `Log()` | 326–333 | 临界区 + 每行 `fflush` |
| `SafeReadable` | 335–343 | 页级可读性检查（`VirtualQuery`） |
| 配置 Win32 适配 | 345–560 | `CfgLogBridge`、`SelfModule`、`DllDir`、`ConfigPath`、`WriteConfigTemplate`、`PollConfig`、`ConfigSnapshot` |
| 游戏结构读取 | 583–931 | `ReadStdString`、`ReadTechKey`、`ReadCandidateCards`、`IsCountryPlayer`、`CountryFromSlot` |
| tech 身份诊断 | 955–1061 | `DumpTechIdentity`、`MaybeDumpTechIdentity` |
| 构建开关 | 1063–1145 | `AR_BUILD_WITH_PROBES` 与三个派生开关 |
| 探针（探针版才编） | 1147–2058 | SEL / C890 / rp / LogCallStack / take-v1（`#if AR_ENABLE_PROBES` 块） |
| 接管 v2 | 2063–2957 | `Tk2ReadCfg`(2193)、`AR_TakeoverV2`(2220)、`InstallTakeoverV2`(2804)、`RemoveTakeoverV2`(2892)、`AR_TakeoverV2Tramp`(2912) |
| AI 路径探针 | 2960–3369 | `AR_PlayerPathProbe`(3037)、`AR_BpTramp`(3278)、`InstallPlayerPathProbe`(3310) |
| 选卡循环探针 | 3371–3618 | `AR_SelBLog`(3422)、`LocateAndPatchSelB`(3547) |
| C890 探针 | 3619–3746 | `C890Log`(3627)、`C890LogSummary`(3738) |
| hookA 记录 | 3805–3890 | `ARLogStartInner`(3805，写环形缓冲)、`ARLogStart`(3877)、`AREntryA`(3885) |
| 主 hook | 3937–4029 | `ARProcessInner`(3993，使用版静默)、`ARProcess`(4023) |
| 版本闸门 + 原子安装 | 4107–4470 | `GameExePath`(4143)、`LogReport`(4151)、`InstallAll`(4241) |
| 导出函数 | 4118–4140 | 6 个 `AutoResearch*` |
| 初始化 | 4652–4767 | `Init()`(4653) |
| `DllMain` | 4769–4821 | ATTACH → `Init()`；DETACH → 汇总 + fclose |

### 2.3 测试文件各测什么

| 文件 | 项数 | 测什么 | 需要游戏 EXE？ |
|---|---:|---|---|
| `config_selftest.cpp` | 144 | `ar_config.h` 纯逻辑（解析 / 语义 / 热重载状态机），内存假文件 | 否 |
| `config_filetest.cpp` | 28 | 真磁盘热重载（`ar_config_win32.h`），**需要可写目录** | 否 |
| `gate_selftest.cpp` | 69 | 版本闸门，假映像 | 否 |
| `gate_realcheck.cpp` | 14 | 版本闸门，真 `stellaris.exe`（当 DATA 加载，不执行） | 是 |
| `anchor_verify.cpp` | 13 | 锚点解析在真 EXE 上得出已知正确答案 | 是 |
| `anchor_perturb_test.cpp` | 18 | 构造「RVA 全变了」的镜像，验证跨版本可解析 | 是（+扰动） |
| `lde_verify.cpp` | 12 | 指令长度解码器，用 `.pdata` 边界当已知答案 | 是 |
| `take_selftest.cpp` | 25 | tech key / 候选卡 / 权重决策的纯逻辑 | 否 |
| `hook_tramp_test.cpp` | 306 | trampoline 仿真 + 源码级防回归断言（含 tie 累加位置） | 否 |
| `shadow_space_test.cpp` | 11 | Win64 shadow space 覆盖（2026-11-16 真机崩溃根因） | 否 |
| `layout_test.cpp` | 19 | `ar_layout.h` 偏移推导，双版本 + 对抗 + 唯一解 | 是 |
| `c890_chain_test.cpp` | 22 | C890 三级定位/推导/校验链 | 是 |
| **合计** | **681** | | |

### 2.4 ⚠️ 文件头 / 注释里有三处过时描述

改代码前先知道这三处，否则会被误导：

**① 文件头把主 hook 写成 `0x425550`，实际是 `0x428EE0`**
```
1: // auto_research.dll — 玩家专属自动科研权重框架 v2
3: // hook FUN_140425550 (0x425550)：自动科研选科技唯一入口      ← 过时
```
运行日志的解析结果是 `main-hook 0x428EE0`（`[install] main-hook hooked at 0x428EE0`）。而同一个文件 3980 行的注释写的是正确的 `0x428EE0`。`0x425550` 这段文字自 2026-10-31 就没再更新。

**② 注释把 `0x428EE0` 叫「hookA」，实际它是主 hook**
```
102: //   hookA (0x428EE0) 是「科技显示名构造器」，每次 UI 刷新都调。   ← 标签错
```
`0x428EE0` 是**主 hook**（科技显示名构造器）。真正的 hookA 是 `0x81C850`（科技定义校验）。4686 行的横幅写对了：`[ON ] observe ... （主 hook 0x428EE0）`。

**③ 文件头的配置语义一行有歧义**
```
10: //   tech = < 0     不选；仅当没有 > 0 的候选时，在 < 0 里取绝对值最大（最小者）
```
「绝对值最大（最小者）」这个括注容易被读成「取最小」= 取最负。**实际语义是取数值最大、最接近 0 的那个**（`-1` 优于 `-1000`），`ar_config.h:391-395` 与 `config_selftest.cpp:307-340` 都是这个语义（断言名就叫「全负 → 取数值最大（最接近 0）」「-1 优于 -1000」）。

⇒ 读语义以 `ar_config.h` 和测试为准，**不要以 `auto_research.cpp` 文件头的注释为准**。

---

## 3. 三个构建开关

都在 `auto_research.cpp` 里，用 `#ifndef` 给默认值，所以命令行 `-D` 覆盖优先。

### 3.1 `AR_BUILD_WITH_PROBES` —— 版本总开关

```c
#ifndef AR_BUILD_WITH_PROBES
#define AR_BUILD_WITH_PROBES 1     // 默认维护版
#endif
```

| 值 | 产物 | 派生的子开关 |
|---|---|---|
| `1`（默认） | 维护版 848,758 B | `AR_ENABLE_PROBES=1`、`AR_ENABLE_RP_PROBE=1`、`AR_ENABLE_BP_PROBE=0` |
| `0` | 使用版 828,061 B | 三者全 0 |

⚠️ **它不能包住整个接管块**。源码 2060-2063 有明确记录：
```c
#endif  // AR_ENABLE_PROBES（C890/SEL/take 到此为止）
// ★ 2026-11-18：不能用 #if 包整块（会误伤接管核心：AR_TakeoverV2 / trampoline / InstallTakeoverV2）
//   改为「常驻 + 运行时跳过安装」：使用版不调用探针安装函数，
//   但代码仍在（不影响接管）。代价是二进制含探针字符串。
#if 1
```
⇒ 使用版里**仍有探针的格式字符串**（`strings` 能搜到 `[selB]` / `[bp]` 等）。这不影响功能，但会让人误以为探针在用。

### 3.2 `AR_TAKEOVER_V2_DRYRUN` —— 真接管开关

```c
#ifndef AR_TAKEOVER_V2_DRYRUN
#define AR_TAKEOVER_V2_DRYRUN 0     // 0 = LIVE 真接管（当前）
#endif
```

| 值 | 行为 |
|---|---|
| `0`（当前） | 决策结果真的写给游戏（`return chosen`） |
| `1` | 只记录，`return gamePick` 恒不干预 |

DRY-RUN 分支在 2742-2769，LIVE 分支在 2770-2798 —— 两套日志代码，**只有 LIVE 分支会真正返回 `chosen`**。

### 3.3 `AR_ENABLE_BP_PROBE` —— AI 路径探针

```c
#ifndef AR_ENABLE_BP_PROBE
#define AR_ENABLE_BP_PROBE 0     // 两版都关
#endif
```

目标 `0xBBC3E7`（AI 路径的 `call 0x820B30`）。已确认 347/347 条 `c314c=0`，对玩家零影响，继续装只刷日志 + 吃性能（每秒约 3 次调用）。源码保留是因为「将来要让 AI 也用配置」这里是接入点。

配套的旧开关名 `AR_TAKEOVER_BP_DRYRUN` 仍存在（2171-2173），值是 `1`，但引用处已不依赖它。

### 3.4 另外两个（非构建开关）

| 名字 | 位置 | 作用 |
|---|---|---|
| `AR_ONLY_MAIN_HOOK` | 4333 | 二分排障：只装主 hook，完全不 patch hookA |
| `AR_ENABLE_PROBES` / `AR_ENABLE_RP_PROBE` | 1112–1145 | 由 `AR_BUILD_WITH_PROBES` 派生；可单独 `-D` 覆盖 |

---

## 4. 技术核心

### 4.1 接管点

```
patch 位置:  EXE RVA 0x6F334E，9 字节
原字节:      48 8B F0   mov rsi,rax
             48 8B 10   mov rdx,[rax]
             48 8B C8   mov rcx,rax
替换为:      E9 rel32 + 4×NOP  →  nearby 桩（FF 25 disp32）  →  AR_TakeoverV2Tramp（DLL 内）

跳回:        0x6F3357  正常（补执行上述 3 条 MOV 后继续，进入虚函数有效性检查）
             0x6F3369  跳过（不装槽，直接 INC R14D 进入下一领域）
```

实测验证（运行日志）：
```
[tk2] take v2 INSTALLED at 0x7FF65ED9334E near=0x7FF65E690000 backN=0x7FF65ED93357 backS=0x7FF65ED93369
```
其中 `0x7FF65ED9334E - 0x7FF65E6A0000`（日志行的 `base`）= `0x6F334E` ✓，`backN`/`backS` 也逐一对上。

⚠️ 这行文案写的是 "take v2"，但地址是 v3 的玩家路径。**文案不准，不要以它判断版本。**

### 4.2 玩家判据

```c
// 游戏 is_human @ 0xD18175（逐字节）
is_human = (country[+0x314C] != 0) AND (byte[0x281B833] == 0)
```

实现 `IsCountryPlayer`（896–905）：

```c
static bool IsCountryPlayer(void* country) {
    if (!country) return false;
    if (!SafeReadable((uint8_t*)country + 0x314C, 4)) return false;
    if (*(volatile int32_t*)((uint8_t*)country + 0x314C) == 0) return false;
    if (!g_base) return false;
    if (!SafeReadable((void*)(uintptr_t)(g_base + 0x281B833), 1)) return false;
    return *(volatile uint8_t*)(uintptr_t)(g_base + 0x281B833) == 0;
}
```

**保留 `g833` 条件不简化**的理由（源码 867-870）：它是游戏原判据的一部分；多人 / observer / 异步存档下可能非 0，简化版会误判为玩家；代价是读一个字节。

单人游戏下 `g833` 恒 0（实测 238/238），所以等价于单条件。

**调用方必须传当次的 `country`**，不允许传全局缓存 —— 这是 2026-11-15 修过的时序 bug（见 `IsPlayerContext` 的 deprecated 注释）。

### 4.3 数据结构

```
country 数组基址   = BASE + cid × 0x37B8      （实测 18/18 + 17/17，零例外）
cid                = [country+0x20] & 0xFFFFFF （源码 3078）

slotmgr            = country + 0x1620          （实测 232/232 + 21/21，零例外；源码 2225）

候选槽             = slotmgr + (area+11) × 0x18 （源码 2269）
  +0x08            = tech 指针数组（void**）
  +0x14            = count（int32）

tech key           = tech + 0x20 的 MSVC std::string
                     +0x10 size  +0x18 cap   （cap > 15 → 堆指针，否则内联 SSO）

自动科研开关       = [slotmgr+0x08] 的 bit0/1/2（物理/社会/工程）
                     清 bit 会让该领域本 tick 跳过（源码 2536-2538）
```

⚠️ 本版本已**不再使用全局哨兵值**做判定 —— 「是否真选卡」靠成员判据 `gamePick ∈ arr[0..cnt-1]`（源码 2304-2330 明确写了「这比哨兵比较更本质：不依赖任何全局值」）。`[base+0x311BF18]` 只剩 AI 路径探针里的诊断读取（3105-3106），使用版不编译那段。

`area` 取值 `0/1/2`。展开后：

| area | count 位置 | 数组位置 |
|---|---|---|
| 0 物理 | `slotmgr+0x11C` | `slotmgr+0x110` |
| 1 社会 | `slotmgr+0x134` | `slotmgr+0x128` |
| 2 工程 | `slotmgr+0x14C` | `slotmgr+0x140` |

⚠️ **两套 key 偏移并存，不要混用**：

| 用途 | 偏移 | 实测成功率 |
|---|---|---|
| 候选数组元素（接管决策用） | `tech+0x20`（size `+0x10` / cap `+0x18`） | 455/455 = 100% |
| hookA 的 `param_2`（诊断用） | `tech+0x350`（buf `+0x360` / size `+0x370` / cap `+0x378`） | 0/9,571 = 0% |

第二套读不出是**必然的**：hookA 的 `param_2` 与候选数组元素不是同一类对象。详见 `LOG_AUDIT_usage_version.md §1.4`。

### 4.4 三条早退路径

`0x820B30` 有 3 条分支直接跳 `0x820ED6`，完全绕过 `0x820ED2` 的 `MOV R12,[RAX+RCX*8]`：

```
0x820D0D  JNE 0x820ED6   （虚函数 [RAX+8] 返回 true）
0x820D72  JNE 0x820ED6   （[obj+0x9B1] != 0）
0x820D96  JE  0x820ED6   （count == 0）
```

⇒ 早退时返回值是未初始化的 R12。这就是「成员判据 `gamePick ∈ arr[0..cnt-1]`」存在的理由 —— 比比较哨兵值更本质，不依赖任何全局。

### 4.5 trampoline 的栈与寄存器契约

```
进入 rsp%16 = 0     （0x6F2590 prologue: 7 push + sub 0x220）
7 push (56 B)       → rsp%16 = 8
sub $0x28 (40 B)    → rsp%16 = 0   ✓ 可以 call
call AR_TakeoverV2
add $0x28
7 pop               → 回到 0
```

参数：`rcx = country`（原 `rbx`，未被 push）、`rdx = area`（原 `r14d`）、`r8 = gamePick`（从全局读回）。

**返回值的正确写法**（源码 2945-2953）：
```asm
pop %rax                              # 恢复成原 gamePick（不是我们要的）
mov g_tk2Result(%rip), %rax           # 从全局读回真正的 chosen
test %rax, %rax
je 1f                                 # nullptr → 走跳过路径
mov %rax, %rsi
mov (%rax), %rdx
mov %rax, %rcx
jmp *g_tk2BackN(%rip)                 # → 0x6F3357
1:
jmp *g_tk2BackS(%rip)                 # → 0x6F3369
```

⚠️ 两个曾经踩过的点：
1. `sub $0x20` → `(0-56-32)%16 = 8`，`call` 时栈未对齐 → 崩。
2. 从 `[rsp+0x30]` 读 gamePick 读到的是 `r9` 不是 `rax` → 改成走全局，彻底不依赖栈偏移。

### 4.6 nearby 桩

`E9 rel32` 只能跳 ±2 GB，而 EXE 与 DLL 相距约 137 TB。所以必须两段跳：

```
0x6F334E: E9 rel32  →  nearby 桩（VirtualAlloc 在 0x6F334E 附近 2 GB 内）
nearby 桩: FF 25 disp32  →  绝对地址（AR_TakeoverV2Tramp 在 DLL 内）
```

桩的内容来自常量 `0x90900000000225ff`，小端展开 = `FF 25 02 00 00 00 90 90`：
- `FF 25 disp32` = `jmp qword ptr [rip+disp32]`，**零寄存器副作用**
- `disp32 = +2`，`FF25` 指令 6 字节 → `RIP = N+6` → 目标 `N+8`，那里放 8 字节绝对地址

**绝对不能用 `mov rax, imm64; jmp rax`** —— 会破坏 `RAX`，而 `RAX` 就是 `gamePick`。这条踩过（见 `auto_research.cpp:2831`）。

### 4.7 两次调用路径的分工

```
玩家（cid=0，+0x314C != 0） → 0x6F2590 → 0x6F334E → 0x820B30
AI  （cid=1..N，+0x314C==0） → 0xBBC300 → 0xBBC3E7 → 0x820B30
```

两条路共用同一个选卡器 `0x820B30`。本 DLL 只 patch 玩家路径。

`0x6F2590` 的入口守卫与 `is_human` 同构（`0x6F32D0 CMP [RBX+0x314C],0` / `0x6F32D7 JE ret`），所以能走到 `0x6F334E` 的本质上是玩家 —— `AR_TakeoverV2` 里的 `IsCountryPlayer` 是二重保险，不是唯一防线。

---

## 5. 数据流：一次决策发生了什么

```
每日 tick
 └─ 0x25C850 DailyUpdate
     └─ 0x6F2590 country 更新（只处理 is_human 成立的国家）
         ├─ 0x6F32F2  CALL 0x81E790             虚函数检查
         ├─ 0x6F3326  读 [slotmgr+0x08] bit(area)  自动科研开关
         ├─ 0x6F332C  JE 0x6F3369               未开 → 跳过该领域
         ├─ 0x6F3349  CALL 0x820B30             ★ 选卡器 → RAX = gamePick
         ├─ 0x6F334E  ★★★ 本 DLL 的 patch 点 ★★★
         │     └─ AR_TakeoverV2(country, area, gamePick)
         │          ├─ PollConfig()              热重载（mtime + size）
         │          ├─ IsCountryPlayer(country)  不是玩家 → return gamePick
         │          ├─ cfg.mode != Take          → return gamePick
         │          ├─ slot = slotmgr + (area+11)*0x18
         │          ├─ arr = [slot+0x08], cnt = [slot+0x14]
         │          ├─ 再读一次 arr/cnt，不一致 → return gamePick（防重建中间态）
         │          ├─ gamePick ∈ arr[0..cnt-1]？否 → return gamePick（早退）
         │          ├─ 逐候选 Tk2ReadCfg → 权重
         │          ├─ 分类：>0 取最大（并列随机）/ <0 取数值最大（并列随机）
         │          ├─ 全 0 → 清 [slotmgr+0x08] bit(area)，return nullptr
         │          └─ 否则 → return chosen
         ├─ 0x6F3357  CALL [RDX+8]              tech 有效性（vtable[1]）
         ├─ 0x6F3364  CALL 0x81D000             装进研究槽
         └─ 0x6F3369  INC R14D                  下一领域（0→1→2）
```

`return nullptr` 是安全的，因为 trampoline 有 null 检查并跳 `0x6F3369`（跳过装槽）。这一点曾被错误地认为「需要额外 patch 消费路径」，实际不需要 —— 见 `PHASE1_COMPLETE.md §3.1` 的更正。

---

## 6. 配置语义在哪、怎么改

### 6.1 语义有两处实现，**必须同步**

| 位置 | 用途 |
|---|---|
| `ar_config.h` 的 `PickBest`（397–439） | 纯逻辑真值来源，供测试和前端复刻 |
| `auto_research.cpp` 的 `AR_TakeoverV2`（2395–2522） | DLL 实际运行的决策 |

两者目前语义一致（`>0` 取最大 / `0` 跳过 / `<0` 取数值最大 / 都无 → Stop），但 DLL 那份额外带**并列随机**（`pickRandomTieIdx`），而 `PickBest` 是「并列取列表靠前者」（确定性，便于测试复现）。

⚠️ **改语义必须两处一起改，否则测试仍然全绿但运行时行为已变。** 这是这一节最需要注意的事。

### 6.2 改语义的步骤

1. 改 `ar_config.h::PickBest` + 注释里的规范描述（1–22 行是「唯一规范」的正文）
2. 改 `auto_research.cpp::AR_TakeoverV2` 的分类与选择逻辑
3. 改 `config_selftest.cpp` 的对应断言（4.x 段）
4. 改 `hook_tramp_test.cpp` 的源码级断言（如果涉及代码位置关系）
5. 跑 681 项
6. 同步 `CONFIG_FORMAT.md` 与根目录 `README.md` 的语义表

### 6.3 数值解析规则（`ParseInt`，116–133）

```
接受: "0"  "-5"  "+7"  "100000"
拒绝: ""  "1.5"  "12abc"  "0x10"  "1 000"  "soft"  "ban"  "99999999999999999999"（溢出）
```
`soft` / `ban` 已彻底删除，不再是特殊值。任何非十进制整数的值都是无效行，记日志后忽略（不猜测映射成某个数字）—— 见 `ar_config.h:224-228`。

### 6.4 热重载状态机

`Watcher::Poll` 用 `(是否存在, 写时间戳, 文件大小)` 三元组：

| 前态 → 后态 | 结果 | 日志 |
|---|---|---|
| 三元组全不变 | `NoChange` | 无（不刷屏） |
| 时间戳或大小变了 | `Reloaded` | `[cfg] reloaded: ...` |
| 存在 → 不存在 | `Cleared` | `file not found -> config cleared` |
| 存在但读不到（权限/独占/是目录） | `ReadFailed` | `unreadable -> config cleared` |
| 不存在 → 重新出现（哪怕旧时间戳） | `Reloaded` | `[cfg] reloaded: ...` |

三个关键点：
1. 「删文件」和「时间戳没变」是两种不同状态，不会混淆。
2. **重载是整份替换，不是合并** —— 删掉一行，那条权重立刻回到 `@default`。
3. 读失败也是清空，不是沿用上次成功的配置。

`PollConfig()` 的调用点：`ARProcessInner`（3994，主 hook 每次）、`ARLogInner`（4054）、`Init`（4719、4762）。所以热重载的粒度是「每次主 hook 调用」，不是定时器。

### 6.5 配置模板自动创建

`WriteConfigTemplate`（432–493）在 `PollResult::Cleared` 且 `static` 标志未置位时触发一次，写完 `g_watcher.Reset()` 让下次必重载。

模板里 `@mode = observe`、所有 tech 条目都是注释 ⇒ 自动创建**不可能**意外改变游戏行为。这个设计是有意的（源码 424-431 有记录）。

放在 `PollConfig` 里而不是 `DllMain` 的原因：`DllMain` 在加载器锁下不能做文件 I/O。

---

## 7. 怎么加日志

### 7.1 三条硬规则

1. **必须限流。** 无限流的新日志会重演 `[hookA]` 的 9,571 行 / 82 秒。现成的限流写法：
   ```c
   static volatile LONG s_cnt = 0;
   const LONG n = InterlockedIncrement(&s_cnt);
   if (n <= 20 || (n % 100) == 0) { Log("..."); }
   ```
   参考 `[tak-SKIP]`（2320-2324）、`[tk2] arr/cnt`（2293-2298）、`[tak-DBG]`（2339）。

2. **关键动作全记，次要动作限流。** 现在的分级：
   | 类别 | 策略 | 例 |
   |---|---|---|
   | 接管 / 全禁 | 全记 | `[PICK]` 的 `接管*` / `★全禁→停研究` |
   | 不干预 | 前 50 + 每 20 | `[PICK]` 的 `不干预*` |
   | 无候选 | 前 10 + 每 500 | `[PICK] 候选=[]` |
   | 早退 / 诊断 | 前 20 + 每 100 | `[tak-SKIP]`、`[tk2]` |
   | 一次性诊断 | 前 5 + 形态变化，上限 10 | `[dump]` |

3. **中文输出走 `ArAreaZh` / `ArActionZh` 这类映射函数，不要在 `Log()` 里手写中文分支。**
   `ArActionZh`（58–71）对未知 verdict 直接返回原文 —— 加新 verdict 时记得在这里补一行，否则日志里会冒出英文枚举名。

### 7.2 加一条日志的完整步骤

1. 选好位置。**决策类**日志加在 `AR_TakeoverV2` 内 `verdict` 确定之后；**诊断类**加在读取数据之后。
2. 用 `%s` 配 `ArAreaZh(area)`，不要打裸 `area=0`。
3. 加限流计数器（`static volatile LONG` + `InterlockedIncrement`）。
4. 如果涉及**代码位置不变性**（比如「A 必须在 B 之前」），去 `hook_tramp_test.cpp` 加一条源码断言。写法：
   ```c
   const size_t a = s.find("标记 A");
   const size_t b = s.find("标记 B");
   Check(a != std::string::npos && b != std::string::npos && a < b, "A 在 B 之前");
   ```
   现成例子：1364-1386 的 tie 累加位置断言。
5. 跑 681 项。
6. 更新根目录 `README.md` 的日志字段表。

### 7.3 使用版 / 维护版分流

想让日志只在维护版出现：
```c
#if AR_BUILD_WITH_PROBES
    Log("[your-tag] ...");
#endif
```
⚠️ **注意一个现存问题**：`[tak-DBG]`、`[tak-SKIP]`、`[disp]` 三个**没有**被 `#if AR_BUILD_WITH_PROBES` 包住（它们在 2063 的 `#if 1` 块里），而横幅（4692-4698）却把它们标成 `[OFF]`。实测使用版一局仍有 `[tak-DBG]` 21 条、`[tak-SKIP]` 1 条、`[disp]` 1 条。

新加日志时不要复制这个模式。要么真包在 `#if` 里，要么横幅写 `[ON ]`。

### 7.4 日志本身的开销

`Log()`（326–333）每行都 `fputc('\n')` + `fflush()`，并且进出临界区。所以**行数就是性能成本**，不只是磁盘占用。9,571 行 = 9,571 次 flush，在 82 秒内完成。

大流量的东西应该走 `RingPush`（122–137）：只写内存，200 条 × 160 B = 32 KB，崩溃时 `RingDump` 一次性导出。

---

## 8. 已知风险

### R1 patch 写入无线程挂起

**现象**：`0x6F334E` 的 9 字节用一次 `memcpy` 写入，期间不挂起其他线程。

**实际风险：极低**。9 字节连续写入约 10–20 ns；该窗口内其他线程恰好取指到 `0x6F334E..0x6F3356` 的概率极低；且 patch 在独立线程（`ARENTRY`）里执行。

**为什么不修**（`PHASE1_COMPLETE.md §R1` 的三方案对比）：
| 方案 | 成本 | 效果 | 结论 |
|---|---|---|---|
| `SuspendThread` 枚举线程 | ~80 行 | `SuspendThread` 自身也有竞态 | 成本高，收益不确定 |
| 先 `int3` 后 NOP | ~15 行 | **更差** —— 执行到 `0x6F3351..0x6F3356` 会立刻 int3 崩 | 不采纳 |
| 接受 + 文档标注 | 0 | — | **采纳** |

**缓解**：在游戏主菜单时注入（此时科研 tick 未启动）。

### R2 热替换 / 热卸载 DLL 必崩

**现象**：`RemoveTakeoverV2` 等卸载函数在 `AR_ENABLE_PROBES=0` 时被预处理掉。

**已实测确认**：字符串 `take v2 removed`（该函数最后一句）在使用版 DLL 里**命中 0 次**，在维护版里**命中**。`DllMain` 的 DETACH 分支里所有 `Remove*` 调用都在 `#if AR_ENABLE_PROBES` 内（4773–4783）。

⇒ **运行中 `FreeLibrary` 会崩，因为 patch 的 9 字节永远不会被还原。**

**当前不触发**：注入器只 load 不 unload（`stellaris_mod_injector.ini` 只有 `delay_ms` / `probe`，日志里无 unload 记录）。

**规矩**：关游戏 → 换 DLL → 开游戏。这条同时写在横幅（4710-4713）和 `Init` 里。

### R3 `SafeReadable` 页级 TOCTOU

**现象**：`SafeReadable`（335–343）只验「该页 `MEM_COMMIT` 且不是 `PAGE_NOACCESS`/`PAGE_GUARD` 且区间在同一 region」，**挡不住「页面还在但对象已释放」**。

**已有四层防护**：
1. 读 `arr`/`cnt` 后再读一次，不一致就 bail（2278–2301）
2. `SafeReadable(arr, cnt*8)` 验数组整体
3. 每个 `arr[i]` 非空 + `Tk2ReadCfg` 四层校验（size / cap / 字符白名单）
4. 选中对象二次 `SafeReadable(chosen, 8)`（2625–2629）

**剩余风险**：两次检查之间被 `realloc`（微秒级窗口，且游戏主逻辑单线程）。这是所有用户态指针校验的固有限制。

### R4 DLL 内 RVA 随源码漂移

**现象**：`AR_TakeoverV2Tramp` / `AR_TakeoverV2` / `AR_PlayerPathProbe` 在 DLL 内的 RVA 是**每个构建各自的值**，源码一改就变。

**历史教训**：某些旧报告写 `AR_TakeoverV2 = 0x5350`。核实后 `0x5350` 落在另一个函数（`0x52C0..0x56BE`）的指令中间，甚至不是指令边界 —— 以它为基址的所有偏移推算全部作废。正确的权威值（当时那版构建）是 `0x4C50`，长度 `0x666`。

**结论**：**不要硬编码 DLL 内 RVA**。要用就在构建后重新核实（`.pdata` 边界 + 符号表双重核对）。

### R5 MinGW 构建不可复现

**实测**：从 `release_v1/src` 重建，大小 828,061 / 848,758 B 与发布版**逐字节相同大小**，SHA256 完全不同。

⇒ SHA256 不能用来判断「是不是同一个版本」。用功能指纹：
```
日志 banner 的 build 行    │ take-v3 LIVE-PLAYER / AR_TAKEOVER_V2_DRYRUN=0
关键格式串是否存在         │ [PICK] 领域= / [汇总] / [tk2] take v2 INSTALLED
导出函数是否存在           │ AutoResearchGetState 等 6 个
```

⚠️ **`Init` 的横幅有 1 处已知不准**：它打印 `build : 2026-11-18 take-v3`，但 2026-11-20 的改动（中文日志 / 环形缓冲 / VEH / 模板）没有更新这个字符串。所以横幅日期 ≠ 实际构建日期。判断版本时要看**功能串**，不看日期。

---

## 9. 真实踩过的坑

### 坑 1：`GetModuleFileNameA(nullptr, ...)` 返回 exe 目录，不是 DLL 目录

`nullptr` 表示「调用进程的主模块」= `stellaris.exe`。

实测后果：日志被写到 `E:\...\Stellaris\auto_research.log`，而不是 `E:\...\Stellaris\injected_mods\auto_research\auto_research.log`。

修法（`auto_research.cpp:391-398`）：
```c
static HMODULE SelfModule() {
    HMODULE h = nullptr;
    GetModuleHandleExA(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCSTR)(const void*)&SelfModule,      // 用「函数地址」反查它所在的模块
        &h);
    return h;
}
```
优点：不依赖 `DllMain` 的 `hInstance`，任何时候都能调。

**验证**：运行日志第 6/8 行的 config / log 路径现在都在 `injected_mods\auto_research\` 下。

### 坑 2：Windows 异常码是**三段**，不是两段

```
< 0xC0000000                调试/警告    0x40010006 DBG_PRINTEXCEPTION_C
                                          0x406D1388 线程命名
[0xC0000000, 0xD0000000)    ★ 真硬件异常 0xC0000005 AV
                                          0xC000001D ILLEGAL_INSTRUCTION
                                          0xC00000FD STACK_OVERFLOW
                                          0xC0000409 __fastfail
                                          0xC0000374 HEAP_CORRUPTION
>= 0xD0000000               用户自定义   0xE06D7363 MSVC C++ EH
                                          0xE0434352 .NET CLR
```

**只判下界会怎样**：`0xE06D7363` = 3,766,556,003 > `0xC0000000`，被误判为硬件异常 → 走完整 CRASH 块 → **实测误报 8 次**。

正确判据（`auto_research.cpp:231`）：
```c
if (code < 0xC0000000u || code >= 0xD0000000u) { /* 软件异常，一码只记一次 */ }
```

**改前实测代价**：71 个崩溃块里真异常 0 个，全是 `0x40010006`（66 次）/ `0xE06D7363`（4 次）/ `0x406D1388`（1 次），且 71/71 都打印「请把这段发给开发者」—— 主动制造假工单。

### 坑 3：`tie` 累加块的大括号位置错了 → 计数器永远是 0

**现象**：`[汇总] 并列=0`，但 `[PICK]` 里 260 条「接管（并列随机）」。

**根因**：累加代码被错放进 `if (chosen && chosen != gamePick && !SafeReadable(chosen, 8))` 分支内部，而那个分支只在「对象不可读」时执行（极罕见）。正常接管路径根本走不到。

**修法**：移到**所有决策分支之后、UNREADABLE 检查之前**，不在任何条件分支内部（`auto_research.cpp:2579-2614`）。

**防回归**（`hook_tramp_test.cpp:1364-1386`）—— 位置关系断言，不是数值断言：
```c
const size_t tieInc = s.find("InterlockedIncrement(&s_tieTotal)");
const size_t unread = s.find("!SafeReadable(chosen, 8)");
Check(tieInc != npos && unread != npos && tieInc < unread,
      "并列累加在 UNREADABLE 检查之前（在所有决策分支之后）");
```

**验证**：一局 153 次决策，`并列=152`（不再是 0），`撞上原选=36`（23.7%，理论 1/N ≈ 25~33%）。

### 坑 4：MinGW 的 `.data` 段每次不同

`release_v1/src/build.sh` 头注释就写着这条。实测：同源码、同编译器、同参数 → 同大小、不同 SHA256。

**推论**：
- 不能用 SHA256 判断「部署的是不是构建出来的那一份」
- 交接/验收里「SHA256 不一致 ⇒ 部署错了」这类结论**必须**配合大小 + 功能指纹一起看，否则会误判（项目历史上确实发生过 —— `AUDIT_DLL_TK2V3.md` 记录过审查对象与任务描述不符的实例）

### 坑 5：配置文件名是硬编码的单一路径

`ConfigPath()`（413–417）= `DllDir() + "\\auto_research_weights.txt"`。**没有环境变量、没有命令行参数、没有多文件支持。**

推论：目录里放多个配置文件不会互相干扰，但也不会被读。想切换配置只能改文件内容（或用 `Copy-Item` 覆盖）。

### 坑 6：`0x820B30` 的返回值有 3 条早退路径

见 [§4.4](#44-三条早退路径)。曾经的错误假设是「`R12` 总会在 `0x820ED2` 被赋值」，实际有 3 条分支绕过它。

**教训**：判「返回值是否可信」不能只读正常路径，要穷举所有 `jcc` 目标。

### 坑 7：`isai` 这个变量名骗了所有人

`isai` 日志字段装的是 `[country+0x314C]` 的**原始值**，而它的语义是 `is_human` 的**必要条件**（1 = 人类）。名字与实际含义相反。

误读这个名字直接导致了「去找另一条玩家路径」的整段弯路（2026-11-16 至 11-17），事后确认 `0x6F334E` 一开始就是对的。

**副作用（读历史日志必看）**：修复前判据是反的，旧日志里 `ai-by-current-slot` 多半其实是玩家，`PLAYER-by-current-slot` 其实是 AI。

---

## 10. 测试

### 10.1 681 项，12 个套件

```bash
cd release_v1/src
KEY="E:/Steam/steamapps/common/Stellaris/stellaris.exe"
TMP=/d/tmp TMPDIR=/d/tmp TEMP=/d/tmp     # 若 %TEMP% 不可写
GXX=g++

$GXX -std=c++17 -O2 -static -o config_selftest.exe   config_selftest.cpp
$GXX -std=c++17 -O2 -static -o config_filetest.exe   config_filetest.cpp -lkernel32
$GXX -std=c++17 -O2 -static -o gate_selftest.exe     gate_selftest.cpp
$GXX -std=c++17 -O2 -static -o gate_realcheck.exe    gate_realcheck.cpp -lkernel32 -lbcrypt
$GXX -std=c++17 -O2 -static -o anchor_verify.exe     anchor_verify.cpp
$GXX -std=c++17 -O2 -static -o anchor_perturb_test.exe anchor_perturb_test.cpp
$GXX -std=c++17 -O2 -static -o lde_verify.exe        lde_verify.cpp
$GXX -std=c++17 -O2 -static -o take_selftest.exe     take_selftest.cpp
$GXX -std=c++17 -O2 -static -o hook_tramp_test.exe   hook_tramp_test.cpp
$GXX -std=c++17 -O2 -static -o shadow_space_test.exe shadow_space_test.cpp
$GXX -std=c++17 -O2 -static -o layout_test.exe       layout_test.cpp
$GXX -std=c++17 -O2 -static -o c890_chain_test.exe   c890_chain_test.cpp
```

跑：

```bash
./config_selftest.exe
./config_filetest.exe --dir /d/tmp/ar_cfg   # ★ 必须给 --dir（见 §1.5）
./gate_selftest.exe
./gate_realcheck.exe   "$KEY"               # 省略则默认 E:/Steam/.../stellaris.exe
./anchor_verify.exe
./anchor_perturb_test.exe
./lde_verify.exe
./take_selftest.exe
./hook_tramp_test.exe
./shadow_space_test.exe
./layout_test.exe
./c890_chain_test.exe
```

### 10.2 基线（2026-11-20 实测）

| 套件 | 结果 | exit |
|---|---|---:|
| config_selftest | 144 passed, 0 failed | 0 |
| config_filetest (`--dir` 可写) | 28 passed, 0 failed | 0 |
| gate_selftest | 69 passed, 0 failed | 0 |
| gate_realcheck | 14 passed, 0 failed | 0 |
| anchor_verify | 13 passed, 0 failed | 0 |
| anchor_perturb_test | 18 passed, 0 failed | 0 |
| lde_verify | 12 passed, 0 failed | 0 |
| take_selftest | 25 passed, 0 failed | 0 |
| hook_tramp_test | 306 passed, 0 failed | 0 |
| shadow_space_test | 11 passed, 0 failed | 0 |
| layout_test | 19 passed, 0 failed | 0 |
| c890_chain_test | 22 passed, 0 failed | 0 |
| **合计** | **681 passed, 0 failed** | |

需要游戏 EXE 的 4 个（`gate_realcheck` / `anchor_verify` / `anchor_perturb_test` / `lde_verify`）加 `layout_test`、`c890_chain_test` 共 6 个会在 exe 缺失时失败。这些测试只把 exe 当 **DATA 加载，不执行游戏**，所以可以开着别的程序跑。

### 10.3 负向验证（必做）

断言全绿不等于断言有效。改完关键逻辑后，手工把逻辑改坏一次，确认测试会响，再改回来：

| 破坏方式 | 应该看到 |
|---|---|
| `if (InstallC890Probe(...))` → `if (false)` | `[FAIL] InstallC890Probe 被实际调用（不是只声明）` |
| 桩内插入 `sub $8, %rsp` | `[FAIL] 桩内无 sub $8（7 push 后已 16 字节对齐）` |
| 把 tie 累加块移回 UNREADABLE 分支内 | `[FAIL] 并列累加在 UNREADABLE 检查之前` |
| 把 `sub $0x28` 改回 `sub $0x20` | trampoline 栈对齐断言失败 |

历史记录：这四类负向验证都实际做过，且都正确捕获。

### 10.4 游戏内验证（离线测试替代不了）

681 项全是离线测试，**不证明游戏里不崩**。真机验收看这三行：

```bash
# 1. 装上了吗
grep "FINAL STATE" auto_research.log
#    期望：fully-installed（或 anchor-verified 路径下的 fully-installed）

# 2. 接管在跑吗
grep -c "动作=接管" auto_research.log
#    期望：> 0；一局 153 次决策的实测是 116

# 3. 有没有崩
grep -c "!!! CRASH" auto_research.log
#    期望：0
```

再跑一次汇总：
```bash
tail -2 auto_research.log
# [汇总] 总决策=153 真选卡=153 早退=0 玩家=153 AI=0 | 并列=152 撞上原选=36 | [PICK] 接管=116 保留=37
# === detach ===
```
`AI=0` 是玩家判据有效的直接证据 —— 这条数字比任何静态分析都硬。

---

## 11. 跨版本适配

游戏更新后接管点 RVA 会变。设计上有四层防线，按抗漂移能力排序：

| # | 层 | 用途 | 实现 |
|---|---|---|---|
| 1 | 字符串锚点（2 条互证） | **主定位 hookA** | `ar_anchor.h` + `ar_lde.h`（找 rip 相对引用） |
| 2 | 调用链 + 稀有 callee 指纹 | **主定位主 hook** | `ar_resolve.h`（SEL=1, GETC=1） |
| 3 | 长特征码 24–56 B | 只做**校验**，不做定位 | `ar_version.h::Target::expect` + `funcLen` |
| 4 | SHA256 / buildId 白名单 | 显式**兜底** | `ar_gate.h` + `ar_version.h::kKnownBuilds` |

第 3 层「只校验不定位」是有意的：原函数 15 字节序言在 `.text` 里出现 2,572 次，拿它定位必然错。

运行日志展示这套机制实际在工作：
```
[resolve]   "MESSAGE_TECHNOLOGY_RESEARCH_FINISH" @0x23A33E8 -> 1 func(s) (unique)
[resolve]   "TECHNOLOGY_ORDER_FINISH_MESSAGE_TYPE" @0x23A3410 -> 1 func(s) (unique)
[resolve]   hook-a makes 21 direct calls
[resolve]   length-filtered candidates: 5
[resolve]     candidate 0x7415F0 len=1453 : fingerprint mismatch
[resolve]     candidate 0x428EE0 len=1294 : SEL=1 GETC=1 OK
[resolve]   unique candidate 0x428EE0
[resolve] verdict = anchor-verified
```

### 换游戏版本的操作顺序

1. 跑 `node gen_version_h.js "<新exe>"` → 重新生成 `ar_version.h`
2. 编译 `anchor_verify.exe` / `anchor_perturb_test.exe` / `lde_verify.exe` / `layout_test.exe` / `c890_chain_test.exe` 并跑，确认锚点解析在新 exe 上仍然唯一命中
3. **重新定位接管点**。`0x6F334E` 的 9 字节 pattern `48 8B F0 48 8B 10 48 8B C8` 在 `0x6F3300..0x6F3400` 窗口内搜索（`InstallTakeoverV2`，2804–2821）。窗口是硬编码的，跨版本可能失效 —— 见下。
4. 重新核对数据偏移：`country+0x1620` / `country+0x314C` / `slotmgr+(area+11)*0x18` / `tech+0x20`
5. 跑全 681 项 + 真机一局

⚠️ **硬编码残留清单**（跨版本必须先处理这些）：
```
InstallTakeoverV2:  lo = 0x6F3300, hi = 0x6F3400      搜索窗口
                    hit != 0x6F334E                   期望值
                    base + 0x6F3357 / 0x6F3369        两个跳回点
IsCountryPlayer:    country + 0x314C
AR_TakeoverV2:      country + 0x1620
                    0x281B833（g_base 相对）
候选槽:             (area + 11) * 0x18，+0x08 / +0x14
TkReadKey:          tech + 0x20（size +0x10 / cap +0x18）
ReadTechKey:        tech + 0x350（buf +0x360 / size +0x370 / cap +0x378）
自动科研开关:        slotmgr + 0x08 的 bit0/1/2
BK 探针:           0xBBC3E7 / 0xBBC3EC
```

`ar_layout.h` 能自动推导候选槽布局，但**推导结果仍会与 legacy 常量对照告警**（不 fallback），所以换版本后要看日志里那行 `derived ... vs legacy constant ... (match)` 是否还 match。

### 未验证项（如实列出）

- HiDPI / 分辨率对日志无影响（日志是纯文本），但对 UI 无验证
- 多人游戏 / observer 模式下 `byte[0x281B833]` 的实际取值 —— 单人下恒 0（238/238），多人下未知
- AI 路径探针只做过观测（347/347 条 `c314c=0`），未验证「让 AI 也用配置」的可行性
- `arr`/`cnt` 一致性检查能挡住「显著中间态」，但微秒级 TOCTOU 未做专项压测
