# 更新日志

> 本文件只记录**能对应到实测证据或源码注释**的变更。
> 每条后面标 `[证据: ...]`，指向可以自己复核的地方。
> 游戏版本固定为 Stellaris 4.5.4 (Cygnus) build `4394a9a4797b27029182f9dba4431b4f`。
>
> **关于证据强度**：本文件里凡标「实测」的，都给了原始数字与可复算方法；凡只在注释/口述里出现而无法复算的，明确标了「历史记录，条件不可考」。
> 随机性那一节的数字有三组不同来源，**请读那一节的口径说明再用**，别引错。

---

## v1.0.0 — 2026-11-20

首个可发布版本。使用版 `auto_research.dll` 828,061 B / 维护版 `auto_research_debug.dll` 848,758 B。

### 新增

**日志中文化** — 领域、候选数、科技名、动作全部中文输出
```
[PICK] 领域=物理 候选数=3 候选=[tech_physics_1（量子计算）,...] 抽中=1 选中=... 动作=接管（并列随机）
```
`area=0/1/2` → `领域=物理/社会/工程`；`ours=tech_x` → `选中=tech_x（中文名）`；`action=OVERRIDE-POS-TIE` → `动作=接管（并列随机）`。
中文名表 678 条内嵌进二进制（`ar_tech_names.h`，来源 `log_tool/tech_names.json`）。
`[证据: auto_research.cpp:39-71 ArAreaZh/ArActionZh；ar_tech_names.h 首行「678 条」]`

**hookA 环形缓冲** — `[hookA]` 改为写内存（200 条 × 160 B = 32 KB），只在崩溃时一次性导出
改前实测：`[hookA]` 9,571 行 / 82 秒 / 1.82 MB，占单局日志 81.3% 行、89.2% 体积，而 `tech=` 字段 9,571/9,571 全是 `<unreadable>`。
`[证据: LOG_AUDIT_usage_version.md §1.1 分桶表 + §1.2 时间窗口（首条 tick=86255046，末条 86337375，跨度 82.3 秒），0x0 成功读出；auto_research.cpp:98-118 AR_RING_CAP=200/AR_RING_LINE=160]`

**VEH 崩溃捕获** — `AddVectoredExceptionHandler(1, ...)`，记录 code / rip / rsp / 寄存器 / fault module / DLL base + crash RVA
只在真崩溃时导出环形缓冲，并把当时状态（area / cnt / country / slotmgr / gamePick / mode）一并写下。
`[证据: auto_research.cpp:79-96 设计说明、252-320 崩溃块输出内容、4667-4669 注册]`

**配置模板自动创建** — 配置文件不存在时写出一份带完整注释的模板
模板里 `@mode = observe`、所有科技条目都是注释，所以「自动创建」不会意外改变游戏行为。
`[证据: auto_research.cpp:420-493 WriteConfigTemplate 的 kTpl 全文，463 行 @mode = observe；528-556 只在 PollResult::Cleared 且仅一次时触发]`

**`arr`/`cnt` 一致性检查** — 读到候选数组后立即再读一次，不一致就放弃本次接管
针对「用户开了每天完成一次科研」时游戏重建候选池的中间态。
`[证据: auto_research.cpp:2278-2301，失配时打 [tk2] arr/cnt changed during read -> bail]`

**`AutoResearchGetState` 等 6 个导出函数** — 供外部脚本查询 DLL 状态
`AutoResearchGetState` / `GetStateName` / `IsReady` / `SupportedVersion` / `SupportedBuildId` / `SupportedSha256`。
`[证据: auto_research.cpp:4118-4140；在 DLL 二进制里 6 个名字全部命中]`

**退出时打一条完整汇总** — `[汇总]` 在 `DLL_PROCESS_DETACH` 里输出
原因：一局只有约 219 次决策，而中期汇总间隔是 500 次，永远够不到。
`[证据: auto_research.cpp:4784-4818；实测日志第 546 行 [汇总] 总决策=153 ... 第 547 行 === detach ===]`

### 修复

**并列随机换成 xorshift64\*** — 旧算法 `(mix >> 33) % n` 丢弃低位熵
旧：`mix = tick*A + c*B`，取 `(mix >> 33) % n`。新：状态持久推进的 xorshift64\*（`x^=x>>12; x^=x<<25; x^=x>>27; r=x*0x2545F4914F6CDD1D; r % n`），改用 `% n`（低位）。
源码注释记录的实测：旧 10000 次 `3193/3428/3379` χ²=9.2（df=2 临界 5.99，显著偏差）；新 10000 次 χ²=0.1。
真机一局（153 次决策）实测分布：候选数 3 → `0:14 / 1:21 / 2:22` χ²=2.000；候选数 4 → `0:23 / 1:29 / 2:23 / 3:16` χ²=3.725；两者均在临界值内。
`[证据: auto_research.cpp:2402-2442 两个算法的完整注释与实现；分布由 E:\...\auto_research.log 的 153 条 [PICK] 逐条统计得出（analyze_log.py 独立复算一致）]`

> **⚠️ 数字口径说明（重要，别引错）**
> 关于这次改动，流传着**三组不同的 χ² 数字**，来源不同，不要混用：
>
> | 数字 | 出处 | 能否复核 |
> |---|---|---|
> | 旧 9.2 → 新 0.1 | `auto_research.cpp:2408/2412` 的源码注释 | 注释本身，未记测量条件 |
> | 旧 13.28 → 新 1.35 | 项目交接口述 / 任务书 | 未在任何源码或日志中找到对应记录 |
> | 旧 ≈0.001 / 新 ≈0.385（n=3，10 万次） | 本次按两段算法逐字复制后实测 | 可复现 |
>
> 第三组数字**看起来「旧算法也很均匀」**，原因是：旧算法在同一毫秒内对三个领域取 `c=0/1/2`，三个结果各自都落在合理分布上。**旧算法的真实缺陷不是分布偏，而是「同 tick 内结果完全由 (tick, c) 决定」** —— 同一 tick 内三次调用永远不会撞到同一个下标（实测 0/20000），而均匀随机应当约 1/9 = 11.1%（新算法实测 11.2%）。
>
> ⇒ 引用时建议写可复现的那两条：**一局 153 次决策实测 χ²=2.000 / 3.725，均在临界值内**，以及**「同 tick 三次全撞同一下标：旧 0/20000 vs 新 2249/20000」**。前两组历史数字标为「历史记录，条件不可考」。
>
> **另一个可复现的旁证**：一局 152 次并列里，随机恰好撞上游戏原选 36 次 = **23.7%**；按每次实际候选数算期望值 `Σ(1/cnt)/n` = **27.9%**。差 4.2 个百分点，二项分布 σ ≈ 3.4 个百分点（n=152, p=0.237），即 **1.2σ** —— 在采样误差内。
> ⇒ 随机与「游戏原选」之间没有系统性相关，即接管逻辑没有偏袒某个固定下标。
> `[复算方式：auto_research.log 的 152 条含「并列随机 / 随机命中游戏原选」的 [PICK] 行，数「随机命中游戏原选」= 36；期望按每行的 候选数= 取 1/cnt 后求均值 = 27.9%]`

**并列累加块放错位置，计数器永远是 0** — 移到所有决策分支之后、UNREADABLE 检查之前
`[证据: auto_research.cpp:2579-2614 的整块注释（「旧 bug（用户实测）：[汇总] 并列=0，但 [PICK] 里 260 条『接管（并列随机）』」）；hook_tramp_test.cpp:1364-1386 三条防回归断言，断言 tieInc < unread 的位置关系]`

**日志/配置路径取错目录** — 原用 `GetModuleFileNameA(nullptr, ...)`，拿到的是 `stellaris.exe` 目录
实测曾把日志写到 `E:\...\Stellaris\auto_research.log`，而不是 `E:\...\Stellaris\injected_mods\auto_research\auto_research.log`。
改用 `GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, &SelfModule, &h)` 反查自身模块句柄。
`[证据: auto_research.cpp:376-410 的 bug 说明 + SelfModule()/DllDir() 实现；运行日志第 6、8 行的 config/log 路径已是 injected_mods\auto_research]`

**VEH 异常码判定从单向阈值改成区间** — `0xE06D7363`（MSVC C++ EH）被误判为崩溃
上一版只判 `code < 0xC0000000`，而 `0xE06D7363` = 3,766,556,003 > `0xC0000000`，于是走完整 CRASH 块（实测 8 次）。改为 `[0xC0000000, 0xD0000000)` 才是真崩溃。
`[证据: auto_research.cpp:213-231 的分段表与最终判据 if (code < 0xC0000000u || code >= 0xD0000000u)]`

**软件异常不再刷屏** — 同一异常码只记一次 `[info] 软件异常 0x... （首次出现，非崩溃）`
改前实测：71 个崩溃块里真异常 0 个，全是 `0x40010006`（OutputDebugString，66 次）/ `0xE06D7363`（4 次）/ `0x406D1388`（1 次），且 71/71 都打印「请把这段发给开发者」—— 主动制造假工单。
改后一局：`[info]` 只有 3 行，一码一行，`!!! CRASH` 0 条。
`[证据: LOG_AUDIT_usage_version.md §P0-2 的 71 块签名表；E:\...\auto_research.log 第 36/83/84 行的三行 [info]，全文 grep `!!!` = 0]`

**`[disp]` / 主 hook 日志降噪** — 使用版完全不写，维护版单行 + 限流（前 50 + 每 100）
原因：主 hook `0x428EE0` 是科技显示名构造器，每次 UI 刷新都调，与选卡无关。改前实测 1213 行日志里 807 行（66%）是它。
`[证据: auto_research.cpp:3972-4015 的实测数据与 #if AR_BUILD_WITH_PROBES 分支]`

**`[tak-DBG]` 收紧到前 20 条** — 原无上限
`[证据: auto_research.cpp:2339 的 if (n0 <= 20)；实测日志 21 条（20 条决策 + 1 条横幅）]`

**中期汇总间隔 300 → 500** — 与退出汇总并存
`[证据: auto_research.cpp:2728-2729；hook_tramp_test.cpp:1361-1362 断言 total % 500]`

### 变更

**两版构建分离** — `AR_BUILD_WITH_PROBES` 总开关
`0`（使用版）= 无 C890/SEL/rp/bp 探针；`1`（维护版，默认）= 全探针。两个 DLL 大小 828,061 / 848,758 B。
`[证据: auto_research.cpp:1070-1145 开关与派生逻辑；release_v1/src/build.sh 的两条 g++ 命令；从 src 重建两个 DLL 得到 828,061 / 848,758 B —— 与发布版大小逐字节相同]`

**接管核心不再被探针开关包住** — 只跳过安装调用，代码常驻
原因：`#if AR_ENABLE_PROBES` 包整块会误伤 `AR_TakeoverV2` / trampoline / `InstallTakeoverV2`。
`[证据: auto_research.cpp:2059-2063 的说明与随后的 #if 1]`

**`[PICK]` 的 `ours` 改成跟着 `ridx` 走** — 让「随机落到哪个」可直读
`ridx >= 0` 时 `选中=` 一定是一个真实 key（不再出现 `ours=- action=OVERRIDE-POS` 的自相矛盾）。
`[证据: auto_research.cpp:2682-2702；实测 153 条 [PICK] 中 选中=- 的 0 条]`

### 已知问题

- **`[hookA]` 的 tech key 仍然读不出**（`tech=` 恒 `<unreadable>`）。已确认为偏移不适用（hookA 的 `param_2` 与候选数组元素不是同一类对象），不是偶发。使用版该行只进环形缓冲，不落盘。
  `[证据: LOG_AUDIT_usage_version.md §1.4 两个读取点成功率对照 0/9,571 vs 455/455]`
- **`RemoveTakeoverV2` 未编入使用版**（`take v2 removed` 字符串在 828,061 B 的 DLL 里命中 0 次，在维护版里命中）→ 运行中卸载 DLL 会崩。当前注入器只 load 不 unload，正常游玩不触发。
  `[证据: 对两个 DLL 做字符串检索；auto_research.cpp:4773-4783 的 DETACH 分支在 #if AR_ENABLE_PROBES 内]`
- **`take v2 INSTALLED` 文案与实际不符** — 打印的是 `0x6F334E`（玩家路径），但字面量写的是 v2。
  `[证据: 运行日志「[tk2] take v2 INSTALLED at 0x7FF65ED9334E」；0x7FF65ED9334E - 0x7FF65E6A0000(base) = 0x6F334E]`
- **`[tak-SKIP]` / `[tak-DBG]` / `[disp]` 在使用版仍会输出** — 它们不在 `AR_BUILD_WITH_PROBES` 保护内（横幅却标 `[OFF]`）。实测使用版一局：`[tak-DBG]` 21 条、`[tak-SKIP]` 1 条、`[disp]` 1 条。
  `[证据: 横幅 auto_research.cpp:4692-4698 标 OFF vs 一局日志计数]`
- 多人游戏未测试。

---

## v0.9 — 2026-11-18

真接管首次上线。这一天的主线是「玩家路径之争结束」+「语义修正」。

### 新增

**`[PICK]` 选卡日志** — 一次决策一行，含候选列表、随机下标、最终选中、动作
```
[PICK] 领域=物理 候选数=3 候选=[...] 抽中=1 选中=tech_space_science_1（零重力实验室） 动作=不干预（随机命中游戏原选）
```
限流：`接管` / `全禁` 全记；`不干预` 前 50 + 之后每 20；无候选前 10 + 每 500。
`[证据: auto_research.cpp:2631-2722；一局 153 条 [PICK] 对 153 次决策，说明全量记下]`

**`[汇总]` 退出一局一条**（见 v1.0.0「退出时打一条完整汇总」）

**成员判据** — `gamePick ∈ arr[0..cnt-1]` 才认为是「真选卡」，否则按早退跳过
比比较哨兵值更本质：不依赖任何全局值。
`[证据: auto_research.cpp:2304-2330；一局 真选卡=153 早退=0]`

**`ar_config.h` 独立成纯逻辑头文件** — 不带 `windows.h`、不碰游戏内存、不依赖 hook
让 DLL 与控制台自测跑同一份代码，杜绝「测的和用的不一样」。
`[证据: ar_config.h:1-5 的设计原则；config_selftest.cpp 与 auto_research.cpp 都 include 它]`

### 修复

**负数兜底方向修正** — 取**数值最大**（最接近 0），不是绝对值最大
候选 `[-1, -1000]` → 选 `-1`（旧语义选 `-1000`）。
`[证据: ar_config.h:391-395 注释「旧语义是 -1000，2026-11-18 已修正」+ 412 行注释与实现；config_selftest.cpp:307-340 的「全负 → 取数值最大」「-1 优于 -1000」「0 与负数混合：0 仍禁选」三条断言]`

**未配置科技的权重处理修正** — 未配置走 `@default`（默认 100），不是「不参与」
这是禁选 bug 的真根因：旧版把「未配置」当「不参与」，导致 `[0, 未配置, 未配置]` 被误判为全禁。
`[证据: auto_research.cpp:2209-2216 Tk2ReadCfg 里的 ★ 注释与 EffectiveWeight 调用]`

**禁选判定从「有一个配了值」改成「全部权重为 0」**
旧：`else if (anyConfigured)` 的语义是「至少一个候选配了值」，于是 `1 个禁选 + 2 个未配置` 也会停研究。
新：`allOff = (readable > 0 && allZero)`，只有真的全 0 才停研究 + 清该领域自动科研 bit。
`[证据: auto_research.cpp:2352-2375 的旧 bug 说明；2497 行 allOff 定义；2529-2542 全禁分支清 (slotmgr+0x08) 的 bit(area)]`

**`verdict` 与 `ours` 不一致** — 先算 candidate，再用「candidate 是否 != gamePick」统一判定
旧版 342 条 `[PICK]` 里有 106 条是 `ours=- action=OVERRIDE-POS`（自相矛盾）。
`[证据: auto_research.cpp:2481-2496 的 bug 说明；2524-2566 的单一真值判定链]`

**选中对象二次可读性检查** — 主动选了 `arr[i]` 之后再验一次，不可读就退回游戏原选
防止 trampoline 执行 `MOV RDX,[RAX]` 时踩到游戏原本不会踩的路径。
`[证据: auto_research.cpp:2616-2629]`

**`TkReadKey` 移出探针块** — 使用版编译时不再链接失败
`[证据: auto_research.cpp:1116-1123 的说明]`

### 变更

- `0xBBC300` 的 AI 路径探针默认关闭（两版都关）：已确认它 347/347 条 `c314c=0`，不影响玩家，继续观测只是刷日志 + 吃性能。
  `[证据: auto_research.cpp:2160-2168 注释；横幅 [OFF] [bp]]`

---

## v0.8 — 2026-11-17

**这一天最关键的结论：之前 patch 的位置本来就是对的，问题出在判据方向反了。**

### 修复

**玩家判据方向纠错** — `country+0x314C == 0` → `!= 0`
```
游戏 is_human @ 0xD18175（逐字节）：
  0xD18175  CMP dword [RAX+0x314C], 0
  0xD1817C  JE  0xD1818B            ; == 0 → DL=0（不是人类）
  0xD1817E  CMP byte [0x281B833], 0
  0xD18185  JNE 0xD1818B            ; != 0 → DL=0
  0xD18187  MOV DL,1                ; 两者都满足 → DL=1
⇒ is_human = (country[+0x314C] != 0) AND (byte[0x281B833] == 0)
```
**这是行为变更，不是标签修正**：修复前 take 实际作用于 `+0x314C == 0` 的国家（= AI），修复后才真正作用于玩家。
真机证据（同一份 DLL，238 条 `[bp]` + 31 条 `[hookA]`）：
| 路径 | 记录数 | c314c | 判定 |
|---|---|---|---|
| `[bp]`（0xBBC300→0xBBC3E7） | 238 | 0（238/238） | 全 AI，cid 1..15/31/85，**cid=0 从不出现** |
| `[hookA]`（0x6F2590→0x6F334E） | 30 | 1 | 玩家（cid=0） |
| `[hookA]` | 1 | 0 | AI（cid=13） |
判据有分辨力（不是恒真）：同一份日志里两个分支都被走到。
`[证据: auto_research.cpp:845-891 整块注释；896-905 IsCountryPlayer 实现]`

**「isai 变量名误导」定案**
`isai` 这个日志字段装的是 `[country+0x314C]` 的**原始值**，而它的语义是 `is_human` 的**必要条件**——名字与实际含义相反。误读这个名字直接导致了 v0.7 的「去找另一条玩家路径」这条弯路。
副作用：修复前的旧日志里 `ai-by-current-slot` 多半其实是玩家，`PLAYER-by-current-slot` 其实是 AI。
`[证据: auto_research.cpp:888-890 的注意事项]`

**三处崩溃修复**

1. `sub $0x20` → `sub $0x28`：`(0 - 56 - 32) % 16 = 8` 未对齐，`call` 崩。
2. `mov 0x30(%rsp)` 读的是 `r9` 不是 `rax` → `gamePick` 是垃圾。改成**先把 rax 存全局**再传，完全不依赖栈偏移。
3. 三段跳里不能用 `mov rax, imm64`（会破坏 `RAX` = `gamePick`）→ 改用 `jmp [rip+disp32]`（nearby 桩常量 `0x90900000000225ff`，小端 = `FF 25 02 00 00 00 90 90`），零寄存器副作用。
`[证据: auto_research.cpp:2924-2957 trampoline 全文与两条 bug 注释；2831 行「不能用 mov rax,imm64」]`

### 新增

**`[tak-DBG]` 候选数组诊断** — 打印 `slotmgr` / `arr` / 前 3 个元素 / `game` / 逐元素相等位
用于查「`game=0x294e4730010` 出现 89%，但在 52 个 tech 里 0 命中」这一异常。
`[证据: auto_research.cpp:2332-2350；一局日志 20 条，eq=010(8) / 100(9) / 001(3) 三种都出现 —— 说明 gamePick 确实是候选数组元素]`

**`0x820B30` 可能返回空的处理** — 直接走 skip 路径
`[证据: auto_research.cpp:2258-2261]`

### 变更

- 探针阶段（DRY-RUN）结束，`AR_TAKEOVER_V2_DRYRUN` 置 0 → 真接管。
  `[证据: auto_research.cpp:2157-2158 默认值 0；横幅「[ON ] take 真接管 AR_TAKEOVER_V2_DRYRUN=0（LIVE）」]`

---

## v0.7 — 2026-11-16

**这一天的主线是「找玩家路径」——事后证明是白跑，但排除过程本身有价值。**

### 变更

**候选槽布局改为自动推导**（`ar_layout.h`）
不再写死 `country+0x31B0/+0x31BC`，改为从函数体指令形状推导。运行日志：
```
[INFO] ① 32位 count load 候选：18
[INFO] ①~⑤ 完整形状候选 2 个：
[INFO]     count=0x31BC array=0x31B0 elem=4
[INFO]     count=0x1664 array=0x1658 elem=4
[INFO]   排除 count=0x1664 array=0x1658：首次访问非比较语义
[INFO] => 唯一解：count=0x31BC array=0x31B0 elem=4
[INFO] card layout derived: count_off=0x31BC array_off=0x31B0 elem=4 (source: shape-derivation, not hardcoded)
```
legacy 常量只作对照告警，绝不作为 fallback。
`[证据: auto_research.cpp 运行日志第 63-73 行；ar_layout.h 头注释]`

**移除 `RtlCaptureStackBackTrace`** — 真机崩溃根因
加它之后崩，原因是 Win64 shadow space 被覆盖（7 个 push 落在 callee 的 shadow 区）。
`[证据: auto_research.cpp:1487「★ 2026-11-16 移除 —— 真机崩溃根因」]`

**`[alt]` / `[map]` 探针升级到 v2/v3**
`[证据: auto_research.cpp:3463「[map] ... 2026-11-16 v2，数据源改为 A 点探针的 r15」；3655「[alt] 三领域备选列表（2026-11-16 v3）」]`

### 已知问题（当时未解决）

- 「谁是玩家」的判据当时认为需要确认 `+0x314C` 语义 —— 第二天定案（见 v0.8）。
- 全禁时 `return nullptr` 是否安全存疑，当时实现是「全禁 = 不干预」。第二天改成清 bit + skip 路径（见 v0.9）。

---

## v0.6 — 2026-11-15

### 新增

- **C890 只读打点 hook**（`0x81E7E0`，3 条 shadow-store 正好 15 字节）
  用途：确认「每个决策被调几次」，从而判定 C890 是「算单卡权重」还是「从 N 张里选 1 张」。
  `[证据: auto_research.cpp:1372「C890 只读打点 hook（2026-11-15）」]`
- **SEL 探针**（`0x81A5B0`）与**调用栈记录**
  `[证据: auto_research.cpp:1148 / 1427]`

### 修复

**`IsPlayerContext` 时序 bug** — 它读全局 `g_arSlot`，而 `obj` 是当次的 tech 对象，两者不配套 → 同一 tech 在不同时刻被标成不同 `PLAYER`/`ai`
改为 `IsCountryPlayer(CountryFromSlot(slot))`，用**当次链路**。
`[证据: auto_research.cpp:820「2026-11-15 修复」；3817-3835 的详细说明；4031「旧 IsPlayerContext 定义已删除」]`

---

## v0.5 — 2026-11-12

### 修复

**hookA 日志的 `caller` / `site` 永为 0** — `FlushPendingStart` 硬编码传 `(0,0)`
改由 `ARAfter2` 转存真实返回值。
`[证据: auto_research.cpp:767 / 796 / 3960]`

### 新增

**tech 对象身份诊断**（一次性，前 5 次 + 形态变化，上限 10 次）
用途：查「hookA 的 tech key 从未读出过」。一次运行即可定位偏移不适用。
`[证据: auto_research.cpp:956 / 3847]`

---

## v0.4 — 2026-11-11

### 变更

- **删除从未被调用的 `ShouldPatchReturnAddress` 辅助函数**（典型「写了但没接线」）
  `[证据: auto_research.cpp:579-581]`
- **修正第 4 例「代码写了但接线错了」**：`InstallAll` 解析对了 RVA，`Init` 又覆盖回去
  `[证据: auto_research.cpp:4750-4754]`

---

## v0.1 — 2026-10-31

项目起点。这一天定下的架构决定了后面所有代码的形状。

### 新增

- **四层地址定位**，按抗漂移能力排序（不是按易用性）：
  1. 字符串锚点（2 条互证）→ 主定位 hookA
  2. 调用链 + 稀有 callee 指纹（SEL=1, GETC=1）→ 主定位主 hook
  3. 长特征码 24–56 B → 只做校验，不做定位
  4. SHA256 / 版本白名单 → 显式兜底
  `[证据: ar_anchor.h / ar_resolve.h / ar_gate.h 三个头文件的职责划分；运行日志第 37-54 行「anchor-verified」全过程]`

- **原子安装 + 回滚**：要么全装，要么一条都不装；任一步写入失败就把已写的字节全部还原
  `[证据: auto_research.cpp:4325-4406；运行日志「[install] all 2 required hook(s) installed; state=fully-installed verdict=anchor-verified」]`

- **`AR_ONLY_MAIN_HOOK` 二分排障开关** — 只装主 hook、完全不 patch hookA，用于区分「patch 机制有问题」与「hookA 有问题」
  `[证据: auto_research.cpp:4331-4338]`

- **版本闸门**：版本不对时一个 hook 都不装，日志写「The DLL is inert. Your game has NOT been modified.」
  `[证据: auto_research.cpp:4273-4297]`

### 已知问题

- take 模式只有框架：配置写得进去，但**不影响游戏选择**。
- observe 模式可用。

---

## 完整时间线速查

| 日期 | 关键事件 | 证据来源 |
|---|---|---|
| 2026-10-31 | 四层定位 + 原子安装 + 版本闸门落地 | ar_anchor.h / ar_gate.h 头注释；CONFIG_FORMAT.md mtime 10-31 01:15 |
| 2026-11-11 | 删死代码；修「InstallAll 解析对了 Init 又覆盖」 | auto_research.cpp:579 / 4753 |
| 2026-11-12 | 修 caller/site 永为 0；tech 身份诊断 | auto_research.cpp:767 / 956 |
| 2026-11-15 | 修 IsPlayerContext 时序 bug；C890/SEL 只读探针 | auto_research.cpp:820 / 1372 |
| 2026-11-16 | 候选槽自动推导；删 RtlCaptureStackBackTrace（真机崩溃根因）；开始找玩家路径 | auto_research.cpp:1487 / 运行日志 63-73 |
| 2026-11-17 | ★ 判据纠错 `==0` → `!=0`；确认 `0x6F334E` 本来就是玩家路径；isai 命名误导定案；三处崩溃修复 | auto_research.cpp:845-891 / 2924-2957 |
| 2026-11-18 | 真接管上线；`[PICK]` 日志；负数语义修正；禁选修正；未配置 = defaultWeight | auto_research.cpp:2209 / 2352 / 2481 / 2631 |
| 2026-11-20 | xorshift64\*；中文日志；环形缓冲；VEH；配置模板自动创建；路径修正；tie 累加器归位 | auto_research.cpp:39 / 98 / 213 / 420 / 2402 / 2579 |

---

## 版本号对照

| 版本号 | 源码 banner 标识 | 说明 |
|---|---|---|
| v1.0.0 | `2026-11-18 take-v3 LIVE-PLAYER` | 首个可发布版本。**banner 里的日期晚于实际改动日**（字符串是 11-18 写的，11-20 的改动没有更新它） |
| v0.9 | `take-v3`（DRY-RUN → LIVE 切换点） | 真接管上线 |
| v0.8 | `take-v2`（判据纠错） | 玩家判据方向正确 |
| v0.7 及以前 | `STAGE-1a` / `STAGE-1b` | 探针阶段，`AR_TAKEOVER_V2_DRYRUN=1` 只观测 |

> **判断版本请用功能指纹，不要用 SHA256**：MinGW 的 `.data` 段每次构建都不同。
> 实测：从 `release_v1/src` 重新构建两个 DLL，大小 828,061 / 848,758 B 与发布版**完全相同**，但 SHA256 分别是
> `096F79C7…` / `E13EEBC3…`，与发布版的 `CAB01114…` / `0F06E3C7…` 都不同。
