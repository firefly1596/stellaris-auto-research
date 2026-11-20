// auto_research.dll — 玩家专属自动科研权重框架 v2
//
// hook FUN_140428EE0 (0x428EE0)：显示名构造器（每次 UI 刷新都调，与选卡无关）
//   真正的选卡接管点是 0x6F334E（在 0x6F2590 玩家自动科研循环里）
//   本文件还包含 hookA 0x81C850（科研查询）等多个只读探针
//
// ============ 配置语义（纯数字，唯一规范） ============
//   tech = > 0     正常权重，候选里数值最大者胜出
//   tech = 0       禁选，绝不选
//   tech = < 0     不选；仅当没有 > 0 的候选时，在 < 0 里取【数值最大】的（最接近 0 者，如 -1 优于 -1000）
//   tech = 非数字  无效行：记日志并忽略（soft / ban 旧写法已彻底删除）
//   @default = N   未列出科技的权重
//   @mode = observe | take
//   配置文件不存在 / 读不到 → 清空配置（回到 observe + 内置默认）
//
// 解析与决策逻辑全在 ar_config.h（纯函数：无 Windows、无游戏内存、无 hook），
// 由 config_selftest.cpp 离线自测覆盖，格式契约见 auto_research_handoff\team\CONFIG_FORMAT.md
//
// 文件: injected_mods\auto_research_weights.txt (热重载: mtime + size)
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdarg>
#include <string>
#include <unordered_map>
#include <vector>
#include <share.h>       // _fsopen / _SH_DENYNO（读配置时允许别的进程同时写）

#include "ar_config.h"        // 配置解析 + 权重语义 + 热重载（纯函数，离线自测覆盖）
#include "ar_config_win32.h"  // 真实文件读取（与控制台磁盘自测共用）
#include "ar_gate.h"          // 版本闸门（纯逻辑，gate_selftest 覆盖）
#include "ar_gate_win32.h"    // 闸门的真实 Win32 实现（PE/.pdata/SHA256/序言）
#include "ar_resolve.h"        // 地址解析编排（锚点 → 调用链 → 哈希兜底）
#include "ar_resolve_win32.h"
#include "ar_tech_names.h"   // ★ 科技 key → 中文名映射（678 条）

// ============================================================================
// ★★ 2026-11-20：日志字段中文化 ★★
// ============================================================================
//
// 格式：保持「字段名=值」，但字段名和值都中文。
//   area=0  →  领域=物理
//   cnt=4   →  候选数=4
//   ridx=3  →  抽中=3
//   ours=X  →  选中=tech_xxx（中文名）
//   action  →  动作=接管（并列随机）
//
static const char* ArAreaZh(int area) {
    switch (area) {
        case 0: return "物理";
        case 1: return "社会";
        case 2: return "工程";
        default: return "?";
    }
}

static const char* ArActionZh(const char* v) {
    if (!v) return "?";
    if (strcmp(v, "OVERRIDE-POS") == 0)        return "接管（唯一最优）";
    if (strcmp(v, "OVERRIDE-POS-TIE") == 0)    return "接管（并列随机）";
    if (strcmp(v, "OVERRIDE-NEG") == 0)        return "接管（负数兜底）";
    if (strcmp(v, "OVERRIDE-NEG-TIE") == 0)    return "接管（负数并列）";
    if (strcmp(v, "KEEP-TIE-HIT") == 0)        return "不干预（随机命中游戏原选）";
    if (strcmp(v, "KEEP-SAME-BEST") == 0)      return "不干预（最优即游戏原选）";
    if (strcmp(v, "KEEP") == 0)                return "不干预";
    if (strcmp(v, "ALL-DISABLED") == 0)        return "★全禁→停研究";
    if (strcmp(v, "UNREADABLE-FALLBACK") == 0) return "不干预（对象失效）";
    if (strcmp(v, "keep") == 0)                return "不干预";
    return v;
}  // 解析器的真实 Win32 实现

static uint64_t g_base = 0;
static FILE* g_log = nullptr;
static CRITICAL_SECTION g_cs;
static volatile LONG g_seq = 0;

// ============================================================================
// ★★ 2026-11-20：VEH 崩溃捕获（诊断版）★★
// ============================================================================
//
// ★ 前置声明：CrashHandler 在 71 行，SelfModule 在 216 行
//   崩溃处理需要用它算 DLL 基址，所以先声明。
static HMODULE SelfModule();

// 【为什么需要】
//   用户开控制台批量完成科研时，窗口静默消失，无 WER、无 dmp。
//   需要知道：崩在哪条指令、当时我们的状态是什么。
//
// 【安全设计】
//   · 只记录，不吞掉异常（返回 EXCEPTION_CONTINUE_SEARCH）
//   · 记录后立即 fflush，防止日志丢失
//   · 不调用任何可能再次崩溃的 API（Log 本身可能持锁）
//
static volatile LONG  s_crashGuard = 0;   // 防重入

// ============================================================================
// ★★ 2026-11-20：main-hook 环形缓冲（用户实测：它占日志 75.9%）★★
// ============================================================================
//
// 【为什么】
//   main-hook (0x428EE0) 是「科技显示名构造器」，每次 UI 刷新都调。
//   实测一局 5,731 行，占全部日志 75.9%。
//
// 【新策略】
//   平时：只写内存环形缓冲，磁盘 0 B
//   崩溃：硬件异常时一次性导出最近 200 条
//
// 【内存】
//   200 x 160 B = 32 KB
//
// ★ 前置声明：RingDump 在 139 行用到 CrashWrite，而它定义在 200+ 行
static void CrashWrite(const char* s);

#define AR_RING_CAP   200
#define AR_RING_LINE  160

static char          g_ringBuf[AR_RING_CAP][AR_RING_LINE];
static volatile LONG g_ringHead  = 0;   // 下一个写入位置（累计）
static volatile LONG g_ringTotal = 0;   // 累计写入条数

static void RingPush(const char* fmt, ...) {
    char line[AR_RING_LINE];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);

    const LONG idx = InterlockedIncrement(&g_ringHead) - 1;
    const LONG slot = idx % AR_RING_CAP;
    size_t n = strlen(line);
    if (n >= AR_RING_LINE) n = AR_RING_LINE - 1;
    memcpy(g_ringBuf[slot], line, n);
    g_ringBuf[slot][n] = 0;
    InterlockedIncrement(&g_ringTotal);
}

// 导出环形缓冲（只在崩溃时调用）
static void RingDump() {
    const LONG total = InterlockedCompareExchange(&g_ringTotal, 0, 0);
    if (total <= 0) {
        CrashWrite("!!! (hookA 环形缓冲为空，本次运行未调用 hookA)\n");
        return;
    }
    const LONG n = (total > AR_RING_CAP) ? AR_RING_CAP : total;
    const LONG start = total - n;
    char b[AR_RING_LINE + 32];
    snprintf(b, sizeof(b), "!!! ---- 崩溃前最后 %ld 条 hookA 记录（累计 %ld）----\n",
             (long)n, (long)total);
    CrashWrite(b);
    for (LONG i = 0; i < n; ++i) {
        const LONG slot = (start + i) % AR_RING_CAP;
        snprintf(b, sizeof(b), "!!! ring[%ld] %s\n", (long)i, g_ringBuf[slot]);
        CrashWrite(b);
    }
    CrashWrite("!!! ---- ring end ----\n");
}

// ============================================================================
// ★ 2026-11-20：并列 / [PICK] 计数器提为全局
//   原本是 AR_TakeoverV2 / [PICK] 块内的 static，
//   但 DllMain(DLL_PROCESS_DETACH) 需要读它们打总结。
// ============================================================================
static volatile LONG s_tieTotal   = 0;   // 有并列的次数
static volatile LONG s_tiePosN    = 0;   // 正数并列次数
static volatile LONG s_tieNegN    = 0;   // 负数并列次数
static volatile LONG s_tieHitGame = 0;   // 并列随机撞上 gamePick
static volatile LONG s_pickKey    = 0;   // [PICK] 接管类
static volatile LONG s_pickKeep   = 0;   // [PICK] 保留/早退类
static volatile uint64_t s_lastRip   = 0;
static volatile uint64_t s_lastCountry = 0;
static volatile uint64_t s_lastGamePick = 0;
static volatile uint64_t s_lastSlotmgr = 0;
static volatile LONG     s_lastArea  = -1;
static volatile LONG     s_lastCnt   = -1;
static volatile LONG     s_lastMode  = -1;

// 直接用 WriteFile 写（不过 Log 的锁，避免死锁）
static void CrashWrite(const char* s) {
    if (!g_log) return;
    fputs(s, g_log);
    fflush(g_log);
}

// ★ 软件异常：每个码一生只记 1 次（避免 OutputDebugString 刷屏）
static DWORD s_seenSoft[8] = {0};
static volatile LONG s_seenSoftN = 0;

static LONG WINAPI CrashHandler(EXCEPTION_POINTERS* ep) {
    if (!ep || !ep->ExceptionRecord) return EXCEPTION_CONTINUE_SEARCH;
    EXCEPTION_RECORD* er = ep->ExceptionRecord;
    const CONTEXT* cx = ep->ContextRecord;

    // ========================================================================
    // ★★ 2026-11-20：只记硬件异常（用户实测 142 条误报）★★
    // ========================================================================
    //
    // 【误报来源】
    //   OutputDebugString 会发 0x40010006 DBG_PRINTEXCEPTION_C，
    //   游戏每次调用我们都会记一整块，占了 2000+ 行。
    //
    // 【判据】
    //   硬件异常码都 ≥ 0xC0000000：
    //     0xC0000005 ACCESS_VIOLATION
    //     0xC000001D ILLEGAL_INSTRUCTION
    //     0xC00000FD STACK_OVERFLOW
    //     0xC0000409 STACK_BUFFER_OVERRUN (__fastfail)
    //     0xC0000374 HEAP_CORRUPTION
    //   软件异常 < 0xC0000000：
    //     0x40010006 DBG_PRINTEXCEPTION_C / 0x406D1388 线程命名（<0xC0000000）
    //     0xE06D7363 MSVC C++ EH / 0xE0434352 .NET CLR（>=0xD0000000）
    const DWORD code = (DWORD)er->ExceptionCode;
    // ★★ 2026-11-20 修正：不是单向阈值，而是【区间】判定 ★★
    //
    // 【上一版的 bug】只写了 code < 0xC0000000，
    //   但 0xE06D7363（MSVC C++ EH）= 3,766,556,003 > 0xC0000000，
    //   被误判为「硬件异常」→ 走完整 CRASH 块（实测 8 次）。
    //
    // 【Windows 异常码真实分段】
    //   < 0xC0000000          调试/警告  0x40010006 DBG_PRINTEXCEPTION_C
    //                                        0x406D1388 线程命名
    //   [0xC0000000, 0xD0000000)  ★ 真硬件异常（崩溃）
    //                             0xC0000005 AV / 0xC000001D ILLEGAL_INSTRUCTION
    //                             0xC00000FD STACK_OVERFLOW / 0xC0000409 __fastfail
    //                             0xC0000374 HEAP_CORRUPTION
    //   >= 0xD0000000         用户自定义  0xE06D7363 MSVC C++ EH
    //                                        0xE0434352 .NET CLR
    //
    // ⇒ 只有 [0xC0000000, 0xD0000000) 才是真崩溃。
    //
    if (code < 0xC0000000u || code >= 0xD0000000u) {
        // 软件异常：同一码只记 1 次，让人知道游戏在发什么
        const LONG n = InterlockedCompareExchange(&s_seenSoftN, 0, 0);
        for (LONG i = 0; i < n; ++i)
            if (s_seenSoft[i] == er->ExceptionCode) return EXCEPTION_CONTINUE_SEARCH;
        if (n < 8) {
            s_seenSoft[n] = er->ExceptionCode;
            InterlockedCompareExchange(&s_seenSoftN, n + 1, n);
            char b[128];
            snprintf(b, sizeof(b), "[info] 软件异常 0x%08lX（首次出现，非崩溃）\n",
                     (unsigned long)er->ExceptionCode);
            CrashWrite(b);
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }

    if (InterlockedCompareExchange(&s_crashGuard, 1, 0) != 0)
        return EXCEPTION_CONTINUE_SEARCH;

    char buf[768];

    CrashWrite("\n");
    CrashWrite("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
    snprintf(buf, sizeof(buf), "!!! CRASH  code=0x%08lX\n",
             er ? (unsigned long)er->ExceptionCode : 0UL);
    CrashWrite(buf);
    if (er) {
        snprintf(buf, sizeof(buf), "!!! crash addr = 0x%llX\n",
                 (unsigned long long)(uintptr_t)er->ExceptionAddress);
        CrashWrite(buf);
        snprintf(buf, sizeof(buf), "!!! flags = 0x%lX  params = %lu\n",
                 (unsigned long)er->ExceptionFlags,
                 (unsigned long)er->NumberParameters);
        CrashWrite(buf);
        for (DWORD i = 0; i < er->NumberParameters && i < 4; ++i) {
            snprintf(buf, sizeof(buf), "!!!   param[%lu] = 0x%llX\n",
                     (unsigned long)i,
                     (unsigned long long)er->ExceptionInformation[i]);
            CrashWrite(buf);
        }
    }
    if (cx) {
#ifdef _WIN64
        snprintf(buf, sizeof(buf), "!!! rip=0x%llX rsp=0x%llX rbp=0x%llX\n",
                 (unsigned long long)cx->Rip, (unsigned long long)cx->Rsp,
                 (unsigned long long)cx->Rbp);
        CrashWrite(buf);
        snprintf(buf, sizeof(buf), "!!! rax=0x%llX rbx=0x%llX rcx=0x%llX rdx=0x%llX\n",
                 (unsigned long long)cx->Rax, (unsigned long long)cx->Rbx,
                 (unsigned long long)cx->Rcx, (unsigned long long)cx->Rdx);
        CrashWrite(buf);
        snprintf(buf, sizeof(buf), "!!! rsi=0x%llX rdi=0x%llX r14=0x%llX r15=0x%llX\n",
                 (unsigned long long)cx->Rsi, (unsigned long long)cx->Rdi,
                 (unsigned long long)cx->R14, (unsigned long long)cx->R15);
        CrashWrite(buf);
#endif
    }
    snprintf(buf, sizeof(buf),
             "!!! last state: area=%ld cnt=%ld country=0x%llX slotmgr=0x%llX gamePick=0x%llX mode=%ld\n",
             (long)s_lastArea, (long)s_lastCnt,
             (unsigned long long)s_lastCountry, (unsigned long long)s_lastSlotmgr,
             (unsigned long long)s_lastGamePick, (long)s_lastMode);
    CrashWrite(buf);
    // ★ 故障模块归属：直接告诉我们崩在 stellaris.exe 还是 auto_research.dll
    if (er) {
        HMODULE hMod = nullptr;
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCSTR)(const void*)er->ExceptionAddress, &hMod);
        char modName[MAX_PATH];
        modName[0] = 0;
        if (hMod) GetModuleFileNameA(hMod, modName, MAX_PATH);
        snprintf(buf, sizeof(buf), "!!! fault module = %s\n",
                 modName[0] ? modName : "UNKNOWN");
        CrashWrite(buf);

        // 我们自己的 DLL 基址（便于算 RVA）
        HMODULE hSelf = SelfModule();
        if (hSelf) {
            snprintf(buf, sizeof(buf), "!!! dll base = 0x%llX  crash RVA = 0x%llX\n",
                     (unsigned long long)(uintptr_t)hSelf,
                     (unsigned long long)((uintptr_t)er->ExceptionAddress -
                                          (uintptr_t)hSelf));
            CrashWrite(buf);
        }
    }
    // ★ 2026-11-20：导出 hookA 环形缓冲（只在崩溃时）
    RingDump();
    CrashWrite("!!! 请把这段发给开发者\n");
    CrashWrite("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");

    InterlockedExchange(&s_crashGuard, 0);
    return EXCEPTION_CONTINUE_SEARCH;   // ★ 不吞异常，让游戏继续崩
}

static void Log(const char* fmt, ...) {
    if (!g_log) return;
    EnterCriticalSection(&g_cs);
    va_list ap; va_start(ap, fmt);
    vfprintf(g_log, fmt, ap); va_end(ap);
    fputc('\n', g_log); fflush(g_log);
    LeaveCriticalSection(&g_cs);
}

__declspec(noinline)
static bool SafeReadable(const void* p, size_t n) {
    if (!p) return false;
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(p, &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT) return false;
    if (mbi.Protect & (PAGE_NOACCESS|PAGE_GUARD)) return false;
    return (uintptr_t)p + n <= (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
}

// ================= 配置层 =================
// 语义与解析全部在 ar_config.h（纯函数），这里只做 Win32 适配：
//   Win32FileSource : 用 GetFileAttributesExA + fopen 读文件 → arcfg::IFileSource
//   LogBridge       : arcfg 的日志回调 → 本文件的 Log()
//   PollConfig()    : 热重载入口（mtime + size；文件消失/读不到 = 清空）
static arcfg::Config g_cfg;
static arcfg::Watcher g_watcher;
static INIT_ONCE g_cfgOnce = INIT_ONCE_STATIC_INIT;
static CRITICAL_SECTION g_cfgCs;   // 配置专用锁（与日志锁分开，日志不会拖住重载）
static volatile LONG g_cfgCsReady = 0;

static void CfgLogBridge(void*, int severity, const char* msg) {
    // 配置层日志统一带 [cfg] 前缀，warning/error 额外标级别，便于事后 grep
    const char* tag = (severity == 2) ? "[cfg][ERR ]"
                    : (severity == 1) ? "[cfg][WARN]"
                                      : "[cfg]";
    Log("%s %s", tag, msg ? msg : "");
}

static arcfg::Logger CfgLogger() {
    arcfg::Logger lg;
    lg.fn = &CfgLogBridge;
    lg.ctx = nullptr;
    return lg;
}

// Win32 文件读取 + 快照（实现见 ar_config_win32.h，磁盘自测用的同一份）
using arcfg::Win32FileSource;
static Win32FileSource g_cfgSource;

// ============================================================================
// ★★ 2026-11-20 崩溃修复：取【DLL 自己】的目录，不是 exe 目录 ★★
// ============================================================================
//
// 【bug】
//   GetModuleFileNameA(nullptr, ...) 的 nullptr 表示「调用进程的主模块」
//   = stellaris.exe 的路径，不是 DLL 的路径。
//
//   实测：日志被写到 E:\...\Stellaris\auto_research.log
//         而不是 E:\...\Stellaris\injected_mods\auto_research\auto_research.log
//
// 【修法】
//   GetModuleHandleExA + GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
//   用「函数地址」反查它所在的模块 → 就是 DLL 自己。
//   不依赖 DllMain 的 hInstance，任何时候都能用。
//
static HMODULE SelfModule() {
    HMODULE h = nullptr;
    GetModuleHandleExA(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCSTR)(const void*)&SelfModule,
        &h);
    return h;
}

// DLL 所在目录（不带尾部 '\'）。失败返回空串。
static std::string DllDir() {
    char path[MAX_PATH];
    HMODULE self = SelfModule();
    if (!self) return std::string();
    DWORD n = GetModuleFileNameA(self, path, MAX_PATH);   // ★ 用 DLL 自己的 HMODULE
    if (n == 0 || n >= MAX_PATH) return std::string();
    char* s = strrchr(path, '\\');
    if (s) *s = 0;
    return std::string(path);
}

// 配置文件路径: <DLL 所在目录>\auto_research_weights.txt
static std::string ConfigPath() {
    const std::string d = DllDir();
    if (d.empty()) return std::string();
    return d + "\\auto_research_weights.txt";
}

// ============================================================================
// ★★ 2026-11-20：配置模板自动创建 ★★
// ============================================================================
//
// 【为什么需要】
//   旧行为：文件不存在 → 静默进入 observe 模式，用户不知道为什么不生效。
//   新行为：文件不存在 → 写出带注释的模板 → 仍按 observe 运行（安全）。
//
// 【安全设计】
//   · @mode = observe（默认不接管，用户改成 take 才生效）
//   · 所有 tech 条目都注释掉（不会意外生效）
//   · 模板里写明语义（用户不用查文档）
//
static bool WriteConfigTemplate(const std::string& path) {
    if (path.empty()) return false;

    FILE* f = _fsopen(path.c_str(), "wb", _SH_DENYNO);
    if (!f) return false;

    static const char* kTpl =
        "# ============================================================================\r\n"
        "# auto_research 权重配置\r\n"
        "# ============================================================================\r\n"
        "#\r\n"
        "# 【怎么用】\r\n"
        "#   1. 看完下面的说明\r\n"
        "#   2. 把 @mode 改成 take（不改成 take 的话只观察、不接管）\r\n"
        "#   3. 按需要取消注释或新增科技条目\r\n"
        "#   4. 保存即可，DLL 会自动重载（不用重启游戏）\r\n"
        "#\r\n"
        "# 【权重语义】\r\n"
        "#   > 0   候选里有权重最高的 → 一定选它（数值越大越优先，确定性不是随机）\r\n"
        "#   = 0   禁选，永远不选它\r\n"
        "#   < 0   候选里全是负数和 0 时，取数值最大的（-1 优于 -1000，即最接近 0 的优先）\r\n"
        "#   未配置 用下面的 @default\r\n"
        "#\r\n"
        "# 【并列怎么办】\r\n"
        "#   多个候选权重相同时，在这些并列者里【平均概率随机】选一个\r\n"
        "#\r\n"
        "# 【全禁会怎样】\r\n"
        "#   如果候选全是 0（全部禁选），会停止该领域研究 + 关闭该领域的自动科研\r\n"
        "#\r\n"
        "# ============================================================================\r\n"
        "\r\n"
        "@mode = observe\r\n"
        "@default = 100\r\n"
        "\r\n"
        "# ============================================================================\r\n"
        "# 示例（把行首的 # 去掉就生效）\r\n"
        "# ============================================================================\r\n"
        "\r\n"
        "# --- 必选：一级研究所 ---\r\n"
        "# tech_physics_1       = 101    # 量子计算\r\n"
        "# tech_society_1       = 101    # 异星生物学\r\n"
        "# tech_engineering_1   = 101    # 纳米力学\r\n"
        "\r\n"
        "# --- 禁选：永远不选 ---\r\n"
        "# tech_colonial_centralization = 0    # 殖民集中\r\n"
        "\r\n"
        "# --- 负数兜底：没有正数可选时才用，数值越大越优先 ---\r\n"
        "# tech_mountain_range  = -3     # 地表重塑\r\n"
        "# tech_volcano         = -7     # 地壳深部工程\r\n"
        "# tech_massive_glacier = -53    # 气候控制网络\r\n"
        "\r\n"
        "# ============================================================================\r\n"
        "# 你的配置写在这里（下面是空的）\r\n"
        "# ============================================================================\r\n"
        "\r\n"
        "\r\n";

    const size_t n = strlen(kTpl);
    const size_t w = fwrite(kTpl, 1, n, f);
    fclose(f);
    return (w == n);
}

static BOOL CALLBACK CfgInitOnce(PINIT_ONCE, PVOID, PVOID*) {
    g_cfgSource.SetPath(ConfigPath());
    g_watcher.setSource(&g_cfgSource);
    return TRUE;
}

// 热重载入口：每次决策前调用。内部只在 (存在性/时间戳/大小) 变化时才重读。
//   NoChange     → 配置未动
//   Reloaded     → 重新解析
//   Cleared      → 文件不在了，配置已重置为内置默认
//   ReadFailed   → 文件在但读不到，配置已重置为内置默认
static arcfg::PollResult PollConfig() {
    if (!g_cfgCsReady) return arcfg::PollResult::NoChange;
    InitOnceExecuteOnce(&g_cfgOnce, &CfgInitOnce, nullptr, nullptr);

    arcfg::PollResult r;
    int lines = 0, entries = 0, directives = 0, invalid = 0;
    std::string desc;
    EnterCriticalSection(&g_cfgCs);
    r = g_watcher.Poll(&g_cfg, CfgLogger(), "auto_research_weights.txt");
    if (r == arcfg::PollResult::Reloaded) {
        const arcfg::ParseStats& st = g_watcher.LastStats();
        lines = st.lines; entries = st.entries;
        directives = st.directives; invalid = st.invalid;
        desc = arcfg::Describe(g_cfg);
    }
    LeaveCriticalSection(&g_cfgCs);
    // 日志在锁外写，避免配置锁和日志锁叠在一起
    if (r == arcfg::PollResult::Reloaded)
        Log("[cfg] reloaded: %s | lines=%d entries=%d directives=%d invalid=%d",
            desc.c_str(), lines, entries, directives, invalid);

    // ========================================================================
    // ★★ 2026-11-20：文件不存在 → 写出模板（仅一次）★★
    // ========================================================================
    //
    // 【为什么放在这里】
    //   PollConfig 在初始化线程（ARENTRY）里调用，
    //   不在 DllMain（加载器锁下不能做文件 I/O）。
    //
    // 【仅一次】
    //   用 static 标志，避免用户删了模板后反复重建。
    //
    if (r == arcfg::PollResult::Cleared) {
        static volatile LONG s_tplTried = 0;
        if (InterlockedCompareExchange(&s_tplTried, 1, 0) == 0) {
            const std::string cfgPath = ConfigPath();
            if (WriteConfigTemplate(cfgPath)) {
                Log("[cfg] ★ 配置模板已创建: %s", cfgPath.c_str());
                Log("[cfg]   -> 所有条目都是注释，@mode=observe（只观察，不接管）");
                Log("[cfg]   -> 确认后把 @mode 改成 take 才会真正接管");
                Log("[cfg]   -> 保存即可，DLL 会自动重载（不用重启游戏）");
                // 忘掉状态 → 下次 Poll 必重载
                EnterCriticalSection(&g_cfgCs);
                g_watcher.Reset();
                LeaveCriticalSection(&g_cfgCs);
            } else {
                Log("[cfg] ⚠ 配置模板创建失败: %s", cfgPath.c_str());
                Log("[cfg]   请手动创建该文件，否则一直是 observe 模式");
            }
        }
    }
    return r;
}

// 快照当前配置（持锁拷贝，避免决策过程中被热重载打断）
__attribute__((unused))
static arcfg::Config ConfigSnapshot() {
    if (!g_cfgCsReady) return arcfg::Defaults();
    EnterCriticalSection(&g_cfgCs);
    arcfg::Config c = g_cfg;
    LeaveCriticalSection(&g_cfgCs);
    return c;
}

static bool TakeMode() {
    if (!g_cfgCsReady) return false;
    EnterCriticalSection(&g_cfgCs);
    bool t = (g_cfg.mode == arcfg::Mode::Take);
    LeaveCriticalSection(&g_cfgCs);
    return t;
}

// 注：曾经有个 DryRunMode() 辅助函数，但实际决策走的是
// arcfg::ShouldPatchReturnAddress(cfg.mode)（在 Init 里赋值给 g_ar2DoPatch）。
// 那个辅助函数从未被调用，属于「写了但没接线」—— 2026-11-11 删除。
// 保留此说明，避免将来有人又重新加回来。

// ================= 游戏结构 =================

// 读游戏的 string 类（s = string 对象指针）
// 布局(反编译 FUN_140425550 确认): +0x00 buf[16]|ptr, +0x10 size, +0x28 cap
// ★ out 的内容是【本地化后的中文显示名】(如 "克隆")，不是内部 key!
//   实测: E5 85 8B E9 9A 86 = "克隆", size=6, cap=15
static bool ReadStdString(const void* s, std::string* out) {
    if (!s || !SafeReadable(s, 0x30)) return false;
    // 真实布局(raw dump 确认): +0x10 buf[16]|ptr, +0x20 size, +0x28 cap
    uint64_t size = *(volatile uint64_t*)((const uint8_t*)s + 0x20);
    uint64_t cap  = *(volatile uint64_t*)((const uint8_t*)s + 0x28);
    if (size == 0 || size > 64) return false;
    const char* p = (cap > 15)
        ? *(const char* volatile*)((const uint8_t*)s + 0x10)
        : (const char*)((const uint8_t*)s + 0x10);
    if (!SafeReadable(p, size + 1)) return false;
    for (uint64_t i = 0; i < size; i++) {
        unsigned char ch = (unsigned char)p[i];
        // 接受 ASCII 可见字符 + UTF-8 多字节(>=0x80)
        if (ch < 0x20 || ch == 0x7F) return false;
    }
    out->assign(p, size);
    return true;
}

// hex dump（诊断用）：打印 ptr 处 n 字节
static void HexDump(const char* tag, const void* ptr, size_t n) {
    if (!SafeReadable(ptr, n)) {
        Log("        %s @%p <unreadable>", tag, ptr);
        return;
    }
    const uint8_t* b = (const uint8_t*)ptr;
    for (size_t off = 0; off < n; off += 16) {
        char line[80]; int pos = 0;
        pos += snprintf(line + pos, sizeof(line) - pos, "        %s+%02zx:", tag, off);
        for (size_t i = 0; i < 16 && off + i < n; i++)
            pos += snprintf(line + pos, sizeof(line) - pos, " %02X", b[off + i]);
        Log("%s", line);
    }
}

// ================= 决策数据采集（只读，不改写任何游戏内存） =================
//
// 本段全部依据 auto_research_handoff\team\FINDINGS_hook_contract.md。
// 每处偏移都标了证据出处；FINDINGS §8.3 标注「未验证」的一律加防御性检查，
// 读不到就返回失败，让调用方退回游戏原选择。
//
// 已废弃的旧假设（FINDINGS §8.2，不得再用）：
//   x arg1 + 0x314C == 0 判玩家  —— arg1 上无此字段，恒 0
//   x +0x9B8/+0x9C4 当候选卡      —— 那是 technology_swap 交换技术表
//   x 改 out 来接管选择            —— out 只是消息插值参数

// 候选卡（玩家 UI 上看到的那 2-3 个）在 country 上：
//   FINDINGS §2.3 / v1_realpicker.txt:690-706
//     country + 0x31B0 = 候选 tech id 数组（int32 数组）
//     country + 0x31BC = 候选数
//     country + 0x31D8 = 权重数组，每项 0x10 字节
//
// FINDINGS §8.3 明确标注：`country+0x31BC` 的实际上限（MOD/内阁能否到 67）
// 属「未验证」，需运行时 dump。所以这里做严格的值域检查，超范围直接放弃。
static constexpr uint32_t kCountryCandIds   = 0x31B0;
static constexpr uint32_t kCountryCandCount = 0x31BC;
static constexpr uint32_t kCountryCandWeigh = 0x31D8;
static constexpr int      kCandCountMax     = 128;   // 远比 67 宽松，只挡垃圾值
// ---------- take 链路推导结果（由 InstallAll 的阶段 6.5 填充）----------
//
// 这些值来自【形状推导】，不是硬编码。
// 用途与约束：
//   - 候选卡偏移优先用 g_cardCountOff / g_cardArrayOff（若 g_cardLayoutValid）
//   - 推导失败时 g_cardLayoutValid=false，readCandidateCards 应降级（返回 false）
//   - 【绝不】在推导失败时回退到 kCountryCandCount / kCountryCandIds
//     （那两个常量只保留作对照告警）
static void*    g_takeE4B0        = nullptr;   // E4B0 函数指针（研究槽决策）
static void*    g_takeC890        = nullptr;   // C890 函数指针（权重计算）
static bool     g_cardLayoutValid = false;     // 候选卡布局是否推导成功
static uint32_t g_cardCountOff    = 0;         // 推导出的 count 偏移
static uint32_t g_cardArrayOff    = 0;         // 推导出的 array 偏移
static uint32_t g_cardElemSize    = 0;         // 推导出的元素字节数


struct CandidateCard {
    int32_t  techId = 0;
    uint64_t weight = 0;
};

// 从 country 读候选卡。返回 false 表示读不到/数据可疑 → 调用方必须放弃接管。
static bool ReadCandidateCards(void* country, std::vector<CandidateCard>* out) {
    if (!out) return false;
    out->clear();
    if (!country) return false;
    uint8_t* c = (uint8_t*)country;

    if (!SafeReadable(c + kCountryCandCount, 4)) return false;
    int32_t count = *(volatile int32_t*)(c + kCountryCandCount);
    if (count <= 0 || count > kCandCountMax) return false;

    if (!SafeReadable(c + kCountryCandIds, 8)) return false;
    void* idsPtr = *(void* volatile*)(c + kCountryCandIds);
    if (!idsPtr) return false;
    if (!SafeReadable(idsPtr, (size_t)count * 4)) return false;

    if (!SafeReadable(c + kCountryCandWeigh, 8)) return false;
    void* wPtr = *(void* volatile*)(c + kCountryCandWeigh);
    if (!wPtr) return false;
    if (!SafeReadable(wPtr, (size_t)count * 0x10)) return false;

    for (int32_t i = 0; i < count; ++i) {
        CandidateCard cd;
        cd.techId = *(volatile int32_t*)((uint8_t*)idsPtr + (size_t)i * 4);
        cd.weight = *(volatile uint64_t*)((uint8_t*)wPtr + (size_t)i * 0x10);
        // tech id 是索引，负值/超大值都是垃圾
        if (cd.techId < 0 || cd.techId > 0x100000) { out->clear(); return false; }
        out->push_back(cd);
    }
    return !out->empty();
}

// ================= 决策 =================
// 权重语义完全交给 ar_config.h 的 PickBest()（纯函数，离线自测覆盖）：
//   > 0 → 最大者胜；0 → 禁选；< 0 → 只在没有正数候选时按绝对值最大兜底
//
// 返回: 0=负数兜底 1=正数胜出 2=停止研究 / 放弃接管
//
// ⚠️ 当前【未接线】：候选卡 tech id → 内部 key 的映射链依赖 status 与 country
//    的关系（FINDINGS §8.3 标未验证）。等那条链验证通过后，
//    本函数会接入 FUN_14081C890 的 hook，用于按配置改写权重。
//    在此之前保持只评估、不写内存，并由 __attribute__((unused)) 标注。
// 注意：本函数只【评估】，不改写任何游戏内存。
__attribute__((unused))
static int Decide(void* country, int* bestIdx, long long* bestW,
                  std::vector<std::string>* namesOut) {
    if (bestIdx) *bestIdx = -1;
    if (bestW) *bestW = 0;
    if (namesOut) namesOut->clear();

    std::vector<CandidateCard> cards;
    if (!ReadCandidateCards(country, &cards)) return 2;

    // 候选卡里只有 tech id（整数索引），没有内部 key 字符串。
    // 要把 id 映射成 key 需要「全量科技表 status+0x978/+0x984」（FINDINGS §2.2），
    // 但 FINDINGS §8.3 明确说 `status` 与 `country` 的偏移关系【未验证】。
    // 在拿到这条链之前，我们无法把候选卡映射成配置里的科技 key。
    //
    // => 这里明确返回「无法决策」，由调用方退回游戏原选择。
    return 2;
}

// ================= hook =================

extern "C" __fastcall void ARLog(void* country, void* out, int decided,
                                const char* name, long long w);

// naked 入口: RCX=country, RDX=out(sret std::string*)
// RSP 保持一致后 jmp trampoline；observe 模式下只记录不接管
extern "C" uint8_t* g_arTramp = nullptr;   // 安装成功后填入 trampoline

// ---------- take 模式: 返回地址改写 ----------
extern "C" void* g_retAddr = nullptr;     // 真实返回地址
extern "C" void* g_arRetSlot = nullptr;    // rax 暂存槽
extern "C" void* g_curOut   = nullptr;    // 本次调用的 out 参数
extern "C" void* g_curObj   = nullptr;    // 本次调用的 param_1(上下文)
extern "C" void* g_arSlot   = nullptr;    // hook A: 最近的研究槽管理器
extern "C" uint8_t* g_trampA = nullptr;   // hook A trampoline

// 游戏的 std::string 操作函数（构造/析构）
// 注：原 StrCtorFn / StrDtorFn / GetPlayerFn 三个函数指针（及对应全局变量）
// 已于 2026-11-12 删除。它们是死代码 —— 只被赋值、从未被调用。

// hook A: FUN_14081A900 入口 (slotmgr, tech, param3)
//   只记录三个参数 + 调用者返回地址, 然后原样执行（不改写任何东西）
// AREntryA 的参数快照（供 ARAfter2 使用）
static volatile LONG g_startSeq = 0;
extern "C" void*   g_ar2Tech   = nullptr;   // param_2 (RDX) = 要开始研究的科技对象
extern "C" void*   g_ar2Tramp  = nullptr;
extern "C" uint8_t g_ar2Param3 = 0;        // param_3 (R8B)，低 8 位
// 安装时按配置决定是否改写返回地址：
//   1 = 正常（改写 → ARAfter2）
//   0 = dryrun（只记录参数，不改写；用于单独验证 patch 本身是否安全）
// 注意：只在安装时读一次配置。运行中切换 @mode 需要重启游戏才生效 ——
// dryrun 是验证档，不做热切换是刻意的（避免改写状态与配置不一致）。
extern "C" uint8_t g_ar2DoPatch = 1;
// hookA 侧只记录到这两个变量（不调任何函数），由主 hook 输出日志。
extern "C" void*    g_pendingStartTech  = nullptr;
extern "C" uint64_t g_pendingStartValid = 0;
// 2026-11-12 修复：此前只挂起 tech，caller/param3 被 FlushPendingStart 硬编码传 0，
// 导致日志里 caller=0x0 site=0x0，无法区分「手动选科技」与「give_technology」。
// 现在在 ARAfter2 里一并转存（只做 mov，不 call —— 保持"裸汇编不调 C 函数"原则）。
extern "C" uint64_t g_pendingCaller  = 0;
extern "C" uint32_t g_pendingParam3  = 0;
extern "C" void*   g_ar2Caller = nullptr;  // hookA 的返回地址 = 调用者体内下一条指令

// 后处理: 原函数跑完 → 记录"开始了哪个科技" + 三个参数 + 调用者
extern "C" __attribute__((naked)) void ARAfter2();
__asm__(
    ".text\n"
    ".globl ARAfter2\n"
    "ARAfter2:\n"
    // ============================================================
    // 本函数由【原函数的 ret】跳入。历史上这里有两个致命缺陷：
    //   1) jmp *g_ar2Tramp —— trampoline 是【入口】不是函数，跳回去
    //      会重放序言并再跑一遍函数体，且此时 RSP 已回到调用者视角，
    //      重放的 home-space 写入会踩坏调用者栈帧 → ret 弹出垃圾 → 崩。
    //   2) 里面 call ARLogStart —— 本函数被 ret 跳入时 rsp%16==0，
    //      而 7 个 push 后变成 8；Win64 ABI 要求 call 前 rsp%16==0，
    //      sub 取 0x30 或 0x38 都只是在给一个【本不该存在的 call】
    //      打补丁，永远有踩空的风险。
    //
    // 结论：**不在裸汇编里 call 任何 C 函数**，直接消除这一类风险。
    //   ARAfter2 只做一件事：把 tech 指针存进全局，然后跳回真实调用者。
    //   日志由主 hook（ARProcess，栈环境正常）在下次被调用时输出。
    // ============================================================
    "  mov g_ar2Tech(%rip), %rax\n"       // 只取指针，不调函数
    "  mov %rax, g_pendingStartTech(%rip)\n"  // 挂起，等主 hook 输出
    // 2026-11-12：连带转存 caller/param3，否则日志永远是 0。
    // 只做 mov，不 call —— 本函数由 ret 跳入，栈状态非标准。
    "  mov g_ar2Caller(%rip), %rax\n"
    "  mov %rax, g_pendingCaller(%rip)\n"
    "  mov g_ar2Param3(%rip), %eax\n"
    "  mov %eax, g_pendingParam3(%rip)\n"
    "  movq $1, g_pendingStartValid(%rip)\n"
    "  jmp *g_ar2Caller(%rip)\n"          // 跳真实调用者（不是 trampoline）
);

// ================= hookA 只读诊断（步骤 1：只观察，不改写） =================
//
// 为什么先只读：
//   候选卡 tech id → 内部 key 的映射链依赖 `status` 与 `country` 的关系，
//   FINDINGS §8.3 明确标注【未验证】。在没验证之前写内存 = 拿用户游戏冒险。
//   本步骤的唯一目的：用日志证明「我们读到的科技 key 就是玩家看到的那张卡」。
//
// 验证方法（写给用户看的）：
//   开游戏 → 研究槽空出来 → 看日志里的 `[pick] selected=` 是否与 UI 上选中的科技一致。
//   如果一致 → 偏移理解正确，可以进步骤 2（改写）。
//   如果不一致 → 偏移错了，停下来，不写任何内存。

// 前向声明：定义在 hook 区（依赖 g_arSlot），这里先用
// ============================================================================
// 2026-11-15 修复：IsPlayerContext 的时序 bug
// ============================================================================
//
// 【旧实现的 bug】
//   static bool IsPlayerContext() {
//       void* country = *(g_arSlot + 0x10);   // ← g_arSlot 是【全局最近一次】
//       return *(country + 0x314C) == 0;
//   }
//
//   g_arSlot 在 hookA 里被覆盖，而 obj（param_2）是【当次】的 tech 对象。
//   两者不配套 → 同一个 tech 在不同时刻被标成不同的 PLAYER/ai。
//   实测：obj=be9c1ac0 第2条记录是 ai，第8条记录是 PLAYER。
//
// 【修法】
//   改成传入【当次的 country】，由调用方给出：
//     hookA 侧：   country = *(g_arSlot + 0x10)      （当次 hookA 的 slot）
//     C890 侧：    country = *(param_1 + 0x10)       （当次 C890 的 slot）
//   不再依赖任何全局「最近一次」。
//
// 【仍然未验证的两层】
//   ① slotmgr + 0x10 是否真的 == country
//   ② country + 0x314C 是否真的是「非玩家标志」
//   本次日志同时记录 slot / country / isai_val，用真机数据验证这两层。
// ============================================================================

// ============================================================================
// 2026-11-17 修复（重要）：判据原先写反了
// ============================================================================
//
// 【旧实现（错）】
//   return *(int32_t*)(country + 0x314C) == 0;      // ← 把 == 0 当成玩家
//
// 【游戏真实判据 is_human @ 0xD18175（逐字节，来源 PLAYER_CRITERION_HUNT.md §3.2）】
//   0xD18175  83 B8 4C 31 00 00 00   CMP dword [RAX+0x314C], 0
//   0xD1817C  74 0D                  JE  0xD1818B          ; == 0  → DL=0（不是人类）
//   0xD1817E  80 3D AE 36 B0 01 00   CMP byte [0x281B833], 0
//   0xD18185  75 04                  JNE 0xD1818B          ; != 0  → DL=0
//   0xD18187  B2 01                  MOV DL,1              ; 两者都满足 → DL=1
//   0xD1818B  32 D2                  XOR DL,DL
//   0xD1818D  4C 8D 05 DC 72 63 01   LEA R8,"is_human"     ; 注册条件名
//
//   ⇒ is_human = (country[+0x314C] != 0) AND (byte[0x281B833] == 0)
//
// 【真机实测（2026-11-17，238 条 [bp] + 31 条 [hookA]）】
//   g833 == 0 在 238/238 条成立 —— 单人游戏下它恒 0。
//   所以 is_human 在本场景等价于 (country[+0x314C] != 0)。
//
//   ★ 但我们【保留】g833 这个条件，不简化成单条件。原因：
//     · 它是游戏原判据的一部分（0xD1817E 那条 CMP），删掉就与游戏不一致；
//     · 多人 / observer / 异步存档下它可能非 0，那时简化版会误判为玩家；
//     · 保留的代价是每次读一个字节，可忽略。
//
//   实测佐证判据确实在区分（不是恒真）：
//     isai=1（cid=0，30 条） → PLAYER-by-current-slot   ← 玩家国
//     isai=0（cid=13，1 条） → ai-by-current-slot       ← AI 国
//   同一份日志里两个分支都被走到，说明判据有分辨力。
//
// 【同构证据】0x6F2590 的守卫（0x6F32D0）与之同构：
//   0x6F32D0  CMP dword [RBX+0x314C], 0
//   0x6F32D7  JE  0x6F3372 (ret)      ; == 0 → 直接返回
//   ⇒ 0x6F2590 只在 +0x314C != 0 时执行，与 is_human 的必要条件一致。
//   ⇒ 所以 0x6F2590 是【玩家路径】，不是 AI 路径（旧结论已推翻）。
//
// 【影响面】旧判据（== 0）把方向搞反了：
//   · 修复前：take 只对 +0x314C == 0 的国家生效 → 实际作用于【AI】
//   · 修复后：take 只对 +0x314C != 0 且 g833 == 0 → 真正作用于【人类玩家】
//   ⚠️ 这是行为变更，不是纯标签修正。
//
// 【注意】isai 日志字段仍打印 +0x314C 的原始值（便于核对），
//   但 player 标签现在按上面的真实语义计算。
//   旧日志里的 "ai-by-current-slot" 多半其实是玩家 —— 阅读历史日志时必须记住这一点。
// ============================================================================

// 判据（与游戏 is_human 一致）：
//   country[+0x314C] != 0  AND  byte[g_base+0x281B833] == 0
// 调用方必须传【当次】的 country，不允许传全局缓存。
static bool IsCountryPlayer(void* country) {
    if (!country) return false;
    if (!SafeReadable((uint8_t*)country + 0x314C, 4)) return false;
    // 必要条件 1：+0x314C != 0（== 0 时 is_human 必为 false）
    if (*(volatile int32_t*)((uint8_t*)country + 0x314C) == 0) return false;
    // 必要条件 2：全局字节 0x281B833 == 0（多人/非人控时为非 0）
    if (!g_base) return false;
    if (!SafeReadable((void*)(uintptr_t)(g_base + 0x281B833), 1)) return false;
    return *(volatile uint8_t*)(uintptr_t)(g_base + 0x281B833) == 0;
}

// 从 slotmgr 取 country（当次）。失败返回 nullptr。
static void* CountryFromSlot(void* slot) {
    if (!slot || !SafeReadable(slot, 0x18)) return nullptr;
    void* c = *(void* volatile*)((uint8_t*)slot + 0x10);
    if (!c || !SafeReadable(c, 0x3150)) return nullptr;
    return c;
}

// 兼容旧调用点：仍用全局 g_arSlot，但标注 deprecated。
// 新代码一律用 IsCountryPlayer(CountryFromSlot(slot))。
static bool IsPlayerContext() {
    return IsCountryPlayer(CountryFromSlot(g_arSlot));
}


static bool IsPlayerContext();

// tech+0x350 = std::string 对象起点
//   +0x360 = buf  /  +0x370 = size  /  +0x378 = cap       (FINDINGS §6，决定性证据)
static constexpr uint32_t kTechKeyString = 0x350;
static constexpr uint32_t kTechKeyBuf    = 0x360;
static constexpr uint32_t kTechKeySize   = 0x370;
static constexpr uint32_t kTechKeyCap    = 0x378;

// 读一个科技/swap 元素对象的内部 key。成功返回 true 并填 out。
// 任何一步不可读或数据可疑 → false（调用方必须放弃，不许猜）。
static bool ReadTechKey(void* tech, std::string* out) {
    if (!out || !tech) return false;
    uint8_t* t = (uint8_t*)tech;
    // 覆盖 0x350..0x380 整个 string 头
    if (!SafeReadable(t + kTechKeyString, (kTechKeyCap + 8) - kTechKeyString)) return false;
    uint64_t size = *(volatile uint64_t*)(t + kTechKeySize);
    uint64_t cap  = *(volatile uint64_t*)(t + kTechKeyCap);
    if (size == 0 || size > 64) return false;
    if (cap < size) return false;                       // 容量不可能小于长度
    const char* p = (cap > 15) ? *(const char* volatile*)(t + kTechKeyBuf)
                               : (const char*)(t + kTechKeyBuf);
    if (!SafeReadable(p, (size_t)size + 1)) return false;
    for (uint64_t i = 0; i < size; ++i) {
        char ch = p[i];
        if (!((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_')) return false;
    }
    out->assign(p, (size_t)size);
    return true;
}

// 记录"开始研究"（hookA 的参数 param_2 = 即将开始研究的科技对象）

// =====================================================================
// tech 对象身份诊断（2026-11-12，一次性）
// =====================================================================
//
// 为什么需要它：hookA 的 tech key 从未成功读出过（历史日志 0 条成功记录）。
// 已尝试并失败的方法：布局 A、布局 B、长度匹配、hexdump 统计。
// 这次改为【直接读取证据】，不再猜偏移。
//
// 【停止条件】如果本次 dump 后仍无法确定 tech key 位置：
//   → 放弃「从 hookA 读 tech key」
//   → 转 C890 方案（按 tech id 禁选）
//   → id→key 映射另寻途径（全量科技表 或 本地化 key 反推）
// ============================================================
static void DumpTechIdentity(void* tech) {
    if (!tech || !SafeReadable(tech, 0x400)) {
        Log("  [dump] 对象不可读，跳过");
        return;
    }
    uint8_t* t = (uint8_t*)tech;
    auto u64 = [&](uint32_t off) -> uint64_t {
        if (!SafeReadable(t + off, 8)) return 0;
        return *(volatile uint64_t*)(t + off);
    };

    // 1) 对象头：判断是否多态对象（vptr 指向 .rdata）
    HexDump("  obj+0x000", t, 0x20);

    // 2) 关键区域：0x340..0x3B0
    HexDump("  obj+0x340", t + 0x340, 0x70);

    // 3) 三个候选的 (buf/size/cap) 组合 —— 一次日志就能看出哪个像 std::string
    //    MSVC x64 std::string 标准布局：对象+0x00=buf, +0x10=size, +0x18=cap
    Log("  cand A (obj 起点设为 0x360):  buf=%llu size=%llu cap=%llu",
        (unsigned long long)u64(0x360), (unsigned long long)u64(0x370),
        (unsigned long long)u64(0x378));
    Log("  cand B (obj 起点设为 0x368):  buf=%llu size=%llu cap=%llu",
        (unsigned long long)u64(0x368), (unsigned long long)u64(0x378),
        (unsigned long long)u64(0x380));
    Log("  cand C (obj 起点设为 0x350):  buf=%llu size=%llu cap=%llu",
        (unsigned long long)u64(0x350), (unsigned long long)u64(0x358),
        (unsigned long long)u64(0x360));

    // 4) 如果某个候选的 buf 像合法指针，读它指向的内容
    struct C { const char* name; uint32_t off; };
    const C cands[] = { {"A", 0x360}, {"B", 0x368}, {"C", 0x350} };
    for (size_t i = 0; i < 3; ++i) {
        uint64_t p = u64(cands[i].off);
        if (p > 0x10000 && p < 0x7FFFFFFFFFFFULL &&
            SafeReadable((void*)p, 64)) {
            char tag[48];
            snprintf(tag, sizeof(tag), "  buf@%s(0x%X) ->", cands[i].name, cands[i].off);
            HexDump(tag, (uint8_t*)p, 64);
        }
    }

    // 5) SSO 内联内容：字符串内容可能就在对象内部，不在指针里
    HexDump("  inline@350", t + 0x350, 0x20);
    HexDump("  inline@360", t + 0x360, 0x20);
    HexDump("  inline@368", t + 0x368, 0x20);
}

// 形态指纹 + 计数：前 5 次必 dump，之后仅形态变化时 dump，最多 10 次
static void MaybeDumpTechIdentity(void* tech) {
    static volatile LONG s_seq = 0;
    static volatile LONG s_dumps = 0;
    static uint64_t s_seen[32];
    static volatile LONG s_seenN = 0;

    LONG seq = InterlockedIncrement(&s_seq);
    if (InterlockedCompareExchange(&s_dumps, 0, 0) >= 10) return;

    // 形态指纹：读 4 个关键字段，组合成一个 hash
    uint64_t fp = 0;
    if (tech && SafeReadable(tech, 0x390)) {
        const uint8_t* t = (const uint8_t*)tech;
        uint64_t v360 = *(const volatile uint64_t*)(t + 0x360);
        uint64_t v368 = *(const volatile uint64_t*)(t + 0x368);
        uint64_t v370 = *(const volatile uint64_t*)(t + 0x370);
        uint64_t v378 = *(const volatile uint64_t*)(t + 0x378);
        bool n360 = (v360 > 0x10000 && v360 < 0x7FFFFFFFFFFFULL);
        bool n368 = (v368 > 0x10000 && v368 < 0x7FFFFFFFFFFFULL);
        fp = (uint64_t)n360 | ((uint64_t)n368 << 1) |
             ((v370 > 0 && v370 < 0x10000 ? 1ULL : 0ULL) << 2) |
             ((v378 > 0 && v378 < 0x10000 ? 1ULL : 0ULL) << 3);
    }

    bool shouldDump = (seq <= 5);
    if (!shouldDump) {
        // 形态是否见过
        LONG n = s_seenN;
        bool seen = false;
        for (LONG i = 0; i < n && i < 32; ++i) if (s_seen[i] == fp) { seen = true; break; }
        if (!seen) {
            shouldDump = true;
            if (n < 32) { s_seen[n] = fp; InterlockedIncrement(&s_seenN); }
        }
    }

    if (shouldDump) {
        LONG dn = InterlockedIncrement(&s_dumps);
        Log("  [dump #%ld] seq=%ld fingerprint=0x%llX", (long)dn, (long)seq,
            (unsigned long long)fp);
        DumpTechIdentity(tech);
    }
}



// ============================================================================
// ============================================================================
// 探针开关：默认 0（干净版）
//   1 = 编译 C890/SEL 只读探针（调试用，日志量大）
//   0 = 不编译（产品用）
// ============================================================================
// ============================================================================
// ★★ 2026-11-18：构建变体总开关 ★★
// ============================================================================
//
// 用法：
//   使用版（用户装）：  -DAR_BUILD_WITH_PROBES=0
//   维护版（排查用）：-DAR_BUILD_WITH_PROBES=1
//
// 当下面两行都被注释时，默认值在文件底部附近定义。
//
// 使用版关闭：
//   AR_ENABLE_PROBES     —— C890/SEL/LogCallStack/InstallTakeover(v1) 全部探针
//   AR_ENABLE_RP_PROBE   —— [rp] 科研槽探针
//   AR_ENABLE_BP_PROBE   —— [bp] AI 路径探针
//
// 两版都保留（与接管相关）：
//   AR_TAKEOVER_V2_DRYRUN（接管开关）、IsCountryPlayer、SafeReadable、配置热重载
//
#ifndef AR_BUILD_WITH_PROBES
#define AR_BUILD_WITH_PROBES 1
#endif

// ---- 由总开关派生各探针开关 ----
// 读 tech 对象的 key（按实测布局 tech+0x20）
static bool TkReadKey(void* tech, char* out, size_t outCap) {
    if (!tech || !out || outCap < 8) return false;
    if (!SafeReadable((uint8_t*)tech + 0x20, 0x20)) return false;
    uint8_t* obj = (uint8_t*)tech + 0x20;
    const uint64_t sz  = *(volatile uint64_t*)(obj + 0x10);
    const uint64_t cap = *(volatile uint64_t*)(obj + 0x18);
    if (sz == 0 || sz >= 64 || cap < sz) return false;
    const char* p = (cap > 15) ? *(const char* volatile*)obj : (const char*)obj;
    if (!p || !SafeReadable(p, (size_t)sz)) return false;
    for (uint64_t i = 0; i < sz; ++i) {
        const char c = p[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_')) return false;
    }
    const size_t k = (sz < outCap - 1) ? (size_t)sz : outCap - 1;
    memcpy(out, p, k);
    out[k] = 0;
    return true;
}

#if AR_BUILD_WITH_PROBES
  #ifndef AR_ENABLE_PROBES
  #define AR_ENABLE_PROBES     1
  #endif
// ============================================================================
// ★ ★ ★ 2026-11-18：TkReadKey 已移出探针块 ★ ★ ★
//
// 原因：AR_TakeoverV2 的 [PICK] 日志需要读候选 key，
//   但 TkReadKey 原本被 #if AR_ENABLE_RP_PROBE 包住，
//   使用版（PROBES=0）编译时不存在 → 链接错误。
//   现在把它提到探针块之外，两版都能用。
// ============================================================================

  #ifndef AR_ENABLE_RP_PROBE
  #define AR_ENABLE_RP_PROBE   1
  #endif
  #ifndef AR_ENABLE_BP_PROBE
  #define AR_ENABLE_BP_PROBE   0   // AI 路径已确认无用，两版都关
  #endif
#else
  #ifndef AR_ENABLE_PROBES
  #define AR_ENABLE_PROBES     0
  #endif
  #ifndef AR_ENABLE_RP_PROBE
  #define AR_ENABLE_RP_PROBE   0
  #endif
  #ifndef AR_ENABLE_BP_PROBE
  #define AR_ENABLE_BP_PROBE   0
  #endif
#endif

#ifndef AR_ENABLE_PROBES
#define AR_ENABLE_PROBES 0
#endif

#if AR_ENABLE_PROBES
// SEL 探针（0x81A5B0）：take 接管点候选（2026-11-15）
// ============================================================================
//
// 【为什么是它】
//   re-analyst 五条判据 + captain 独立核实：
//     +0x31BC ×4 / +0x31B0 ×4 / +0x31D8 ×4   读候选三件套
//     CMOVcc ×4                               取最大形状（严格更大才替换）
//     +0x314C ×0                             不区分玩家/AI
//     MISSING_HEAD_OF_RESEARCH 唯一引用 = 它的 0x81B25C
//     跨 6 版本 CMOV 恒为 4
//
// 【参数布局（re-analyst 查清）】
//   param_1 (RCX) → tech-status 对象（只读 +0x9F8 的位）
//   param_2 (RDX) → 容器
//   country = *(param_2 + 0x10)      ← 关键
//    证据：0x81A79F MOV R9,[R13+0x10] → 0x81A7A5 MOV ECX,[R9+0x31BC]
//
// 【本探针只做入口只读观测】
//   不做出 hook、不改返回值、不改内存。
//   要回答：count 是 2-8（候选）还是 47（全部可研）？
// ============================================================================

extern "C" void* g_selTramp = nullptr;
static void*     g_selTarget = nullptr;
static bool      g_selProbeInstalled = false;

static volatile LONG s_selSeq    = 0;
static volatile LONG s_selCount  = 0;
static volatile LONG s_selLogged = 0;
static uint64_t      s_selP3Set[64] = {0};
static volatile LONG s_selUniqP3 = 0;

static bool SelTrackP3(uint64_t v) {
    if (v == 0) return false;
    LONG n = s_selUniqP3;
    for (LONG i = 0; i < n && i < 64; ++i) if (s_selP3Set[i] == v) return false;
    if (n < 64) { s_selP3Set[n] = v; InterlockedIncrement(&s_selUniqP3); return true; }
    return false;
}

extern "C" void SelLog(void* p1, void* p2, void* p3, void* p4) {
    LONG seq = InterlockedIncrement(&s_selSeq);
    InterlockedIncrement(&s_selCount);

    // country = *(p2 + 0x10)，全部 SafeReadable 包裹
    void* country = nullptr;
    if (p2 && SafeReadable(p2, 0x18))
        country = *(void* volatile*)((uint8_t*)p2 + 0x10);

    int32_t count = -1, isai = -1;
    if (country && SafeReadable(country, 0x31D0)) {
        count = *(volatile int32_t*)((uint8_t*)country + 0x31BC);
        isai  = *(volatile int32_t*)((uint8_t*)country + 0x314C);
    }
    uint32_t bits = 0;
    bool haveBits = false;
    if (p1 && SafeReadable((uint8_t*)p1 + 0x9F8, 4)) {
        bits = *(volatile uint32_t*)((uint8_t*)p1 + 0x9F8);
        haveBits = true;
    }

    const uint64_t p3v = (uint64_t)(uintptr_t)p3;
    bool isNew = SelTrackP3(p3v);

    LONG logged = InterlockedCompareExchange(&s_selLogged, 0, 0);
    bool shouldLog = (logged < 200);
    if (!shouldLog && isNew) shouldLog = true;
    if (!shouldLog) return;
    InterlockedIncrement(&s_selLogged);

    Log("[sel] seq=%ld tick=%llu p1=%p p2=%p p3=%p p4=%p country=%p count=%d isai=%d bits9f8=0x%X%s",
        (long)seq, (unsigned long long)GetTickCount64(), p1, p2, p3, p4,
        country, (int)count, (int)isai, (unsigned)bits, haveBits ? "" : "(noread)");

    // ★ D6: hexdump(param_2, 0x20)
    //   判读：+0x10 应是 country 指针；+0x08/+0x14 是容器 ptr/count
    //   只在前 20 条记录时 dump（避免日志爆炸）
    if (logged < 20 && p2 && SafeReadable(p2, 0x20)) {
        HexDump("  p2dump", p2, 0x20);
    }

    // ★ D9: 遍历候选表（只在 count 合理且前几条记录时）
    //
    // 目的：验证 +0x31D8 存的是「权重」还是「成本」
    //   判据：
    //     · 若 w8 量级 0-100000 且与 tech tier 正相关 → 更像权重
    //     · 若 w8 与 tech cost 正相关              → 更像成本
    //   同时验证元素步长是 8 还是 0x10
    //
    if (logged < 10 && count > 0 && count < 20 && country
        && SafeReadable(country, 0x31E0)) {
        int32_t* ids = *(int32_t* volatile*)((uint8_t*)country + 0x31B0);
        uint8_t*  w   = *(uint8_t*  volatile*)((uint8_t*)country + 0x31D8);
        if (ids && w && SafeReadable(ids, (size_t)count * 4)
                   && SafeReadable(w, (size_t)count * 8)) {
            Log("[sel] candidates (count=%d):", (int)count);
            for (int i = 0; i < count; ++i) {
                uint64_t w8 = *(uint64_t volatile*)(w + (size_t)i * 8);
                double   dw = 0.0;
                memcpy(&dw, &w8, sizeof(dw));
                Log("    [%d] id=%-5d w8=0x%016llX  as_i64=%-12lld  as_dbl=%g",
                    i, (int)ids[i], (unsigned long long)w8,
                    (long long)(int64_t)w8, dw);
            }
        }
    }


}

static void SelLogSummary() {
    Log("[sel] === summary: total=%ld logged=%ld uniq_p3=%ld ===",
        (long)InterlockedCompareExchange(&s_selCount, 0, 0),
        (long)InterlockedCompareExchange(&s_selLogged, 0, 0),
        (long)InterlockedCompareExchange(&s_selUniqP3, 0, 0));
}

extern "C" __attribute__((naked)) void SelEntry();
__asm__(
    ".text\n"
    ".globl SelEntry\n"
    "SelEntry:\n"
    // 入口: rsp%16==8；7 次 push(56) → (8-56)%16==0 已对齐，不许 sub
    // 参数: RCX=p1 RDX=p2 R8=p3 R9=p4
    "  push %rax\n"
    "  push %rcx\n"
    "  push %rdx\n"
    "  push %r8\n"
    "  push %r9\n"
    "  push %r10\n"
    "  push %r11\n"
    // == C890 stub: reserve own shadow space (7 push -> R-56, then sub 0x20 -> R-88)
    "  sub $0x20, %rsp\n"
    "  mov 56(%rsp), %r8\n"      // p3  [R-32]
    "  mov 64(%rsp), %rdx\n"     // p2  [R-24]
    "  mov 72(%rsp), %rcx\n"     // p1  [R-16]
    "  mov 48(%rsp), %r9\n"      // p4  [R-40]
    "  call SelLog\n"
    "  add $0x20, %rsp\n"
    "  pop %r11\n"
    "  pop %r10\n"
    "  pop %r9\n"
    "  pop %r8\n"
    "  pop %rdx\n"
    "  pop %rcx\n"
    "  pop %rax\n"
    "  jmp *g_selTramp(%rip)\n"
);

// 安装：0x81A5B0 前 19 字节（4 条 shadow-store）→ 绝对跳转
static bool InstallSelProbe(uint32_t selRva) {
    g_selTarget = (void*)(g_base + selRva);
    if (!SafeReadable(g_selTarget, 20)) {
        Log("[sel] probe: target not readable -> skip");
        return false;
    }
    // ★ 20 字节：4 条 shadow-store（5+5+5+5）
    static const uint8_t kExpect[20] = {
        0x48,0x89,0x5C,0x24,0x08,   // mov [rsp+0x08], rbx
        0x4C,0x89,0x4C,0x24,0x20,   // mov [rsp+0x20], r9
        0x44,0x88,0x44,0x24,0x18,   // mov [rsp+0x18], r8b
        0x48,0x89,0x54,0x24,0x10    // mov [rsp+0x10], rdx
    };
    if (memcmp(g_selTarget, kExpect, 20) != 0) {
        Log("[sel] probe: prologue mismatch -> skip; first: %02X %02X %02X %02X",
            ((uint8_t*)g_selTarget)[0], ((uint8_t*)g_selTarget)[1],
            ((uint8_t*)g_selTarget)[2], ((uint8_t*)g_selTarget)[3]);
        return false;
    }

    // trampoline: 20 原指令 + 13 绝对跳转 = 33 字节
    uint8_t* tramp = (uint8_t*)VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE,
                                            PAGE_EXECUTE_READWRITE);
    if (!tramp) { Log("[sel] probe: VirtualAlloc failed -> skip"); return false; }
    memcpy(tramp, kExpect, 20);
    {
        uint8_t* p = tramp + 20;
        p[0] = 0x48; p[1] = 0xB8;                        // mov rax, imm64
        uint64_t back = (uint64_t)(uintptr_t)((uint8_t*)g_selTarget + 20);
        memcpy(p + 2, &back, 8);
        p[10] = 0xFF; p[11] = 0xE0;                      // jmp rax
    }
    FlushInstructionCache(GetCurrentProcess(), tramp, 33);
    g_selTramp = tramp;

    DWORD oldProt = 0;
    if (!VirtualProtect(g_selTarget, 20, PAGE_EXECUTE_READWRITE, &oldProt)) {
        Log("[sel] probe: VirtualProtect failed -> skip");
        VirtualFree(tramp, 0, MEM_RELEASE); g_selTramp = nullptr;
        return false;
    }
    // ★ 15 字节绝对跳转 + 4 字节 NOP（覆盖 19 字节）
    argate::MakeAbsJmp((uint8_t*)g_selTarget, (uint64_t)(uintptr_t)&SelEntry);
    memset((uint8_t*)g_selTarget + 15, 0x90, 5);
    VirtualProtect(g_selTarget, 20, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), g_selTarget, 20);

    Log("[sel] probe INSTALLED: target=0x%llX tramp=0x%llX (20-byte abs jmp)",
        (unsigned long long)(uintptr_t)g_selTarget,
        (unsigned long long)(uintptr_t)tramp);
    return true;
}

// ============================================================================
#endif  // AR_ENABLE_PROBES

// 在 target 附近（±2GB 内）分配可执行内存
static uint8_t* AllocNearby(void* target, size_t size) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    const uintptr_t gran = si.dwAllocationGranularity ? si.dwAllocationGranularity : 0x10000;
    const uintptr_t base = (uintptr_t)target & ~(uintptr_t)(gran - 1);
    for (int i = 1; i < 2048; ++i) {
        void* p = VirtualAlloc((void*)(base - (uintptr_t)i * gran), size,
                               MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (p) return (uint8_t*)p;
        p = VirtualAlloc((void*)(base + (uintptr_t)i * gran), size,
                         MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (p) return (uint8_t*)p;
    }
    return nullptr;
}

#if AR_ENABLE_PROBES
// C890 只读打点 hook（2026-11-15，task t18）
// ============================================================================
//
// 【为什么需要它】
//   g_takeC890 / g_takeE4B0 之前只被赋值，从未真正 patch —— 这是「第 8 例：
//   写了没接线」。所有关于 C890 的结论都是在纸上跑的，没有运行时证据。
//
// 【这次做什么】
//   在 C890 入口（0x81E7E0）打一个【只读】的打点：
//     · 记录 seq / tick / param1 / param2 / param3 / country
//     · 不修改任何参数、不修改返回值、不修改内存
//     · 记录完立即跳回原函数
//
// 【要回答的问题】
//   每次「科研决策」C890 被调用几次？
//     · 被调用 N 次（N=候选数）→ C890 是「算单卡权重」
//     · 被调用 1 次                → C890 是「从 N 张里选 1 张」
//   这是判定 C890 是「抽卡」还是「选卡」的决定性证据。
//
// 【安全原则】
//   · 所有解引用都用 SafeReadable 包裹，绝不裸解引用
//   · 桩内不抛异常、不分配内存、失败静默
//   · 任何未预期情况 → 直接跳回 trampoline，不做任何处理
//   · 宁可少记日志，不能崩游戏
// ============================================================================

extern "C" void* g_c890Tramp = nullptr;   // trampoline（20 字节：15 原指令 + 5 jmp）
static void*     g_c890Target = nullptr;  // patch 目标地址（0x81E7E0 的运行时地址）
static bool      g_c890ProbeInstalled = false;  // 是否已成功安装只读打点

// 打点统计
static volatile LONG s_c890Seq   = 0;     // 全局递增序号
static volatile LONG s_c890Count = 0;     // 总调用次数
static volatile LONG s_c890Logged = 0;    // 已记录的行数
static uint64_t      s_c890LastP3 = 0;    // 上次记录的 param_3（用于「地址变化」判定）

// 独立的 param_3 集合（最多跟踪 64 个）
static volatile LONG s_c890UniqP3 = 0;
static uint64_t      s_c890P3Set[64] = {0};

// 独立的 country 集合（最多跟踪 32 个）
static volatile LONG s_c890UniqCountry = 0;
static uint64_t      s_c890CountrySet[32] = {0};

static bool C890TrackUnique(uint64_t* set, volatile LONG* cnt, LONG cap, uint64_t v) {
    if (v == 0) return false;
    LONG n = *cnt;
    for (LONG i = 0; i < n && i < cap; ++i) if (set[i] == v) return false;
    if (n < cap) { set[n] = v; InterlockedIncrement(cnt); return true; }
    return false;
}

// 由汇编桩调用：记录一次 C890 调用。绝不抛异常，绝不阻塞。

// ============================================================================
// 调用栈记录（2026-11-15，定位 take 的最后一步）
// ============================================================================
//
// 【为什么需要】
//   静态分析已穷尽：偏移扫描 / 字节模式 / 字符串锚点 / 调用链
//   每次都命中成百上千个候选，无法区分「抽卡」与「通用代码」。
//
//   唯一确定的方法是【看真实调用栈】：
//     C890 被调用 = 算某个科技的权重
//     ⇒ 它的调用者必然是「遍历候选」的循环
//     ⇒ 那个循环的上层就是「抽卡」
//
// 【怎么拿栈】
//   桩里已传 entryRsp（C890 入口时的 rsp，S = rsp+56）。
//   x64 的 [S] 就是「C890 的直接调用者返回地址」。
//   继续沿 rbp 链（或按 ABI 的栈帧）往上，但 rbp 链不一定可靠，
//   所以：只记录 [S]（直接调用者，100% 可靠）。
//   曾经用 RtlCaptureStackBackTrace 拿完整栈 → 真机崩溃（栈回溯不可靠），已移除。
// ============================================================================

// 已记录过的 (p1,p3) 组合，避免重复记录栈
static uint64_t s_stackSeenP1[64] = {0};
static uint64_t s_stackSeenP3[64] = {0};
static volatile LONG s_stackSeenN = 0;
static volatile LONG s_stackLogged = 0;

static bool StackShouldLog(void* p1, void* p3) {
    if (InterlockedCompareExchange(&s_stackLogged, 0, 0) >= 50) return false;
    const uint64_t a = (uint64_t)(uintptr_t)p1;
    const uint64_t b = (uint64_t)(uintptr_t)p3;
    LONG n = s_stackSeenN;
    for (LONG i = 0; i < n && i < 64; ++i)
        if (s_stackSeenP1[i] == a && s_stackSeenP3[i] == b) return false;
    if (n < 64) {
        s_stackSeenP1[n] = a;
        s_stackSeenP3[n] = b;
        InterlockedIncrement(&s_stackSeenN);
    }
    return true;
}

static void LogCallStack(void* p1, void* p3, void* entryRsp) {
    if (!StackShouldLog(p1, p3)) return;
    InterlockedIncrement(&s_stackLogged);

    Log("[c890] ---- stack for p1=%p p3=%p (base=0x%llX) ----",
        p1, p3, (unsigned long long)(uintptr_t)g_base);

    // 1) 直接调用者：entryRsp 指向的返回地址（100% 可靠，不依赖 rbp）
    if (entryRsp && SafeReadable(entryRsp, 8)) {
        uint64_t ret = *(uint64_t volatile*)entryRsp;
        if (ret > (uint64_t)(uintptr_t)g_base) {
            Log("    #0 direct caller  RVA 0x%llX  (ret=0x%llX)",
                (unsigned long long)(ret - (uint64_t)(uintptr_t)g_base),
                (unsigned long long)ret);
        } else {
            Log("    #0 direct caller  raw=0x%llX  (不可信)", (unsigned long long)ret);
        }
    }

    // 2) ★ 2026-11-16 移除 RtlCaptureStackBackTrace —— 真机崩溃根因
    //
    //   日志证据：cap #0 raw=0x8286DFBED0（140TB 偏移，明显是垃圾）
    //   原因：RtlCaptureStackBackTrace 返回的帧地址在游戏进程里不可靠
    //         （x64 无帧指针 + 编译器优化 → 栈回溯不可信）。
    //   ⇒ 只保留 #0 direct caller（手动读 [entryRsp]，100% 可靠）。
    //   ⇒ 它已经给出关键信息：RVA 0x8206A7 = E4B0 的 callsite（0x8206A2+5）。
    //   不再调用任何栈回溯 API。
    Log("[c890] ---- end stack ----");
}

// [alt] v3 三领域备选状态
static volatile LONG s_lastAlt[3] = {-999, -999, -999};

// [cnt] v2 采样状态
static volatile LONG s_cntSampled   = 0;
static volatile LONG s_cntLastA     = -999;
static volatile LONG s_cntLastB     = -999;
static volatile LONG s_cntLastBp    = -999;
static uint64_t      s_cntLastTickMs = 0;




// ============================================================================
// [rp] 科研槽观测探针 —— 默认关闭（2026-11-16 定案）
//
// 【为什么关闭】读数无效：只能看到 idx/candCnt 的「当前值」，
//   而变化与清空同一时刻，无法区分「谁改的」。
//   找「填充者」需要寄存器级跨函数数据流分析，静态做不到。
// 【如何重新启用】AR_ENABLE_RP_PROBE 设为 1。
// ============================================================================
#ifndef AR_ENABLE_RP_PROBE
#define AR_ENABLE_RP_PROBE 0
#endif
#if AR_ENABLE_RP_PROBE
// ============================================================================
// ★ 科研槽观测探针（0x81B360，月度结算）
// ============================================================================
//
// 【为什么 hook 这里】
//   0x81B360 是「月度科研结算」，每次调用遍历 3 个领域（area=0/1/2），
//   访问结构（逐字节核实）：
//     14081B3AC  mov 0x293e83d(%rip),%r14     ; ★ r14 = *(0x143159BF0) 全局
//     14081B3D8  mov 0x58(%r14),%rax          ; area=2（工程）
//     14081B3DE  mov 0x50(%r14),%rax          ; area=1（社会）
//     14081B3E4  mov 0x48(%r14),%rax          ; area=0（物理）
//     14081B3E8  movslq 0x18(%rax),%rcx       ; ★ idx @ +0x18
//     14081B3F0  mov 0x1f90(%rdi),%rax        ; rdi = 科技表（表对象）
//     14081B3F7  cmp 0xc(%rax),%ecx           ; 表大小 @ +0xC
//     14081B3FC  mov (%rax),%rax              ; 数组 @ +0x0
//     14081B3FF  lea (%rax,%rcx,8),%rbx       ; ★ tech = arr[idx]
//
// 【观测目标】
//   ① idx（当前研究的科技索引）
//   ② key（索引→key，需从科技表读）
//   ③ candCnt（候选槽 count，slotmgr+(area+11)*0x18+0x14）
//   ④ 变化检测（idx 或 candCnt 变化 → [CHANGED]）
//
// 【两条路径都记】
//   A: r14（全局 0x143159BF0）—— 实测路径
//   B: slotmgr（hookA 的 param_1）—— 备选假设
//   ⇒ 哪条给出合理 key，就确定用哪条
// ============================================================================

// 前置声明
extern "C" __attribute__((naked)) void AR_RpEntry();

// 前置声明（AllocNearby 定义在 take 区块里，位于其后）
static uint8_t* AllocNearby(void* target, size_t size);

static uint8_t* g_rpPatch = nullptr;
static uint8_t  g_rpOrig[20] = {0};
static uint64_t g_rpBack = 0;
static volatile LONG s_rpInstalled = 0;
static volatile LONG s_rpCount = 0;
static volatile LONG s_rpLogged = 0;

extern "C" { uint64_t g_rpBackAddr = 0; }

// 每个 area 的上次状态
static volatile LONG s_rpLastIdx[3] = {-2, -2, -2};
static volatile LONG s_rpLastCnt[3] = {-2, -2, -2};

// 从科技表 + 索引读 key
//   表结构：+0x00 = 数组指针，+0x0C = 元素数（int32）
//   元素：tech 对象指针，key @ tech+0x20
static bool RpReadKeyFromTable(void* table, int idx, char* out, size_t outCap) {
    if (!table || !out || outCap < 8 || idx < 0) return false;
    if (!SafeReadable(table, 0x10)) return false;
    void** arr = (void**)(*(void* volatile*)table);
    const int32_t n = *(volatile int32_t*)((uint8_t*)table + 0xC);
    if (!arr || n <= 0 || idx >= n) return false;
    if (!SafeReadable(arr, ((size_t)idx + 1) * 8)) return false;
    void* tech = arr[idx];
    if (!tech) return false;
    if (!SafeReadable((uint8_t*)tech + 0x20, 0x20)) return false;
    uint8_t* obj = (uint8_t*)tech + 0x20;
    const uint64_t sz  = *(volatile uint64_t*)(obj + 0x10);
    const uint64_t cap = *(volatile uint64_t*)(obj + 0x18);
    if (sz == 0 || sz >= 64 || cap < sz) return false;
    const char* p = (cap > 15) ? *(const char* volatile*)obj : (const char*)obj;
    if (!p || !SafeReadable(p, (size_t)sz)) return false;
    for (uint64_t i = 0; i < sz; ++i) {
        const char c = p[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_')) return false;
    }
    const size_t k = (sz < outCap - 1) ? (size_t)sz : outCap - 1;
    memcpy(out, p, k);
    out[k] = 0;
    return true;
}

extern "C" void AR_ResearchProbe(void* table, void* slotmgr) {
    const LONG n = InterlockedIncrement(&s_rpCount);

    // r14 = *(g_base + 0x3159BF0)
    void* r14 = nullptr;
    if (SafeReadable((void*)(uintptr_t)(g_base + 0x3159BF0), 8))
        r14 = *(void* volatile*)(uintptr_t)(g_base + 0x3159BF0);

    for (int area = 0; area < 3; ++area) {
        // ---- 路径 A：r14 ----
        int32_t idxA = -1;
        char keyA[64] = {0};
        bool haveA = false;
        if (r14 && SafeReadable((uint8_t*)r14 + 0x48 + (size_t)area * 8, 8)) {
            void* slotA = *(void* volatile*)((uint8_t*)r14 + 0x48 + (size_t)area * 8);
            if (slotA && SafeReadable((uint8_t*)slotA + 0x18, 4)) {
                idxA = *(volatile int32_t*)((uint8_t*)slotA + 0x18);
                haveA = RpReadKeyFromTable(table, idxA, keyA, sizeof(keyA));
            }
        }

        // ---- 路径 B：slotmgr ----
        int32_t idxB = -1;
        char keyB[64] = {0};
        bool haveB = false;
        if (slotmgr && SafeReadable((uint8_t*)slotmgr + 0x48 + (size_t)area * 8, 8)) {
            void* slotB = *(void* volatile*)((uint8_t*)slotmgr + 0x48 + (size_t)area * 8);
            if (slotB && SafeReadable((uint8_t*)slotB + 0x18, 4)) {
                idxB = *(volatile int32_t*)((uint8_t*)slotB + 0x18);
                haveB = RpReadKeyFromTable(table, idxB, keyB, sizeof(keyB));
            }
        }

        // ---- 候选槽 count ----
        int32_t candCnt = -1;
        if (slotmgr && SafeReadable((uint8_t*)slotmgr + (size_t)(area + 11) * 0x18 + 0x14, 4))
            candCnt = *(volatile int32_t*)((uint8_t*)slotmgr + (size_t)(area + 11) * 0x18 + 0x14);

        // ---- 变化检测 ----
        const bool changed = (idxA != s_rpLastIdx[area]) || (candCnt != s_rpLastCnt[area]);
        const LONG logged = InterlockedCompareExchange(&s_rpLogged, 0, 0);

        // 限流：[CHANGED] 全记；普通记录前 100 条 + 每 100 条
        if (!changed && logged >= 100 && (n % 100) != 0) continue;

        if (changed) {
            InterlockedIncrement(&s_rpLogged);
            Log("[rp][CHANGED] area=%d candCnt=%d idxA=%d(was %d) keyA=%s idxB=%d keyB=%s r14=%p",
                area, (int)candCnt, (int)idxA, (int)s_rpLastIdx[area],
                haveA ? keyA : "(null)", (int)idxB, haveB ? keyB : "(null)", r14);
            s_rpLastIdx[area] = idxA;
            s_rpLastCnt[area] = candCnt;
        } else if (logged < 100 || (n % 100) == 0) {
            InterlockedIncrement(&s_rpLogged);
            Log("[rp] area=%d candCnt=%d idxA=%d keyA=%s idxB=%d keyB=%s r14=%p",
                area, (int)candCnt, (int)idxA, haveA ? keyA : "(null)",
                (int)idxB, haveB ? keyB : "(null)", r14);
        }
    }
}

// 安装：0x81B360 前 10 字节（两条 shadow-store）→ E9 rel32 到 nearby 桩
//   原字节：48 89 5C 24 10 / 48 89 4C 24 08
//   跳回：0x81B36A（push rbp）
static uint8_t* g_rpNear = nullptr;

static bool InstallResearchProbe(uint64_t base) {
    static const uint8_t kPat[10] = {
        0x48,0x89,0x5C,0x24,0x10,
        0x48,0x89,0x4C,0x24,0x08
    };
    const uint32_t fnRva = 0x81B360, fnLen = 1297;
    uint32_t hit = 0; int nHit = 0;
    for (uint32_t off = 0; off + 10 <= fnLen; ++off) {
        if (memcmp((uint8_t*)(uintptr_t)(base + fnRva + off), kPat, 10) == 0) {
            hit = fnRva + off; ++nHit;
        }
    }
    if (nHit != 1 || hit != 0x81B360) {
        Log("[rp] pattern hit %d at RVA 0x%X (expect 1 @ 0x81B360) -> disabled", nHit, hit);
        return false;
    }
    g_rpPatch = (uint8_t*)(uintptr_t)(base + hit);
    g_rpBack  = base + 0x81B36A;
    if (!SafeReadable(g_rpPatch, 10)) { Log("[rp] unreadable -> disabled"); return false; }
    memcpy(g_rpOrig, g_rpPatch, 10);

    uint8_t* nearStub = AllocNearby(g_rpPatch, 64);
    if (!nearStub) { Log("[rp] AllocNearby failed err=%lu -> disabled", (unsigned long)GetLastError()); return false; }
    {
        uint8_t buf[12];
        uint64_t dst = (uint64_t)(uintptr_t)&AR_RpEntry;
        buf[0] = 0x48; buf[1] = 0xB8;
        memcpy(buf + 2, &dst, 8);
        buf[10] = 0xFF; buf[11] = 0xE0;
        memcpy(nearStub, buf, 12);
        FlushInstructionCache(GetCurrentProcess(), nearStub, 12);
    }
    g_rpNear = nearStub;
    g_rpBackAddr = g_rpBack;

    const int64_t rel = (int64_t)((uintptr_t)nearStub - ((uintptr_t)g_rpPatch + 5));
    if (rel < INT32_MIN || rel > INT32_MAX) {
        Log("[rp] rel32 out of range (rel=%lld) -> disabled", (long long)rel);
        VirtualFree(nearStub, 0, MEM_RELEASE); g_rpNear = nullptr; return false;
    }

    DWORD oldProt = 0;
    if (!VirtualProtect(g_rpPatch, 10, PAGE_EXECUTE_READWRITE, &oldProt)) {
        Log("[rp] VirtualProtect failed err=%lu -> disabled", (unsigned long)GetLastError());
        VirtualFree(nearStub, 0, MEM_RELEASE); g_rpNear = nullptr; return false;
    }
    {
        uint8_t buf[10];
        buf[0] = 0xE9;
        int32_t r32 = (int32_t)rel;
        memcpy(buf + 1, &r32, 4);
        memset(buf + 5, 0x90, 5);
        memcpy(g_rpPatch, buf, 10);
    }
    VirtualProtect(g_rpPatch, 10, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), g_rpPatch, 10);

    InterlockedExchange(&s_rpInstalled, 1);
    Log("[rp] probe INSTALLED at 0x%llX near=0x%llX (rel=%lld) back=0x%llX",
        (unsigned long long)(uintptr_t)g_rpPatch,
        (unsigned long long)(uintptr_t)nearStub, (long long)rel,
        (unsigned long long)g_rpBack);
    return true;
}

static void RemoveResearchProbe() {
    if (!g_rpPatch || !s_rpInstalled) return;
    DWORD oldProt = 0;
    if (VirtualProtect(g_rpPatch, 10, PAGE_EXECUTE_READWRITE, &oldProt)) {
        memcpy(g_rpPatch, g_rpOrig, 10);
        VirtualProtect(g_rpPatch, 10, oldProt, &oldProt);
        FlushInstructionCache(GetCurrentProcess(), g_rpPatch, 10);
    }
    if (g_rpNear) { VirtualFree(g_rpNear, 0, MEM_RELEASE); g_rpNear = nullptr; }
    g_rpPatch = nullptr;
    InterlockedExchange(&s_rpInstalled, 0);
    Log("[rp] probe removed (original 10 bytes restored)");
}

// 入口桩：保存全部易失寄存器 → 调 AR_ResearchProbe → 恢复 → 跳 trampoline
extern "C" __attribute__((naked)) void AR_RpEntry();
__asm__(
    ".text\n"
    ".globl AR_RpEntry\n"
    "AR_RpEntry:\n"
    // 入口 rsp%16 = 8；7 push (56) → (8-56)%16 = 0 已对齐
    // ★ 但 CALL 前需要 shadow space → 再 sub 0x20 → 仍 0
    "  push %rax\n"
    "  push %rcx\n"
    "  push %rdx\n"
    "  push %r8\n"
    "  push %r9\n"
    "  push %r10\n"
    "  push %r11\n"
    "  sub $0x20, %rsp\n"
    // 栈布局（7 push + sub 0x20 后，rsp = R-88）：
    //   [rsp+0x00]=r11 [0x08]=r10 [0x10]=r9 [0x18]=r8
    //   [0x20]=rdx  [0x28]=rcx  [0x30]=rax  [0x38..0x57]=shadow
    // 参数：rcx = 科技表（原 rdi，未被 push），rdx = slotmgr（原 rcx @ [rsp+0x28]）
    "  mov %rdi, %rcx\n"
    "  mov 0x28(%rsp), %rdx\n"
    "  call AR_ResearchProbe\n"
    "  add $0x20, %rsp\n"
    "  pop %r11\n"
    "  pop %r10\n"
    "  pop %r9\n"
    "  pop %r8\n"
    "  pop %rdx\n"
    "  pop %rcx\n"
    "  pop %rax\n"
    // ★ 补执行被覆盖的两条 shadow-store（原始 0x81B360 / 0x81B365）
    "  mov %rbx, 0x10(%rsp)\n"
    "  mov %rcx, 0x08(%rsp)\n"
    "  jmp *g_rpBackAddr(%rip)\n"
);
#endif  // AR_ENABLE_RP_PROBE

// ============================================================================
// ★ 接管版（take）：0x820ECB 选卡决策拦截
// ============================================================================
//
// 【用户语义（纯数字配置）】
//   cfg > 0  → 取 cfg 最大的候选（确定性，同分取靠前者）
//   cfg = 0  → 禁选（不参与）
//   cfg < 0  → 只在「全部无正值」时启用，取 |cfg| 最大的
//   未配置    → 不参与投票；若整个候选集都未配置 → 不干预（用游戏原值 gameIdx）
//
// 【patch 点】0x820ECB，7 字节
//   48 63 C8              movsxd rcx,eax        (3)
//   49 8B 45 08           mov rax,[r13+0x08]    (4)
//   ─────────────────────────────────────
//   0x820ED2: 4C 8B 24 C8   mov r12,[rax+rcx*8]  ← 跳回目标
//
// ⇒ 只有 7 字节 ⇒ 必须用 E9 rel32（5 字节）+ 2 NOP
// ⇒ 需要 ±2GB 内的 trampoline ⇒ AllocNearby
//
// 【栈对齐（已用解码器精确推导）】
//   0x820B30 prologue: 7 push (56) + sub 0x1A0 (416)  ⇒ rsp%16 = 8-56-416 ≡ 0
//   0x820DE8..DF4: and ~0xF,%rcx 后 sub %rcx,%rsp
//                   ⇒ rcx 已是 16 的倍数，模 16 不变
//   ⇒ 0x820ECB 处 rsp%16 = 0
//   trampoline: 进入 0 → 8 push (64) → 仍 0 → sub 0x20（shadow）→ 仍 0 ✓
//
// 【r13 的身份（已核实）】
//   140820D85  lea 0xb(%r15),%rax       ; r15 = area
//   140820D89  lea (%rax,%rax,2),%rax   ; ×3
//   140820D8D  lea (%r14,%rax,8),%r13   ; r13 = slotmgr + (area+11)*0x18
//   140820D91  cmpl $0x0,0x14(%r13)     ; count @ +0x14
//   140820DBD  movslq 0x14(%r13),%r14   ; r14 = count
//   ⇒ r13 = 备选槽位；[r13+0x08] = tech 对象数组；[r13+0x14] = count
//
// 【key 布局（A 点探针实测确认）】
//   tech + 0x20 = std::string（buf@+0x00 / size@+0x10 / cap@+0x18）
//   实测样例：sz=14 cap=15 key=tech_physics_1
// ============================================================================

static uint8_t* g_tkPatch    = nullptr;   // patch 点
static uint8_t  g_tkOrig[7]  = {0};       // 原 7 字节
static uint64_t g_tkBackAddr = 0;         // 跳回 0x820ED2
static volatile LONG s_tkInstalled = 0;
static volatile LONG s_tkDecisions = 0;

extern "C" { uint64_t g_tkBack = 0; }


// 取当前配置快照（复用 arcfg 的全局快照机制）
static bool TkLookup(const char* key, long long* out) {
    if (!key || !*key) return false;
    // ★★ 2026-11-18：未配置的 key 用 defaultWeight（默认 100），
    //   而不是「不参与决策」。这是禁选 bug 的真正根因。
    //   实现用 ar_config.h 现成的 EffectiveWeight()（行 367）：
    //     return (it == c.weights.end()) ? c.defaultWeight : it->second;
    *out = arcfg::EffectiveWeight(ConfigSnapshot(), std::string(key));
    return true;
}

// ★ 安全返回：gameIdx 可能是未初始化的垃圾值（实测 -1422191178）
//   任何情况下传给游戏的索引都必须在 [0, count) 内，否则游戏会越界读到崩溃。
static inline int TkSafeIdx(int idx, int count) {
    if (idx >= 0 && idx < count) return idx;
    return 0;   // 越界 → 用 0（安全下限）
}

// 决策：返回选中的索引（= 游戏要用的 gameIdx 时表示不干预）
extern "C" int AR_Takeover(void* container, int count, int gameIdx) {
    if (!container || count <= 0 || count > 64) return 0;   // count 非法 → 0（不信任 gameIdx）
    if (!SafeReadable((uint8_t*)container + 0x08, 8)) return TkSafeIdx(gameIdx, count);
    void** arr = (void**)(*(void* volatile*)((uint8_t*)container + 0x08));
    if (!arr || !SafeReadable(arr, (size_t)count * 8)) return TkSafeIdx(gameIdx, count);

    // ==========================================================================
    // ⚠️⚠️ 2026-11-18：此处删除了一段引用未定义变量的死代码 ⚠️⚠️
    //
    // 【旧代码（已删）】
    //   if (country && SafeReadable((uint8_t*)country + 0x314C, 4)) {
    //       const int32_t c314c = *(volatile int32_t*)((uint8_t*)country + 0x314C);
    //       if (c314c == 0) { InterlockedIncrement(&s_tk2AiTicks); return gamePick; }
    //       InterlockedIncrement(&s_tk2PlayerPicks);
    //   }
    //
    // 【为什么删】
    //   AR_Takeover（v1）的签名是 (void* container, int count, int gameIdx)，
    //   没有 country 也没有 gamePick。这段代码是从 AR_TakeoverV2 误拷过来的。
    //   它靠 AR_ENABLE_PROBES=0 被预处理掉才能编译 —— 一旦打开就报错。
    //
    // 【玩家判据在哪里】
    //   在 AR_TakeoverV2（行 ~1372）里，已用 IsCountryPlayer() 实现，见下。
    //   v1 本身已被 if (false && InstallTakeover(...)) 禁用，不需要玩家判据。
    // ==========================================================================

    // 只有 take 模式才干预
    arcfg::Config cfg = ConfigSnapshot();
    if (cfg.mode != arcfg::Mode::Take) {
        return TkSafeIdx(gameIdx, count);
    }

    int bestPosIdx = -1, bestNegIdx = -1;
    long long bestPosCfg = 0, bestNegAbs = 0;
    int anyConfigured = 0;

    for (int i = 0; i < count; ++i) {
        void* tech = arr[i];
        if (!tech) continue;
        char key[64] = {0};
        if (!TkReadKey(tech, key, sizeof(key))) continue;
        long long w = 0;
        if (!TkLookup(key, &w)) continue;      // 未配置 → 不参与
        anyConfigured = 1;
        if (w > 0) {
            if (w > bestPosCfg) { bestPosCfg = w; bestPosIdx = i; }
        } else if (w < 0) {
            const long long a = -w;
            if (a > bestNegAbs) { bestNegAbs = a; bestNegIdx = i; }
        }
        // w == 0 → 禁选，不参与
    }

    int chosen = gameIdx;   // 默认不干预
    if (bestPosIdx >= 0)      chosen = bestPosIdx;    // 有正值 → 取最大
    else if (bestNegIdx >= 0) chosen = bestNegIdx;    // 无正值有负值 → 取 |cfg| 最大
    else if (!anyConfigured)  chosen = gameIdx;       // 全未配置 → 不干预
    else                      chosen = gameIdx;       // 全禁选（全 0）→ 不干预（保守）

    const LONG n = InterlockedIncrement(&s_tkDecisions);
    if (n <= 20 || (n % 500) == 0) {
        Log("[take] n=%ld count=%d gameIdx=%d inRange=%d -> chosen=%d "
            "(pos=%d/%lld neg=%d/%lld cfg=%d) %s",
            (long)n, count, gameIdx, (gameIdx >= 0 && gameIdx < count) ? 1 : 0, chosen,
            bestPosIdx, bestPosCfg, bestNegIdx, bestNegAbs, anyConfigured,
            (chosen == gameIdx) ? "(no-intervene)" : "(OVERRIDE)");
    }
    return chosen;
}

// trampoline：
//   JMP 进入 rsp%16 = 0
//   8 push (64B) → 0
//   sub 0x20（shadow）→ 0  ✓ 满足 CALL 前对齐
//   call AR_Takeover（参数：rcx=container(r13), edx=count(r14d), r8d=gameIdx(eax)）
//   add 0x20
//   pop ×8（逆序）→ rax 保留 AR_Takeover 的返回值
//   补执行 movsxd rcx,eax / mov rax,[r13+0x08]
//   绝对跳回 0x820ED2
extern "C" __attribute__((naked)) void AR_TakeoverTramp();
__asm__(
    ".text\n"
    ".globl AR_TakeoverTramp\n"
    "AR_TakeoverTramp:\n"
    "  push %rbx\n"
    "  push %rbp\n"
    "  push %rsi\n"
    "  push %rdi\n"
    "  push %r12\n"
    "  push %r13\n"
    "  push %r14\n"
    "  push %r15\n"
    "  sub $0x20, %rsp\n"
    "  mov %r13, %rcx\n"        // container
    "  mov %r14d, %edx\n"       // count
    "  mov %eax, %r8d\n"        // gameIdx
    "  call AR_Takeover\n"
    "  add $0x20, %rsp\n"
    "  pop %r15\n"
    "  pop %r14\n"
    "  pop %r13\n"
    "  pop %r12\n"
    "  pop %rdi\n"
    "  pop %rsi\n"
    "  pop %rbp\n"
    "  pop %rbx\n"
    // ★ 补执行 2 条原指令（rax 是 AR_Takeover 的返回值）
    "  movslq %eax, %rcx\n"
    "  mov 0x8(%r13), %rax\n"
    // ★ 绝对跳回 0x820ED2
    "  mov g_tkBack(%rip), %r11\n"
    "  jmp *%r11\n"
);


// 安装：0x820ECB 的 7 字节 → E9 rel32 到 nearby trampoline
static bool InstallTakeover(uint64_t base) {
    static const uint8_t kPat[7] = {
        0x48,0x63,0xC8,            // movsxd rcx,eax
        0x49,0x8B,0x45,0x08        // mov rax,[r13+0x08]
    };
    const uint32_t fnLo = 0x820B30, fnLen = 1138;
    uint32_t hit = 0; int nHit = 0;
    for (uint32_t off = 0; off + 7 <= fnLen; ++off) {
        if (memcmp((uint8_t*)(uintptr_t)(base + fnLo + off), kPat, 7) == 0) {
            hit = fnLo + off; ++nHit;
        }
    }
    if (nHit != 1) {
        Log("[take] pattern hit %d times (expect 1) -> takeover disabled", nHit);
        return false;
    }
    if (hit != 0x820ECB) {
        Log("[take] WARN pattern found at RVA 0x%X (expect 0x820ECB) -> takeover disabled", hit);
        return false;
    }

    g_tkPatch = (uint8_t*)(uintptr_t)(base + hit);
    g_tkBackAddr = base + 0x820ED2;
    if (!SafeReadable(g_tkPatch, 7)) { Log("[take] patch unreadable -> disabled"); return false; }
    memcpy(g_tkOrig, g_tkPatch, 7);

    // nearby trampoline：拷贝 AR_TakeoverTramp 体
    uint8_t* t = AllocNearby(g_tkPatch, 256);
    if (!t) { Log("[take] AllocNearby failed err=%lu -> disabled", (unsigned long)GetLastError()); return false; }
    // ⚠️ AR_TakeoverTramp 里有 rip 相对的 mov g_tkBack(%rip)，拷贝后会失效
    //    ⇒ 不能在附近内存里放「拷贝版」，必须放在它自己所在的 DLL 里
    //    ⇒ 但 DLL 离 exe 数百 GB，E9 rel32 不可达
    //    ⇒ 解法：nearby 只放一个「绝对跳转桩」，跳到 DLL 里的 AR_TakeoverTramp
    //
    //   nearby[0..6]  = 48 B8 <&AR_TakeoverTramp> FF E0   (12 字节)
    //   patch 点      = E9 <nearby - patch - 5> + 2 NOP   (7 字节)
    {
        uint8_t buf[12];
        uint64_t dst = (uint64_t)(uintptr_t)&AR_TakeoverTramp;
        buf[0] = 0x48; buf[1] = 0xB8;
        memcpy(buf + 2, &dst, 8);
        buf[10] = 0xFF; buf[11] = 0xE0;
        memcpy(t, buf, 12);
        FlushInstructionCache(GetCurrentProcess(), t, 12);
    }

    g_tkBack = g_tkBackAddr;

    const int64_t rel = (int64_t)((uintptr_t)t - ((uintptr_t)g_tkPatch + 5));
    if (rel < INT32_MIN || rel > INT32_MAX) {
        Log("[take] nearby trampoline out of rel32 range (rel=%lld) -> disabled", (long long)rel);
        VirtualFree(t, 0, MEM_RELEASE);
        return false;
    }

    DWORD oldProt = 0;
    if (!VirtualProtect(g_tkPatch, 7, PAGE_EXECUTE_READWRITE, &oldProt)) {
        Log("[take] VirtualProtect failed err=%lu -> disabled", (unsigned long)GetLastError());
        VirtualFree(t, 0, MEM_RELEASE);
        return false;
    }
    {
        uint8_t buf[7];
        buf[0] = 0xE9;
        int32_t r32 = (int32_t)rel;
        memcpy(buf + 1, &r32, 4);
        buf[5] = 0x90; buf[6] = 0x90;
        memcpy(g_tkPatch, buf, 7);
    }
    VirtualProtect(g_tkPatch, 7, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), g_tkPatch, 7);

    InterlockedExchange(&s_tkInstalled, 1);
    Log("[take] OVERRIDE INSTALLED at 0x%llX nearby=0x%llX (rel=%lld) back=0x%llX",
        (unsigned long long)(uintptr_t)g_tkPatch,
        (unsigned long long)(uintptr_t)t, (long long)rel,
        (unsigned long long)g_tkBackAddr);
    return true;
}

static void RemoveTakeover() {
    if (!g_tkPatch || !s_tkInstalled) return;
    DWORD oldProt = 0;
    if (VirtualProtect(g_tkPatch, 7, PAGE_EXECUTE_READWRITE, &oldProt)) {
        memcpy(g_tkPatch, g_tkOrig, 7);
        VirtualProtect(g_tkPatch, 7, oldProt, &oldProt);
        FlushInstructionCache(GetCurrentProcess(), g_tkPatch, 7);
    }
    g_tkPatch = nullptr;
    InterlockedExchange(&s_tkInstalled, 0);
    Log("[take] takeover removed (original 7 bytes restored)");
}

#endif  // AR_ENABLE_PROBES（C890/SEL/take 到此为止）
// ★ 2026-11-18：不能用 #if 包整块（会误伤接管核心：AR_TakeoverV2 / trampoline / InstallTakeoverV2）
//   改为「常驻 + 运行时跳过安装」：使用版不调用探针安装函数，
//   但代码仍在（不影响接管）。代价是二进制含探针字符串。
#if 1
// [map] 状态与去重（512 槽开放寻址，只存 id）
static volatile LONG s_mapLogged = 0;
static uint32_t      s_mapSlots[512] = {0};   // 0 = 空（tech id 不会是 0）

static bool MapSeen(int32_t id) {
    if (id <= 0) return true;                 // 非法 id 直接当已见
    const uint32_t u = (uint32_t)id;
    uint32_t h = (u * 2654435761u) & 511u;
    for (int probe = 0; probe < 512; ++probe) {
        const uint32_t v = s_mapSlots[h];
        if (v == 0) return false;
        if (v == u) return true;
        h = (h + 1u) & 511u;
    }
    return true;                               // 表满当已见
}
static void MapRemember(int32_t id) {
    if (id <= 0) return;
    const uint32_t u = (uint32_t)id;
    uint32_t h = (u * 2654435761u) & 511u;
    for (int probe = 0; probe < 512; ++probe) {
        uint32_t& v = s_mapSlots[h];
        if (v == 0) { v = u; return; }
        if (v == u) return;
        h = (h + 1u) & 511u;
    }
}




// ============================================================================
// ★★ take v2：装槽前拦截（0x6F334E，9 字节）
// ============================================================================
//
// 【为什么改到 0x6F334E】
//   v1 patch 的是 0x820ECB（0x820B30 函数内部），但那里 gameIdx 是未初始化垃圾
//   （实测 -1422191178）→ 污染返回值 → 崩。
//
//   v2 改在「调用者」侧，此时 0x820B30 已完整执行完（副作用齐全），
//   RAX = 游戏选中的 tech 指针（有效值，不是索引）。
//
// 【调用者结构（0x6F3300..0x6F3370，逐字节核实）】
//   1406F32F0  mov %rdi,%rcx            ; slotmgr
//   1406F3300  movzbl %r14b,%esi        ; area
//   1406F3304  ... 位图检测 + 打日志
//   1406F332C  je 0x6F3369              ; bit 已被清 → 跳过本领域
//   1406F3346  mov %rdi,%rcx            ; param_1 = slotmgr
//   1406F3349  call 0x820B30            ; ★ 副作用完整执行
//   1406F334E  mov %rax,%rsi            ; ★ patch 起点（9 字节）
//   1406F3351  mov (%rax),%rdx
//   1406F3354  mov %rax,%rcx
//   1406F3357  call *0x8(%rdx)          ; 虚函数检查
//   1406F335A  test %al,%al
//   1406F335C  je 0x6F3369              ; 失败 → 跳过
//   1406F335E  mov %rsi,%rdx            ; ★ 用 rsi
//   1406F3361  mov %rdi,%rcx
//   1406F3364  call 0x81D000            ; ★ 装槽
//   1406F3369  inc %r14d                ; 下一领域
//
// 【9 字节 patch】0x6F334E: mov+mov+mov = 9 字节，边界 0x6F3357（干净）
//
// 【跳过装槽的机制】
//   ★ 如果全禁 → 我们不补执行，直接跳到 0x6F3369（inc r14d）
//   ⇒ 该领域这个 tick 什么都不装 ⇒ 研究槽保持空 ⇒ 不会研究禁选科技
//
// 【栈对齐（已验算）】
//   0x6F2590 prologue: 7 push (56) + sub 0x220 (544)
//   ⇒ (8 - 56 - 544) % 16 = 0  ⇒ 0x6F3349 处 rsp%16 = 0
//   trampoline: 进入 0 → 8 push (64) → 0 → sub 0x20（shadow）→ 0 ✓
//
// 【返回值传递（关键设计）】
//   不用寄存器传递（会被 pop 破坏），改用【全局变量】：
//     g_tk2Result  = 选中的 tech 指针（nullptr = 跳过装槽）
//     g_tk2Skip    = 是否跳过
//   trampoline 在 pop 之后从全局读，避免任何寄存器冲突。
//
// 【并发安全】
//   Δ 0x6F2590 是 country 更新（单线程游戏主循环），不需要锁。
//     但仍用 volatile + 简单标志，避免编译器优化。
// ============================================================================

// 前置声明
static uint8_t* AllocNearby(void* target, size_t size);
extern "C" __attribute__((naked)) void AR_TakeoverV2Tramp();

static uint8_t* g_tk2Patch = nullptr;
static uint8_t  g_tk2Orig[9] = {0};
static uint64_t g_tk2BackNorm = 0;   // = 0x6F3357（正常：补执行后继续）
static uint64_t g_tk2BackSkip = 0;   // = 0x6F3369（跳过装槽）
// ★ 阶段 1：只观测不接管（2026-11-16）
//   1 = 只记录 ours vs gamePick，绝不改游戏行为
//   0 = 真接管
#ifndef AR_TAKEOVER_V2_DRYRUN
#define AR_TAKEOVER_V2_DRYRUN 0

// ★★ 开关：AI 路径探针（0xBBC3E7）★★
//   1 = 安装探针
//   0 = 不安装（源码保留，将来可用）
//
// ★ 2026-11-18：已确认 0xBBC300 是 AI 路径（347/347 条 c314c=0，零例外）。
//   它不影响玩家，继续观测只是刷日志 + 吃性能（每秒 3 次调用）。
#ifndef AR_ENABLE_BP_PROBE
#define AR_ENABLE_BP_PROBE 0
#endif

// 保留旧开关名（引用处不变）
#ifndef AR_TAKEOVER_BP_DRYRUN
#define AR_TAKEOVER_BP_DRYRUN 1
#endif
#endif

static volatile LONG s_tk2Installed = 0;
static volatile LONG s_tk2Decisions = 0;
static volatile LONG s_tk2NoOps    = 0;   // 早退 tick（gamePick 不在候选）
static volatile LONG s_tk2RealPicks = 0;  // 真选卡 tick
static volatile LONG s_tk2PlayerPicks = 0; // 玩家的真选卡 tick
static volatile LONG s_tk2AiTicks     = 0; // AI 的 tick（不干预）

// trampoline 用的全局信道（避免寄存器传递问题）
extern "C" {
    volatile uint64_t g_tk2Result = 0;   // 选中的 tech 指针（0 = 跳过）
    volatile uint64_t g_tk2GamePick = 0; // 入口时保存的 gamePick（避免栈偏移计算）
    volatile LONG     g_tk2Skip   = 0;   // 1 = 跳过装槽
    uint64_t          g_tk2BackN  = 0;   // 正常跳回地址
    uint64_t          g_tk2BackS  = 0;   // 跳过跳回地址
}

// 读 tech 的配置：key 在 +0x20（A 点探针实测 194 条全成功）
static bool Tk2ReadCfg(void* tech, long long* out) {
    if (!tech || !out) return false;
    if (!SafeReadable((uint8_t*)tech + 0x20, 0x20)) return false;
    uint8_t* obj = (uint8_t*)tech + 0x20;
    const uint64_t sz  = *(volatile uint64_t*)(obj + 0x10);
    const uint64_t cap = *(volatile uint64_t*)(obj + 0x18);
    if (sz == 0 || sz >= 64 || cap < sz) return false;
    const char* p = (cap > 15) ? *(const char* volatile*)obj : (const char*)obj;
    if (!p || !SafeReadable(p, (size_t)sz)) return false;
    char key[64];
    for (uint64_t i = 0; i < sz; ++i) {
        const char c = p[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_')) return false;
        key[i] = c;
    }
    key[sz] = 0;
    // ★★ 2026-11-18：未配置的 key 用 defaultWeight（默认 100），不是 false。
    //   这是禁选 bug 的真正根因：旧版把「未配置」当「不参与」，
    //   导致 [0, 未配置, 未配置] 被误判为全禁。
    //   实现用 ar_config.h 现成的 EffectiveWeight()：
    //     return (it == c.weights.end()) ? c.defaultWeight : it->second;
    arcfg::Config cfg = ConfigSnapshot();
    *out = arcfg::EffectiveWeight(cfg, std::string(key));
    return true;   // ★ 只要有 key 就成功
}

// 决策：返回选中的 tech 指针（0 = 跳过装槽）
extern "C" void* AR_TakeoverV2(void* country, int area, void* gamePick) {
    const LONG n0 = InterlockedIncrement(&s_tk2Decisions);   // 全函数共用序号

    // ★ 2026-11-18：参数改为 country，这里派生 slotmgr
    //   依据：slotmgr = country + 0x1620（实测 232/232 + 21/21，零例外）
    void* slotmgr = (country && SafeReadable((uint8_t*)country + 0x1620, 8))
                  ? (void*)((uint8_t*)country + 0x1620)
                  : nullptr;

    // ★ 2026-11-20：为 VEH 崩溃捕获记录状态快照
    //   （只写全局变量，无锁、无函数调用，几条 mov）
    s_lastCountry  = (uint64_t)(uintptr_t)country;
    s_lastSlotmgr  = (uint64_t)(uintptr_t)slotmgr;
    s_lastGamePick = (uint64_t)(uintptr_t)gamePick;
    s_lastArea     = area;

    if (!slotmgr || area < 0 || area > 2) return gamePick;

    // ==========================================================================
    // ★★ 2026-11-18：玩家判据（用全局唯一的 IsCountryPlayer）
    // ==========================================================================
    //
    // 依据（与游戏 is_human 完全同构，逐字节核实）：
    //   is_human = (country[+0x314C] != 0) && (byte[g_base+0x281B833] == 0)
    //   而 0x6F2590 的入口守卫（0x6F32D0 / 0x6F32DD）与之同构
    //   ⇒ 能走到 0x6F334E 的本质上是玩家；此处是二重保险。
    //
    // ★ 为什么用 IsCountryPlayer 而不是内联两个条件：
    //   它是全局唯一实现（行 ~473），带 SafeReadable 保护。
    //   将来修改判据只需改一处，不会出现两套不一致的实现。
    //
    if (!IsCountryPlayer(country)) {
        InterlockedIncrement(&s_tk2AiTicks);
        return gamePick;          // 不是玩家 → 不干预
    }
    InterlockedIncrement(&s_tk2PlayerPicks);


    // ★ 2026-11-17：0x820B30 可能返回空（无可选科技）
    //   此时 trampoline 会去读 (%rax) → 空指针崩溃。
    //   直接走 skip 路径（不装槽）—— 这也是合理行为。
    if (!gamePick) return nullptr;

    // 只有 take 模式才干预
    arcfg::Config cfg = ConfigSnapshot();
    s_lastMode = (LONG)cfg.mode;
    if (cfg.mode != arcfg::Mode::Take) return gamePick;

    // 候选槽：slotmgr + (area+11)*0x18
    uint8_t* slot = (uint8_t*)slotmgr + (size_t)(area + 11) * 0x18;
    if (!SafeReadable(slot, 0x18)) return gamePick;
    void**  arr = (void**)(*(void* volatile*)(slot + 0x08));
    int32_t cnt = *(volatile int32_t*)(slot + 0x14);
    s_lastCnt = cnt;
    if (!arr || cnt <= 0 || cnt > 64) return gamePick;
    if (!SafeReadable(arr, (size_t)cnt * 8)) return gamePick;

    // ==========================================================================
    // ★★ 2026-11-20：arr/cnt 一致性检查（防游戏正在重建池）★★
    // ==========================================================================
    //
    // 【为什么需要】
    //   用户开了「每天完成一次科研」，每个游戏日三个领域各刷新一次池。
    //   刷新时 arr 可能被重新分配 → 我们读到「旧 arr + 新 cnt」或反过来 → arr[i] 野指针。
    //
    // 【做法】
    //   读取后立即再读一次，不一致就放弃本次接管。
    //   ⚠️ 这不是完美的（仍有微秒级 TOCTOU），但能挡住「显著的中间态」。
    //
    {
        void**  arr2 = (void**)(*(void* volatile*)(slot + 0x08));
        int32_t cnt2 = *(volatile int32_t*)(slot + 0x14);
        if (arr != arr2 || cnt != cnt2) {
            static volatile LONG s_raceBail = 0;
            const LONG rn = InterlockedIncrement(&s_raceBail);
            if (rn <= 20 || (rn % 100) == 0) {
                Log("[tk2] arr/cnt changed during read (arr %p->%p cnt %d->%d) -> bail #%ld",
                    arr, arr2, (int)cnt, (int)cnt2, (long)rn);
            }
            return gamePick;
        }
    }

    // ==========================================================================
    // ★★ 2026-11-17：「成员判据」——判本次是否真的选卡了
    // ==========================================================================
    //
    // 【依据】四方对比已裁定：0x820B30 有 3 条提前退出路径
    //   （均跳到 0x820ED6），此时 R12 保持入口值（哨兵）。
    //   只有真进了循环，0x820ED2 才会取候选 ⇒ gamePick 才真实。
    //
    // 【判据】gamePick ∈ arr[0..cnt-1] ? 真选卡 : 早退
    //   这比哨兵比较更本质：不依赖任何全局值。
    //
    {
        bool isCandidate = false;
        for (int i = 0; i < cnt; ++i) {
            if (arr[i] == gamePick) { isCandidate = true; break; }
        }
        if (!isCandidate) {
            const LONG k = InterlockedIncrement(&s_tk2NoOps);
            if (k <= 20 || (k % 100) == 0) {
                Log("[tak-SKIP] n=%ld area=%d cnt=%d game=%p not-in-candidates -> no-op (早退 tick)",
                    (long)k, area, (int)cnt, gamePick);
            }


            return gamePick;      // ★ 不干预
        }
        InterlockedIncrement(&s_tk2RealPicks);
    }

    // ==========================================================================
    // [tak-DBG] 诊断：gamePick 到底是不是我们这个数组的元素？
    // ==========================================================================
    //
    // 异常现象：game=0x294e4730010 出现 89%，但在 selB 的 52 个 tech 里 0 命中。
    // 必须判：我们的 slot 和 0x820B30 内部用的是不是同一个数组。
    //
    if (n0 <= 20) {
        void* e0 = nullptr; void* e1 = nullptr; void* e2 = nullptr;
        int eq0 = 0, eq1 = 0, eq2 = 0;
        if (arr && cnt > 0 && SafeReadable((uint8_t*)arr + 0, 8)) e0 = *(void* volatile*)((uint8_t*)arr + 0);
        if (arr && cnt > 1 && SafeReadable((uint8_t*)arr + 8, 8)) e1 = *(void* volatile*)((uint8_t*)arr + 8);
        if (arr && cnt > 2 && SafeReadable((uint8_t*)arr + 16, 8)) e2 = *(void* volatile*)((uint8_t*)arr + 16);
        if (e0 && e0 == gamePick) eq0 = 1;
        if (e1 && e1 == gamePick) eq1 = 1;
        if (e2 && e2 == gamePick) eq2 = 1;
        Log("[tak-DBG] n=%ld area=%d cnt=%d slotmgr=%p arr=%p [0]=%p [1]=%p [2]=%p game=%p eq=%d%d%d",
            (long)n0, area, (int)cnt, slotmgr, arr, e0, e1, e2, gamePick, eq0, eq1, eq2);
    }

    // ==========================================================================
    // ★★ 2026-11-18 重写：禁选语义修正★★
    // ==========================================================================
    //
    // 【用户需求】
    //   ① 候选里有禁选科技，但还有别的可用科技
    //      ⇒ 选别的，绝不选禁选的，研究继续
    //   ② 候选全部都是禁选科技
    //      ⇒ 停止研究 + 关自动科研
    //
    // 【旧实现的 bug】
    //   旧：else if (anyConfigured) → 全禁分支
    //   anyConfigured 的语义是「至少有一个候选配了值」，
    //   不是「全部都是禁选」。
    //   ⇒「1 个禁选 + 2 个未配置」也会停研究。
    //
    // ==========================================================================
    // ★★ 2026-11-18 简化：因为未配置 = defaultWeight(100) 已在 Tk2ReadCfg 处理，
    //    这里只需判「是否全部权重为 0」。
    // ==========================================================================
    //
    // 用户需求：
    //   ① 有可用科技 → 绝不选禁选的，研究继续
    //   ② 全部都是禁选 → 停研究 + 关自动科研
    //
    // 权重语义（ar_config.h）：
    //   未配置  = defaultWeight = 100（正数）
    //   > 0       = 可选，取最大
    //   = 0       = 禁选
    //   < 0       = 兜底（全部无正数时才用，取 |w| 最大）
    //
    // ==========================================================================
    // ★★ 2026-11-18：平局随机（用户实测发现的缺陷）★★
    // ==========================================================================
    //
    // 【用户发现】三个科技权重相同时，固定选第一个。
    //   例：线圈炮(100) / 矿物提纯(100) / 瓷金复合材料(-44) → 永远选线圈炮
    //
    // 【旧实现】if (w > bestPosCfg) —— 并列时 false，保留先出现的
    //
    // 【新实现】并列者全收集到列表，然后平均概率随机选
    //   ★ 与游戏自己的轮盘赌（0x1B56FB0）行为一致
    //
    int bestPos = -1;   long long bestPosCfg = -1;
    int bestNeg = -1;   long long bestNegVal = 0;   // ★ 数值（越接近 0 越优）
    bool allZero = true;      // 所有可读到 key 的候选权重都是 0
    int  readable = 0;        // 能读到 key 的候选数

    // 并列者列表（最高权重的可能有多个）
    // ==========================================================================
    // ★★ 2026-11-20：平局随机 —— 改用 xorshift64* ★★
    // ==========================================================================
    //
    // 【旧实现的缺陷（用户实测：40 次 → 13/8/2，偏差 +69.6% / -73.9%）】
    //   mix = tick*A + c*B，取 (mix >> 33) % n
    //   ⇒ >> 33 只保留高 31 位，丢弃了 c*B 最活跃的低位熵
    //   ⇒ 实测 10000 次：3193/3428/3379，χ² = 9.2 > 5.99（显著偏差）
    //
    // 【新实现：xorshift64*】
    //   · 状态持久（static），每次调用都推进，不依赖 tick 粒度
    //   · 周期 2^64-1，分布经验证均匀（实测 10000 次：χ² = 0.1）
    //   · 几条指令，开销极小
    //   · 用 % n（低位），而不是 >> 33（高位）——这是关键修正
    //
    // ★ 2026-11-20：改为返回「在 list 里的下标位置」（而非 list[i] 的值）
    //   这样调用处可以同时获得 ridx（list[ridx]）和选中值（arr[list[ridx]]）
    auto pickRandomTieIdx = [](const int* list, int n) -> int {
        if (n <= 0) return -1;
        if (n == 1) return 0;

        static volatile LONG64 s_rngState = 0;
        LONG64 st = InterlockedCompareExchange64(&s_rngState, 0, 0);
        if (st == 0) {
            uint64_t seed = GetTickCount64()
                          ^ ((uint64_t)(uintptr_t)&s_rngState)
                          ^ (((uint64_t)(uintptr_t)list) << 13);
            if (seed == 0) seed = 0x9E3779B97F4A7C15ull;
            InterlockedCompareExchange64(&s_rngState, (LONG64)seed, 0);
            st = InterlockedCompareExchange64(&s_rngState, 0, 0);
            if (st == 0) st = (LONG64)seed;
        }

        uint64_t x = (uint64_t)st;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        InterlockedExchange64(&s_rngState, (LONG64)x);

        const uint64_t r = x * 0x2545F4914F6CDD1Dull;
        return (int)(r % (uint64_t)n);
    };

    int tiePos[64];  int tiePosCount = 0;
    int tieNeg[64];  int tieNegCount = 0;
    bool haveNeg = false;     // 是否已遇到过负数（用于首次初始化）

    // 并列统计（用于让用户验证随机均匀性）

    for (int i = 0; i < cnt; ++i) {
        void* tech = arr[i];
        if (!tech) continue;
        long long w = 0;
        if (!Tk2ReadCfg(tech, &w)) continue;   // key 读不到 → 跳过
        ++readable;
        if (w != 0) allZero = false;

        if (w > 0) {
            if (w > bestPosCfg) {
                // 更高 → 重置列表
                bestPosCfg = w;
                tiePosCount = 0;
                tiePos[tiePosCount++] = i;
            } else if (w == bestPosCfg) {
                // ★ 并列 → 加入列表
                if (tiePosCount < 64) tiePos[tiePosCount++] = i;
            }
        } else if (w < 0) {
            // 负数取【数值最大】（最接近 0）
            if (!haveNeg || w > bestNegVal) {
                bestNegVal = w;
                haveNeg = true;
                tieNegCount = 0;
                tieNeg[tieNegCount++] = i;
            } else if (w == bestNegVal) {
                if (tieNegCount < 64) tieNeg[tieNegCount++] = i;
            }
        }
    }

    // ==========================================================================
    // ★★ 2026-11-18 修正：verdict 与 ours 必须一致 ★★
    // ==========================================================================
    //
    // 【用户发现的 bug】
    //   342 条 [PICK] 里有 106 条是〈ours=- action=OVERRIDE-POS〉—— 自相矛盾。
    //
    // 【根因】
    //   旧版 verdict 基于「有没有找到 bestPos」，
    //   而 ours 基于「chosen != gamePick 且 key 可读」。
    //   当「我们算出的最优恰好 == gamePick」时，
    //   verdict 说 OVERRIDE 但 ours 是 "-"。
    //
    // 【正确语义】
    //   先算出 candidate，再用「candidate 是否与 gamePick 不同」统一判定 verdict 与 chosen。
    //
    const bool allOff = (readable > 0 && allZero);
    const bool usePos = (tiePosCount > 0);
    const bool useNeg = (!usePos && tieNegCount > 0);

    // ① 先算出候选（并列时平均概率随机）
    //
    //   ★ 2026-11-20：ridx = 随机选中的「候选数组下标」
    //     用户可以直接对照 cand[ridx] 看出选了哪个
    //
    int ridx = -1;
    void* candidate = nullptr;
    if (allOff) {
        candidate = nullptr;                       // 全禁
    } else if (usePos) {
        const int k = pickRandomTieIdx(tiePos, tiePosCount);
        ridx = (k >= 0) ? tiePos[k] : -1;
        bestPos = ridx;
        candidate = (ridx >= 0) ? arr[ridx] : nullptr;
    } else if (useNeg) {
        const int k = pickRandomTieIdx(tieNeg, tieNegCount);
        ridx = (k >= 0) ? tieNeg[k] : -1;
        bestNeg = ridx;
        candidate = (ridx >= 0) ? arr[ridx] : nullptr;
    } else {
        candidate = gamePick;                      // 无法决策
    }

    // ② 统一判定（单一真值）
    void* chosen = gamePick;
    bool  skip = false;
    const char* verdict = "KEEP";

    if (allOff) {
        // 全禁 → 清 bit + 跳过装槽
        //
        //   能返回 nullptr 的原因：trampoline 有 null 检查
        //     mov g_tk2Result(%rip),%rax / test %rax,%rax / je → jmp *g_tk2BackS
        //
#if !AR_TAKEOVER_V2_DRYRUN
        if (SafeReadable((uint8_t*)slotmgr + 0x08, 1)) {
            *(volatile uint8_t*)((uint8_t*)slotmgr + 0x08) &= (uint8_t)~(1u << area);
        }
#endif
        chosen = nullptr;
        skip = true;
        verdict = "ALL-DISABLED";
    } else if (candidate == nullptr || readable == 0) {
        // ★ 无候选 / 一个 key 都读不到 → 完全不干预
        chosen = gamePick;
        verdict = "KEEP";
    } else if (candidate == gamePick) {
        // ★ 算出的最优 == 游戏选的。
        //   用户需要知道「接管逻辑是否在工作」，所以区分两种：
        //     KEEP-TIE-HIT    —— 并列随机恰好撞上 gamePick（接管在工作）
        //     KEEP-SAME-BEST  —— 唯一最优恰好 == gamePick（也在工作）
        chosen = gamePick;
        const bool anyTie = (tiePosCount > 1) || (tieNegCount > 1);
        verdict = anyTie ? "KEEP-TIE-HIT" : "KEEP-SAME-BEST";
        if (anyTie) ++s_tieHitGame;
    } else if (!SafeReadable(candidate, 8)) {
        // 不可读 → 退回
        chosen = gamePick;
        skip = false;
        verdict = "UNREADABLE-FALLBACK";
    } else {
        // 真接管
        chosen = candidate;
        if (usePos) verdict = (tiePosCount > 1) ? "OVERRIDE-POS-TIE" : "OVERRIDE-POS";
        else        verdict = (tieNegCount > 1) ? "OVERRIDE-NEG-TIE" : "OVERRIDE-NEG";
    }
    // else: readable == 0（一个 key 都读不到）→ 不干预

    // ==========================================================================
    // ★★ 2026-11-18：选中对象可读性检查（审查员 A 的中风险项）
    // ==========================================================================
    //
    // 理由：我们主动选了 arr[bestPos] / arr[bestNeg]。
    //   如果那个元素在选中后失效（被回收/重建），
    //   trampoline 会执行 MOV RDX,[RAX]，踩到游戏原本不会踩的路径。
    //   这里做一次二重保险：不可读 → 退回游戏原选。
    //
    // ==========================================================================
    // ★★ 2026-11-20 修正：并列统计必须在【所有决策分支之后】★★
    // ==========================================================================
    //
    // 【旧 bug（用户实测）】
    //   [汇总] 并列=0，但 [PICK] 里 260 条「接管（并列随机）」
    //
    // 【根因】
    //   这段代码原本被错放在 UNREADABLE-FALLBACK 分支【内部】，
    //   而那个分支只在「chosen 不可读」时执行（极罕见）。
    //   正常接管路径根本走不到 → s_tieTotal 永远是 0。
    //
    // 【修法】
    //   移到决策完成（verdict 已确定）之后、UNREADABLE 检查之前，
    //   不在任何条件分支内部。
    //
    // 【验证】
    //   撞上率 = 撞上gamePick / 总并列次数
    //   理论值 = 1/N（N = 平均并列个数）；N=3 时理论 33.3%
    //
    {
        const bool anyTieNow = (tiePosCount > 1) || (tieNegCount > 1);
        if (anyTieNow) {
            const LONG n = InterlockedIncrement(&s_tieTotal);
            if (tiePosCount > 1) InterlockedIncrement(&s_tiePosN);
            if (tieNegCount > 1) InterlockedIncrement(&s_tieNegN);
            if ((n % 300) == 0) {
                const LONG tot = InterlockedCompareExchange(&s_tieTotal, 0, 0);
                const LONG pos = InterlockedCompareExchange(&s_tiePosN, 0, 0);
                const LONG neg = InterlockedCompareExchange(&s_tieNegN, 0, 0);
                const LONG hit = InterlockedCompareExchange(&s_tieHitGame, 0, 0);
                const int pct = (tot > 0) ? (int)((hit * 100) / tot) : 0;
                Log("[并列] 总次数=%ld 正数并列=%ld 负数并列=%ld 撞上gamePick=%ld (撞上率=%d%%)",
                    (long)tot, (long)pos, (long)neg, (long)hit, pct);
            }
        }
    }

    // ==========================================================================
    // ★★ 2026-11-18：选中对象可读性检查（审查员 A 的中风险项）★★
    // ==========================================================================
    //
    // 理由：我们主动选了 arr[bestPos] / arr[bestNeg]。
    //   如果那个元素在选中后失效（被回收/重建），
    //   trampoline 会执行 MOV RDX,[RAX]，踩到游戏原本不会踩的路径。
    //   这里做一次二重保险：不可读 → 退回游戏原选。
    //
    if (chosen && chosen != gamePick && !SafeReadable(chosen, 8)) {
        chosen = gamePick;
        skip = false;
        verdict = "UNREADABLE-FALLBACK";
    }

    // ==========================================================================
    // ★★ 2026-11-18：[PICK] 详细选卡日志（用户明确需求）★★
    // ==========================================================================
    //
    // 用户需要能从日志读出三件事：
    //   ① 每次备选了哪些科技（列表）
    //   ② 游戏/手动选了其中哪个
    //   ③ 自动科研（我们的接管）选了哪个
    //
    // 日志量控制：
    //   真选卡（readable > 0）→ 全记（实测 1-2 次/小时）
// ==========================================================================
// ★★ 2026-11-18：[PICK] 选卡日志（单行格式，供 log_tool 解析）★★
// 格式（严格，不带 game= 字段）：
//   [PICK] area=%d cnt=%d cand=[k1,k2,k3] ours=%s action=%s
//
// 字段：
//   area   : 0/1/2
//   cnt    : 候选数量
//   cand   : 逗号分隔的 key 列表（按 arr 顺序，最多 8 个）
//   ours   : 我们选的 key（全禁/不干预时打 "-"）
//   action : OVERRIDE-POS / OVERRIDE-NEG / ALL-DISABLED / KEEP / NO-KEY
//
// 为什么不打 game=：
//   用户明确说「游戏选哪个不用管」。那个信息对判断玩家倾向没价值。
//
// 限流：
//   OVERRIDE / ALL-DISABLED → 全记（关键数据）
//   KEEP / NO-KEY          → 前 50 + 之后每 20
//
{
    const bool realPick = (cnt > 0 && readable > 0);
    const bool isKeyAction = (verdict[0] == 'O') ||
                             (verdict[0] == 'A' && verdict[1] == 'L');

    if (realPick) {
        char candBuf[512];
        candBuf[0] = 0;
        int pos = 0;
        const int lim = (cnt < 8) ? (int)cnt : 8;
        for (int i = 0; i < lim; ++i) {
            char k[64];
            k[0] = 0;
            if (!TkReadKey(arr[i], k, sizeof(k))) snprintf(k, sizeof(k), "-");
            const char* zh = ArTechZh(k);
            const int w = snprintf(candBuf + pos, sizeof(candBuf) - (size_t)pos,
                                   "%s%s（%s）", (i ? "," : ""), k, zh ? zh : "?");
            if (w > 0) pos += w;
            if (pos >= (int)sizeof(candBuf) - 70) break;
        }

        // ==================================================================
        // ★★ 2026-11-20：ours 必须与 ridx 一致★★
        //
        //   用户要求：KEEP-TIE-HIT 时也要能看出「随机落到了哪个」。
        //   因此 ours 基于 ridx（而非 chosen）：
        //     ridx >= 0 → ours = cand[ridx] 的 key（总是有值）
        //     ridx <  0 → ours = "-"（无可选 / 全禁）
        //
        char ourKey[64];
        ourKey[0] = 0;
        char ourBuf[128];
        ourBuf[0] = 0;
        const char* ourItem = "-";
        if (ridx >= 0 && ridx < cnt && TkReadKey(arr[ridx], ourKey, sizeof(ourKey))) {
            const char* zh = ArTechZh(ourKey);
            snprintf(ourBuf, sizeof(ourBuf), "%s（%s）", ourKey, zh ? zh : "?");
            ourItem = ourBuf;
        }
        // 兼容：如果 ridx 无效但 chosen 有效（理论上不会发生），回退到 chosen
        else if (chosen && chosen != gamePick && TkReadKey(chosen, ourKey, sizeof(ourKey)))
            ourItem = ourKey;

        if (isKeyAction) {
            ++s_pickKey;
            Log("[PICK] 领域=%s 候选数=%d 候选=[%s] 抽中=%d 选中=%s 动作=%s",
                ArAreaZh(area), (int)cnt, candBuf[0] ? candBuf : "-", ridx, ourItem, ArActionZh(verdict));
        } else {
            const LONG k = InterlockedIncrement(&s_pickKeep);
            if (k <= 50 || (k % 20) == 0) {
                Log("[PICK] 领域=%s 候选数=%d 候选=[%s] 抽中=%d 选中=%s 动作=%s",
                    ArAreaZh(area), (int)cnt, candBuf[0] ? candBuf : "-", ridx, ourItem, ArActionZh(verdict));
            }
        }
    } else {
        static volatile LONG s_pickNoop = 0;
        const LONG k = InterlockedIncrement(&s_pickNoop);
        if (k <= 10 || (k % 500) == 0) {
            Log("[PICK] 领域=%s 候选数=%d 候选=[] 抽中=-1 选中=- 动作=无可选", ArAreaZh(area), (int)cnt);
        }
    }
}

    // 汇总（每 300 次一条）
    {
        const LONG total = InterlockedCompareExchange(&s_tk2RealPicks, 0, 0)
                         + InterlockedCompareExchange(&s_tk2NoOps, 0, 0);
        // ★ 2026-11-20：300 → 100（实测一局 326+ 次决策，100 能打 3+ 条）
        if (total > 0 && (total % 500) == 0) {
            Log("[汇总·中期] 总决策=%ld 真选卡=%ld 早退=%ld 玩家=%ld AI=%ld | 并列=%ld 撞上原选=%ld",
                (long)total,
                (long)InterlockedCompareExchange(&s_tk2RealPicks, 0, 0),
                (long)InterlockedCompareExchange(&s_tk2NoOps, 0, 0),
                (long)InterlockedCompareExchange(&s_tk2PlayerPicks, 0, 0),
                (long)InterlockedCompareExchange(&s_tk2AiTicks, 0, 0),
                (long)InterlockedCompareExchange(&s_tieTotal, 0, 0),
                (long)InterlockedCompareExchange(&s_tieHitGame, 0, 0));
        }
    }
    const LONG n = n0;

#if AR_TAKEOVER_V2_DRYRUN
    // ★ 阶段 1：只观测。记录「本该怎么做」，但返回游戏原值。
    {
        const bool isOverride = (chosen != gamePick);
        if (isOverride || n <= 20 || (n % 500) == 0) {
#if AR_BUILD_WITH_PROBES
            // 维护版：保留指针（排查用）
            Log("%s n=%ld 领域=%s 候选数=%d 游戏原选=%p -> 我们选=%p "
                "(正数=第%d项/权重%lld 负数=第%d项/%lld 可读=%d 全禁=%s) 动作=%s",
                isOverride ? "[TAKE]" : "[take]",
                (long)n, ArAreaZh(area), (int)cnt, gamePick, chosen,
                bestPos, bestPosCfg, bestNeg, bestNegVal,
                readable, allZero ? "是" : "否",
                ArActionZh(verdict));
#else
            // 使用版：去掉无意义的指针
            Log("%s n=%ld 领域=%s 候选数=%d "
                "(正数=第%d项/权重%lld 负数=第%d项/%lld 可读=%d 全禁=%s) 动作=%s",
                isOverride ? "[TAKE]" : "[take]",
                (long)n, ArAreaZh(area), (int)cnt,
                bestPos, bestPosCfg, bestNeg, bestNegVal,
                readable, allZero ? "是" : "否",
                ArActionZh(verdict));
#endif
        }
    }

    return gamePick;   // ★ 不干预
#else

    {
        const bool isOverride = (chosen != gamePick);
        if (isOverride || n <= 20 || (n % 500) == 0) {
#if AR_BUILD_WITH_PROBES
            // 维护版：保留指针（排查用）
            Log("%s n=%ld 领域=%s 候选数=%d 游戏原选=%p -> 我们选=%p "
                "(正数=第%d项/权重%lld 负数=第%d项/%lld 可读=%d 全禁=%s) 动作=%s",
                isOverride ? "[TAKE]" : "[take]",
                (long)n, ArAreaZh(area), (int)cnt, gamePick, chosen,
                bestPos, bestPosCfg, bestNeg, bestNegVal,
                readable, allZero ? "是" : "否",
                ArActionZh(verdict));
#else
            // 使用版：去掉无意义的指针
            Log("%s n=%ld 领域=%s 候选数=%d "
                "(正数=第%d项/权重%lld 负数=第%d项/%lld 可读=%d 全禁=%s) 动作=%s",
                isOverride ? "[TAKE]" : "[take]",
                (long)n, ArAreaZh(area), (int)cnt,
                bestPos, bestPosCfg, bestNeg, bestNegVal,
                readable, allZero ? "是" : "否",
                ArActionZh(verdict));
#endif
        }
    }
    return chosen;
}
#endif  // AR_TAKEOVER_V2_DRYRUN

// 安装：0x6F334E 的 9 字节（mov rsi,rax / mov rdx,[rax] / mov rcx,rax）
//   → E9 rel32 到 nearby 桩 → 绝对跳转 → AR_TakeoverV2Tramp（DLL 内）
static uint8_t* g_tk2Near = nullptr;

static bool InstallTakeoverV2(uint64_t base) {
    static const uint8_t kPat[9] = {
        0x48,0x8B,0xF0,      // mov rsi,rax
        0x48,0x8B,0x10,      // mov rdx,[rax]
        0x48,0x8B,0xC8       // mov rcx,rax
    };
    // 在 0x6F2590..+len 内搜（0x6F2590 len 待确认，用 0x3349 附近窗口）
    const uint32_t lo = 0x6F3300, hi = 0x6F3400;
    uint32_t hit = 0; int nHit = 0;
    for (uint32_t rva = lo; rva + 9 <= hi; ++rva) {
        if (memcmp((uint8_t*)(uintptr_t)(base + rva), kPat, 9) == 0) {
            hit = rva; ++nHit;
        }
    }
    if (nHit != 1 || hit != 0x6F334E) {
        Log("[tk2] pattern hit %d at RVA 0x%X (expect 1 @ 0x6F334E) -> disabled", nHit, hit);
        return false;
    }
    g_tk2Patch = (uint8_t*)(uintptr_t)(base + hit);
    g_tk2BackNorm = base + 0x6F3357;   // 补执行后继续（虚函数检查）
    g_tk2BackSkip = base + 0x6F3369;   // 跳过装槽（inc r14d）
    if (!SafeReadable(g_tk2Patch, 9)) { Log("[tk2] unreadable -> disabled"); return false; }
    memcpy(g_tk2Orig, g_tk2Patch, 9);

    uint8_t* nearStub = AllocNearby(g_tk2Patch, 64);
    if (!nearStub) { Log("[tk2] AllocNearby failed err=%lu", (unsigned long)GetLastError()); return false; }
    {
        // ★★ 2026-11-17 崩溃修复：不能用 mov rax,imm64（会破坏 RAX = gamePick）★★
        //
        //   旧：48 B8 <imm64> FF E0  = mov rax,dst ; jmp rax
        //        ⇒ 进 trampoline 时 RAX 已变成 trampoline 地址
        //        ⇒ 第一句 mov %rax,g_tk2GamePick 存的是垃圾
        //
        //   新：FF 25 <disp32>            = jmp qword ptr [rip+disp32]
        //        完全不碰任何寄存器 ✓
        //
        //   布局（共 16 字节）：
        //     +0x00  FF 25 02 00 00 00   jmp [rip+2]  → +0x08
        //     +0x06  90 90               nop
        //     +0x08  <imm64> = dst       目标地址
        {
            uint8_t buf[16];
            buf[0] = 0xFF; buf[1] = 0x25;                 // jmp qword ptr [rip+disp32]
            int32_t disp = 2;                              // RIP(下一条=+6) + 2 = +8
            memcpy(buf + 2, &disp, 4);
            buf[6] = 0x90; buf[7] = 0x90;                 // nop 对齐
            uint64_t dst = (uint64_t)(uintptr_t)&AR_TakeoverV2Tramp;
            memcpy(buf + 8, &dst, 8);
            memcpy(nearStub, buf, 16);
            FlushInstructionCache(GetCurrentProcess(), nearStub, 16);
        }
    }
    g_tk2Near = nearStub;
    g_tk2BackN = g_tk2BackNorm;
    g_tk2BackS = g_tk2BackSkip;

    const int64_t rel = (int64_t)((uintptr_t)nearStub - ((uintptr_t)g_tk2Patch + 5));
    if (rel < INT32_MIN || rel > INT32_MAX) {
        Log("[tk2] rel32 OOR (rel=%lld)", (long long)rel);
        VirtualFree(nearStub, 0, MEM_RELEASE); g_tk2Near = nullptr;
        return false;
    }

    DWORD oldProt = 0;
    if (!VirtualProtect(g_tk2Patch, 9, PAGE_EXECUTE_READWRITE, &oldProt)) {
        Log("[tk2] VirtualProtect failed err=%lu", (unsigned long)GetLastError());
        VirtualFree(nearStub, 0, MEM_RELEASE); g_tk2Near = nullptr;
        return false;
    }
    {
        uint8_t buf[9];
        buf[0] = 0xE9;
        int32_t r32 = (int32_t)rel;
        memcpy(buf + 1, &r32, 4);
        memset(buf + 5, 0x90, 4);
        memcpy(g_tk2Patch, buf, 9);
    }
    VirtualProtect(g_tk2Patch, 9, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), g_tk2Patch, 9);

    InterlockedExchange(&s_tk2Installed, 1);
    Log("[tk2] take v2 INSTALLED at 0x%llX near=0x%llX backN=0x%llX backS=0x%llX",
        (unsigned long long)(uintptr_t)g_tk2Patch,
        (unsigned long long)(uintptr_t)nearStub,
        (unsigned long long)g_tk2BackNorm, (unsigned long long)g_tk2BackSkip);
    return true;
}

static void RemoveTakeoverV2() {
    if (!g_tk2Patch || !s_tk2Installed) return;
    DWORD oldProt = 0;
    if (VirtualProtect(g_tk2Patch, 9, PAGE_EXECUTE_READWRITE, &oldProt)) {
        memcpy(g_tk2Patch, g_tk2Orig, 9);
        VirtualProtect(g_tk2Patch, 9, oldProt, &oldProt);
        FlushInstructionCache(GetCurrentProcess(), g_tk2Patch, 9);
    }
    if (g_tk2Near) { VirtualFree(g_tk2Near, 0, MEM_RELEASE); g_tk2Near = nullptr; }
    g_tk2Patch = nullptr;
    InterlockedExchange(&s_tk2Installed, 0);
    Log("[tk2] take v2 removed");
}

// trampoline：
//   进入 rsp%16 = 0 → 8 push (64) → 0 → sub 0x20（shadow）→ 0 ✓
//   参数：rcx=slotmgr(原 rdi) rdx=area(原 r14d) r8=gamePick(原 rax)
//   ★ rax 会被 call 破坏，所以 gamePick 先存到全局再传
//   ★ 返回后结果写全局，然后:
//        skip ? jmp g_tk2BackS : 补执行三条 mov + jmp g_tk2BackN
extern "C" __attribute__((naked)) void AR_TakeoverV2Tramp();
__asm__(
    ".text\n"
    ".globl AR_TakeoverV2Tramp\n"
    "AR_TakeoverV2Tramp:\n"
    "  push %rax\n"
    "  push %rcx\n"
    "  push %rdx\n"
    "  push %r8\n"
    "  push %r9\n"
    "  push %r10\n"
    "  push %r11\n"
    // ★★ 2026-11-17 崩溃修复（两个 bug）★★
    //   bug1: sub 0x20 -> (0-56-32)%16 = 8 未对齐 -> CALL 崩
    //   bug2: mov 0x30(%rsp) 读的是 r9 不是 rax -> gamePick 是垃圾
    //   修法: sub 0x28（(0-56-40)%16=0 对齐）+ gamePick 改走全局
    //        （完全不依赖 [rsp+X] 偏移，彻底消除计算错误的可能）
    "  mov %rax, g_tk2GamePick(%rip)\n"   // 入口第一件事：保存 gamePick
    "  sub $0x28, %rsp\n"                  // ★ 0x28 才对齐
    // 参数：country = rbx（未被 push，保持原值）
    "  mov %rbx, %rcx\n"
    "  mov %r14d, %edx\n"
    "  mov g_tk2GamePick(%rip), %r8\n"    // 从全局读 gamePick
    "  call AR_TakeoverV2\n"
    "  mov %rax, g_tk2Result(%rip)\n"
    "  add $0x28, %rsp\n"                  // ★ 与 sub 配对
    "  pop %r11\n"
    "  pop %r10\n"
    "  pop %r9\n"
    "  pop %r8\n"
    "  pop %rdx\n"
    "  pop %rcx\n"
    "  pop %rax\n"
    // ★ rax 被 pop 恢复了（原 gamePick），但我们要用 chosen → 从全局读回
    "  mov g_tk2Result(%rip), %rax\n"
    "  test %rax, %rax\n"
    "  je 1f\n"
    // 正常路径：补执行三条 mov + jmp 0x6F3357
    "  mov %rax, %rsi\n"
    "  mov (%rax), %rdx\n"
    "  mov %rax, %rcx\n"
    "  jmp *g_tk2BackN(%rip)\n"
    // 跳过路径：直接 jmp 0x6F3369（不补执行、不装槽）
    "1:\n"
    "  jmp *g_tk2BackS(%rip)\n"
);


// ============================================================================
// 自动科研路径探针（0xBBC3E7）
// ============================================================================
//
// 【★ 2026-11-17 重大更正：下面原来的结论是错的，已用真机日志推翻】
//
//   旧注释（错）：
//     「0x6F2590 入口对 country+0x314C != 0 的国家直接 ret ⇒ 只处理 AI。
//       玩家的自动科研走另一条：0xBBC300 ⇒ 要改玩家的，必须 patch 0xBBC3E7。」
//
//   错因：判据方向搞反了。游戏的 is_human（0xD18175，逐字节）是
//         is_human = (country[+0x314C] != 0) && (byte[0x281B833] == 0)
//         而 0x6F32D0 的守卫与之同构：
//           0x6F32D0  CMP dword [RBX+0x314C], 0
//           0x6F32D7  JE  0x6F3372 (ret)     ; == 0 → 直接返回
//         ⇒ 0x6F2590 只在 +0x314C != 0 时执行 = 只处理 is_human 成立的国家 = 【玩家】。
//
// 【真机日志实证（225+ 条 [bp] + 31 条 [hookA]，同一份 DLL）】
//
//   [bp]（0xBBC3E7，本探针）  238 条，17 个 cid（1..15, 31, 85）
//       c314c=0  在 238/238  →  全部 isHuman=0  →  全是 AI
//       ★ cid=0 从不出现（min cid = 1）
//
//   [hookA]（0x6F2590 → 0x6F334E）  31 条
//       30 条：country = BASE + 0*0x37B8 = cid=0，isai=1  →  PLAYER-by-current-slot
//        1 条：country = BASE + 13*0x37B8 = cid=13，isai=0 →  ai-by-current-slot
//
//   ⇒ 0x6F2590 = 【玩家路径】，0xBBC300 = 【AI 路径】。
//   ⇒ 我们一开始 patch 的 0x6F334E 就在正确的位置上。
//
//   ★ 判据不是恒真的：同一份日志里 isai 有两个取值（0 和 1），
//     且 isai=1 恰好对应 cid=0（玩家）、isai=0 对应 cid=13（AI）。
//     修好后的判据把这两类正确分开 —— 这是它有效的直接证据。
//
//   ★ 副作用提醒：修复前 isai 的标签是反的。
//     旧日志里的 "ai-by-current-slot" 其实多半是玩家，"PLAYER-by-current-slot" 其实是 AI。
//
// 【保留原因】
//   本探针仍在 0xBBC3E7 上，只观测【AI】路径，不干预（真调 0x820B30 后返回原值）。
//   将来若要「让 AI 也用我的配置」，这里是接入点；否则可移除以减少日志。
//
// 【结构（逐字节核实）】
//   0xBBC300  push %rbx                       ; -8
//   0xBBC302  sub $0x50,%rsp                  ; -80 ⇒ rsp%16 = (8-8-80)%16 = 0
//   0xBBC306  cmpb $0,[0x143118210]           ; 启动模式标志（命令行参数）
//   0xBBC31A  <try 块>
//   0xBBC32E  call 0xBB2F20                   ; 取 country（见下）
//   0xBBC343  mov 0x2a68(%r14),%rcx           ; [country+0x2A68]
//   0xBBC34E  mov 0x8c(%rcx),%edx             ; [+0x8C]
//   0xBBC354  shr $0xb,%edx                   ; bit 11
//   0xBBC35A  je 0xBBC48C                     ; bit11==0 → 跳过
//   0xBBC36D  call 0xBB2F20                   ; 再取 country
//   0xBBC37D  mov %rax,%rsi                   ; ★ RSI = country（此后无其他写入）
//   0xBBC37A  mov %r14d,%edi                  ; EDI = area
//   0xBBC3DB  lea 0x1620(%rsi),%rcx           ; slotmgr = country + 0x1620
//   0xBBC3E7  call 0x820B30                   ; ★ patch 点（5 字节）
//   0xBBC3EC  mov %rax,%rcx                   ; 跳回目标（★ 依赖 RAX）
//
//   ★ 注意：旧注释写「EDI = 0（area）」也不对。真机日志 area 分布 =
//     (0:82, 1:82, 2:68)，外层是「(国家 × area) 双重循环」，三个领域都会走到。
//
// 【本探针只观测不干预】真调 0x820B30、记录、返回原值。
// ============================================================================

static uint8_t* g_bpPatch = nullptr;
static uint8_t  g_bpOrig[5] = {0};
static uint64_t g_bpBack = 0;
static volatile LONG s_bpInstalled = 0;
static volatile LONG s_bpHits = 0;
static volatile LONG s_bpOverrides = 0;
static uint8_t* g_bpNear = nullptr;

extern "C" { uint64_t g_bpBackAddr = 0; }

typedef void* (*PFN_SelTech)(void* slotmgr, int area);
static PFN_SelTech g_pfnSelTech = nullptr;

extern "C" void* AR_PlayerPathProbe(void* country, int area, void* rspNow) {
    const LONG n = InterlockedIncrement(&s_bpHits);
    const uint64_t rsp16 = ((uintptr_t)rspNow + 0x20 + 64) & 15u;

    void* slotmgr = nullptr;
    if (country && SafeReadable((uint8_t*)country + 0x1620, 8))
        slotmgr = (void*)((uint8_t*)country + 0x1620);

    int bit11 = -1;
    if (country && SafeReadable((uint8_t*)country + 0x2A68, 8)) {
        void* sub = *(void* volatile*)((uint8_t*)country + 0x2A68);
        if (sub && SafeReadable((uint8_t*)sub + 0x8C, 4)) {
            const uint32_t v = *(volatile uint32_t*)((uint8_t*)sub + 0x8C);
            bit11 = (int)((v >> 11) & 1u);
        }
    }

    int globalMode = -1;
    if (SafeReadable((void*)(uintptr_t)(g_base + 0x3118210), 1))
        globalMode = (int)*(volatile uint8_t*)(uintptr_t)(g_base + 0x3118210);

    // ★ 真调选卡器（保持副作用）
    void* ret = nullptr;
    if (g_pfnSelTech && slotmgr) ret = g_pfnSelTech(slotmgr, area);

    // ==========================================================================
    // country id vs player id（为将来的玩家判据准备数据）
    // ==========================================================================
    //
    // 【GETC = 0x266340】
    //   0x266346  mov %rcx,%rbx        ; rbx = param_1
    //   0x26634E  mov %rbx,%rcx        ; 写回 rcx
    //   0x266358  call 0x24C5F0        ; 无参，拿 game state
    //   0x266369  mov 0x5c(%rax),%r8d  ; player id（路径A）
    //   0x266380  mov 0x60(%rax),%r8d  ; player id（路径B）
    //   0x2663B6  ret
    // ⇒ param_1 被存入 rbx 但从未被当作基址读取
    // ⇒ 传 nullptr 安全✓
    //
    uint32_t cid = 0xFFFFFFFFu;
    if (country && SafeReadable((uint8_t*)country + 0x20, 4))
        cid = (*(volatile uint32_t*)((uint8_t*)country + 0x20)) & 0xFFFFFFu;

    // ==========================================================================
    // 玩家 id —— 直接读内存，不调任何函数
    // ==========================================================================
    //
    // 【★★ 2026-11-17 崩溃根因：不能调 0x24C5F0 和 0x266340 】
    //
    //   0x24C5F0 的完整反汇编（len 138，已逐字节核实）：
    //     0x24C5FA  mov %rcx,%rdi           ★ RCX 存入 RDI
    //     0x24C5FF  mov [0x14311BF18],%rcx   ★ 读全局
    //     0x24C60B  mov 0x140(%rcx),%rcx
    //     0x24C615  call *0x70(%rax)         虚调用
    //     0x24C61D  movslq 0x24(%rdi),%rcx   ★★ [RDI+0x24] 读内存！
    //     0x24C62B  mov 0x18(%rdi),%r9       ★★ [RDI+0x18] 读内存！
    //     0x24C640  cmp %eax,(%rcx)          遍历数组（步长 0x68）
    //
    //   ⇒ 传 nullptr 或垃圾 RCX → [RDI+0x24] 访问违规 → 崩。
    //   ⇒ GETC(0x266340) 把 param_1 传给它，也崩。
    //
    // 【正确做法】不调函数，直接读：
    //   gs = [0x311BF18]（★注意：不是 0x3119F18，之前差了一位）
    //   player id = gs+0x5C（路径A，[gs+0x38]!=0）或 gs+0x60（路径B）
    //
    uint32_t pid = 0xFFFFFFFFu;
    uint64_t gs038 = 0xFFFFFFFFFFFFFFFFull;
    void* gsPtr = nullptr;
    if (g_base && SafeReadable((void*)(uintptr_t)(g_base + 0x311BF18), 8)) {
        gsPtr = *(void* volatile*)(uintptr_t)(g_base + 0x311BF18);
    }
    if (gsPtr && SafeReadable((uint8_t*)gsPtr + 0x38, 8)) {
        gs038 = *(volatile uint64_t*)((uint8_t*)gsPtr + 0x38);
        const uint32_t idOff = (gs038 != 0) ? 0x5Cu : 0x60u;
        if (SafeReadable((uint8_t*)gsPtr + idOff, 4)) {
            pid = (*(volatile uint32_t*)((uint8_t*)gsPtr + idOff)) & 0xFFFFFFu;
        }
    }

    // ★★ 2026-11-17：pid 诊断（前 10 条才输出）
    //
    //   实测 pid 恒为 0，但 gs038 = 0x1F → 走路径 A → 读 [gs+0x5C] = 0。
    //   三种可能：
    //     ① 0x311BF18 不是 game state（它是某个注册函数的 param_1）
    //     ② player id 不在 +0x5C
    //     ③ 此时恰好为 0
    //
    //   → 扫 gs 前 0x100 字节，把值在 1..200 的 uint32 字段都打出来，
    //     与 country id（已知 1..85）对照，就能找到 player id。
    if (n <= 10 && gsPtr && SafeReadable((uint8_t*)gsPtr, 0x100)) {
        Log("[bp-pid] gs=%p gs038=0x%llX cid=%u : scanning gs+0x00..0x100 for ids 1..200",
            gsPtr, (unsigned long long)gs038, cid);
        char line[512];
        int pos = 0;
        for (uint32_t off = 0; off < 0x100; off += 4) {
            const uint32_t v = *(volatile uint32_t*)((uint8_t*)gsPtr + off);
            if (v >= 1 && v <= 200) {
                pos += snprintf(line + pos, sizeof(line) - pos, " +%02X=%u", off, v);
                if (pos > 420) break;
            }
        }
        if (pos > 0) Log("[bp-pid]   candidates:%s", line);
        else Log("[bp-pid]   no candidates in 1..200");
    }

    int cnt = -1, inCand = -1;
    if (slotmgr) {
        uint8_t* slot = (uint8_t*)slotmgr + (size_t)(area + 11) * 0x18;
        if (SafeReadable(slot, 0x18)) {
            void** arr = (void**)(*(void* volatile*)(slot + 0x08));
            cnt = *(volatile int32_t*)(slot + 0x14);
            if (arr && cnt > 0 && cnt <= 64 && SafeReadable(arr, (size_t)cnt * 8)) {
                inCand = 0;
                for (int i = 0; i < cnt; ++i) if (arr[i] == ret) { inCand = 1; break; }
            }
        }
    }

    // ==========================================================================
    // ★★ 决策（阶段 2）
    // ==========================================================================
    //
    // 【为什么在原调用之后决策】
    //   0x820B30 有清空候选槽等副作用，必须真调。
    //   我们只在「返回值被消费之前」替换它。
    //
    // 【安全性】
    //   · ret 不在候选数组里（哨兵/早退）→ 不干预
    //   · 所有配置都没命中 → 不干预
    //   · 只有「真选卡 + 有配置」才覆盖
    //
    void* chosen = ret;
    const char* verdict = "no-cfg";
    int bestPos = -1, bestNeg = -1;
    long long bestPosCfg = 0, bestNegAbs = 0;
    bool anyConfigured = false;

    if (inCand == 1 && slotmgr) {
        uint8_t* slot = (uint8_t*)slotmgr + (size_t)(area + 11) * 0x18;
        if (SafeReadable(slot, 0x18)) {
            void** arr2 = (void**)(*(void* volatile*)(slot + 0x08));
            if (arr2 && cnt > 0 && cnt <= 64 && SafeReadable(arr2, (size_t)cnt * 8)) {
                for (int i = 0; i < cnt; ++i) {
                    void* tech = arr2[i];
                    if (!tech) continue;
                    long long w = 0;
                    if (!Tk2ReadCfg(tech, &w)) continue;
                    anyConfigured = true;
                    if (w > 0) { if (w > bestPosCfg) { bestPosCfg = w; bestPos = i; } }
                    else if (w < 0) { const long long a = -w; if (a > bestNegAbs) { bestNegAbs = a; bestNeg = i; } }
                }
                if (bestPos >= 0) { chosen = arr2[bestPos]; verdict = "OVERRIDE-POS"; }
                else if (bestNeg >= 0) { chosen = arr2[bestNeg]; verdict = "OVERRIDE-NEG"; }
                else if (anyConfigured) {
                    // ★★ 方案 B（阶段 2a）：全禁时不干预 ★★
                    //
                    // 0xBBC3E7 之后的消费路径：
                    //   0xBBC3F2  MOV RDX,[RAX]   ← 解引用（nullptr 会崩）
                    //   0xBBC3F5  CALL [RDX+8]    ← 虚调用有效性检查
                    //   0xBBC3FA  JE 0xBBC460     ← false → 跳过创建
                    // 因此全禁不能返回 nullptr。
                    // 真正的「全禁」需额外 patch 0xBBC3F2（阶段 2b）。
                    chosen = ret;
                    verdict = "ALL-DISABLED-KEEP";
                }
                else { verdict = "no-cfg"; }
            }
        }
    } else if (inCand == 0) {
        verdict = "SENTINEL";
    }

    if (n <= 200 || (n % 200) == 0) {
        // ====================================================================
        // 2026-11-17 追加：把 is_human 的两个条件都打出来（只读）
        // ====================================================================
        // 目的：一次性裁决「cid=0 是不是玩家」以及「0x6F2590 处理的是玩家还是 AI」。
        //
        //   is_human = (country[+0x314C] != 0) AND (byte[g_base+0x281B833] == 0)
        //   （逐字节来源：0xD18175 / 0xD1817E，见 PLAYER_CRITERION_HUNT.md §3.2）
        //
        // 打印三个字段：
        //   c314c   = country[+0x314C] 原始 int32（-999 = 读不到）
        //   g833    = byte[g_base+0x281B833]（-1 = 读不到）
        //   isHuman = 按上面公式算出的布尔（1/0）
        //
        // 判读方法（下一轮日志）：
        //   · 18 个 cid 的 c314c 若全为 0  → 它们是 AI，0xBBC300 = AI 路径
        //   · 若某个 cid 的 c314c != 0    → 那个国家是玩家，0xBBC300 含玩家
        //   · g833 在单人档应恒 0；若恒非 0，说明它不是「多人标志」
        int32_t c314c = -999;
        if (country && SafeReadable((uint8_t*)country + 0x314C, 4))
            c314c = *(volatile int32_t*)((uint8_t*)country + 0x314C);
        int g833 = -1;
        if (g_base && SafeReadable((void*)(uintptr_t)(g_base + 0x281B833), 1))
            g833 = (int)*(volatile uint8_t*)(uintptr_t)(g_base + 0x281B833);
        const int isHuman = (c314c != -999 && g833 >= 0 && c314c != 0 && g833 == 0) ? 1 : 0;

        Log("[bp] n=%ld area=%d rsp16=%llu country=%p cid=%u pid=%u%s slotmgr=%p bit11=%d global=%d cnt=%d ret=%p inCand=%d -> %s (ours=%p pos=%d/%lld neg=%d/%lld) c314c=%d g833=%d isHuman=%d",
            (long)n, area, (unsigned long long)rsp16, country, cid, pid,
            ((pid == 0xFFFFFFFFu) ? " pid=UNKNOWN" : ((pid == 0) ? " pid=NONE" : ((cid == pid) ? " ISPLAYER" : ""))), slotmgr,
            bit11, globalMode, cnt, ret, inCand, verdict,
            chosen, bestPos, bestPosCfg, bestNeg, bestNegAbs,
            (int)c314c, g833, isHuman);
        // 路径标记（只前 20 条，避免刷屏）
        if (n <= 20) {
            Log("[bp-gs] n=%ld gs038=0x%llX path=%c (A=[+0x5C] B=[+0x60])",
                (long)n, (unsigned long long)gs038,
                (gs038 != 0) ? 'A' : 'B');
        }
    }

#if AR_TAKEOVER_BP_DRYRUN
    return ret;              // ★ 阶段 1：不改行为
#else
    // ★★ 阶段 2a（方案 B，2026-11-17）★★
    //
    // 只做「正数最大 / 负数|最大|」接管。
    // 全禁 → 不干预（chosen == ret），因为：
    //   0xBBC3F2  MOV RDX,[RAX]   ← 解引用，nullptr 会崩
    //   0xBBC3F5  CALL [RDX+8]    ← 虚调用有效性检查
    //   0xBBC3FA  JE 0xBBC460     ← false → 跳过创建
    // 全禁的真正实现需要额外 patch 0xBBC3F2（阶段 2b）。
    if (chosen != ret && chosen != nullptr && inCand == 1) {
        const LONG ov = InterlockedIncrement(&s_bpOverrides);
        if (ov <= 20) {
            Log("[bp-LIVE] OVERRIDE #%ld area=%d game=%p -> ours=%p pos=%d/%lld",
                (long)ov, area, ret, chosen, bestPos, bestPosCfg);
        }
        return chosen;
    }
    return ret;
#endif
}

// trampoline：
//   进入 rsp%16 = 0（已验算）
//   8 push (64) → 仍 0 → sub 0x20（shadow）→ 仍 0 ✓
//   ★ 不 push rax 之外的结果寄存器；返回值经全局带出
extern "C" { volatile uint64_t g_bpRet = 0; }

extern "C" __attribute__((naked)) void AR_BpTramp();
__asm__(
    ".text\n"
    ".globl AR_BpTramp\n"
    "AR_BpTramp:\n"
    "  push %rax\n"
    "  push %rcx\n"
    "  push %rdx\n"
    "  push %r8\n"
    "  push %r9\n"
    "  push %r10\n"
    "  push %r11\n"
    "  push %rbx\n"
    "  sub $0x20, %rsp\n"
    "  mov %rsi, %rcx\n"      // country
    "  mov %edi, %edx\n"      // area
    "  mov %rsp, %r8\n"       // rspNow
    "  call AR_PlayerPathProbe\n"
    "  mov %rax, g_bpRet(%rip)\n"   // ★ 结果存全局
    "  add $0x20, %rsp\n"
    "  pop %rbx\n"
    "  pop %r11\n"
    "  pop %r10\n"
    "  pop %r9\n"
    "  pop %r8\n"
    "  pop %rdx\n"
    "  pop %rcx\n"
    "  pop %rax\n"
    "  mov g_bpRet(%rip), %rax\n"   // ★ 从全局读回返回值（0xBBC3EC 依赖 RAX）
    "  jmp *g_bpBackAddr(%rip)\n"
);

static bool InstallPlayerPathProbe(uint64_t base) {
    static const uint8_t kPat[5] = { 0xE8, 0x44, 0x47, 0xC6, 0xFF };
    const uint32_t lo = 0xBBC360, hi = 0xBBC484;
    uint32_t hit = 0; int nHit = 0;
    for (uint32_t rva = lo; rva + 5 <= hi; ++rva) {
        if (memcmp((uint8_t*)(uintptr_t)(base + rva), kPat, 5) == 0) { hit = rva; ++nHit; }
    }
    if (nHit != 1 || hit != 0xBBC3E7) {
        Log("[bp] pattern hit %d at RVA 0x%X (expect 1 @ 0xBBC3E7) -> disabled", nHit, hit);
        return false;
    }
    g_bpPatch = (uint8_t*)(uintptr_t)(base + hit);
    g_bpBack  = base + 0xBBC3EC;
    g_pfnSelTech = (PFN_SelTech)(uintptr_t)(base + 0x820B30);
    if (!SafeReadable(g_bpPatch, 5)) { Log("[bp] unreadable -> disabled"); return false; }
    memcpy(g_bpOrig, g_bpPatch, 5);

    uint8_t* nearStub = AllocNearby(g_bpPatch, 64);
    if (!nearStub) { Log("[bp] AllocNearby failed err=%lu", (unsigned long)GetLastError()); return false; }
    {
        uint8_t buf[16];
        buf[0] = 0xFF; buf[1] = 0x25;
        int32_t disp = 2;
        memcpy(buf + 2, &disp, 4);
        buf[6] = 0x90; buf[7] = 0x90;
        uint64_t dst = (uint64_t)(uintptr_t)&AR_BpTramp;
        memcpy(buf + 8, &dst, 8);
        memcpy(nearStub, buf, 16);
        FlushInstructionCache(GetCurrentProcess(), nearStub, 16);
    }
    g_bpNear = nearStub;
    g_bpBackAddr = g_bpBack;

    const int64_t rel = (int64_t)((uintptr_t)nearStub - ((uintptr_t)g_bpPatch + 5));
    if (rel < INT32_MIN || rel > INT32_MAX) {
        Log("[bp] rel32 OOR (%lld)", (long long)rel);
        VirtualFree(nearStub, 0, MEM_RELEASE); g_bpNear = nullptr; return false;
    }
    DWORD oldProt = 0;
    if (!VirtualProtect(g_bpPatch, 5, PAGE_EXECUTE_READWRITE, &oldProt)) {
        Log("[bp] VP failed err=%lu", (unsigned long)GetLastError());
        VirtualFree(nearStub, 0, MEM_RELEASE); g_bpNear = nullptr; return false;
    }
    {
        uint8_t buf[5];
        buf[0] = 0xE9;
        int32_t r32 = (int32_t)rel;
        memcpy(buf + 1, &r32, 4);
        memcpy(g_bpPatch, buf, 5);
    }
    VirtualProtect(g_bpPatch, 5, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), g_bpPatch, 5);

    InterlockedExchange(&s_bpInstalled, 1);
    Log("[bp] PLAYER-PATH probe INSTALLED at 0x%llX near=0x%llX back=0x%llX",
        (unsigned long long)(uintptr_t)g_bpPatch,
        (unsigned long long)(uintptr_t)nearStub,
        (unsigned long long)g_bpBack);
    return true;
}

// ============================================================================
// ★ A 点探针 v3（0x820E4B，选卡循环体内）
// ============================================================================
//
// 【目标】一次运行验证 5 件事：
//   ① tech key 可读性（决定 take 能否做）
//   ② raw ai_weight 数值域
//   ③ 栈对齐（自报 rsp16）
//   ④ 循环行为（i 递增 0..count-1）
//   ⑤ std::string 布局（sz/cap 合理性）
//
// 【为什么是这里】
//   0x820B30 (len 1138) 是「每日 tick → 科研选择」的核心循环：
//     0x820DFC  xor edi,edi              ; i = 0
//     0x820DFE  mov rsi,[r13+0x08]       ; rsi = 候选数组起点
//     0x820E02  lea rax,[rsi+r14*8]      ; 数组尾
//     0x820E10  cmp edi,r14d / jge 结束
//     0x820E15  mov r15,[rsi]            ; ★ r15 = 当前候选 tech 指针
//     0x820E25  call 0x81CEE0            ; 资格检查
//     0x820E46  call 0x821070            ; 算 ai_weight → [rbp+0x1D8]
//     0x820E4B  mov ecx,0x8000           ; ★ patch 起点
//     0x820E50  cmp [rbp+0x1D8],rcx
//     0x820E57  cmovge rcx,[rbp+0x1D8]   ; clamp 到 [0x8000, raw]
//     0x820E62  mov [r12+rax*8],rcx      ; 写入权重数组
//     0x820E66  inc edi / add rsi,8 / jne 循环
//
// 【20 字节 patch】（全 exe 唯一，已核验）
//   B9 00 80 00 00               mov ecx,0x8000        (5)
//   48 39 8D D8 01 00 00         cmp [rbp+0x1D8],rcx   (7)
//   48 0F 4D 8D D8 01 00 00      cmovge rcx,[rbp+..]   (8)
//   ⇒ 三条完整指令，边界 0x820E5F = 48 63 C7 (movsxd rax,edi) 干净
//
// 【栈对齐】
//   0x820B30 prologue: 6 push + sub 0x1A0
//     (8 - 24 - 32 - 416) % 16 = 0  ⇒ 0x820E4B 处 rsp%16 = 0
//   trampoline: JMP 进入 rsp%16=0 → 7 push = 8 → sub 0x28 = 0 ✓
//
// 【标志位链】
//   mov ecx,imm 不改 flags；cmp 设 flags；cmovge 读 flags
//   ⇒ 三条必须在 call 之后连续执行（本实现保证）
// ============================================================================

static uint8_t* g_selBPatch = nullptr;     // patch 点（运行时地址）
static uint8_t  g_selBOrig[20] = {0};      // 原 20 字节（用于回滚）
static uint64_t g_selBBack = 0;            // 跳回地址 = base + 0x820E5F
static volatile LONG s_selBInstalled = 0;
static volatile LONG s_selBCount = 0;

// trampoline 需要从这里取跳回地址
extern "C" { uint64_t g_selBBackAddr = 0; }

extern "C" void AR_SelBLog(void* tech, int64_t raw, int idx, void* rspNow) {
    LONG n = InterlockedIncrement(&s_selBCount);
    // 限流：前 300 条全记，之后每 500 条一条
    if (n > 300 && (n % 500) != 0) return;

    // rsp16 = 还原到 trampoline 入口时的 rsp % 16（应为 0）
    const uint64_t rsp16 = ((uintptr_t)rspNow + 0x28 + 56) & 15u;

    // tech key：按 layout A（+0x360 buf / +0x370 size / +0x378 cap）读，
    // 同时尝试 +0x20（交接文档的假设）。两条都试，谁成功用谁。
    char keyA[128] = {0}, keyB[128] = {0};
    const char* kpA = nullptr;
    const char* kpB = nullptr;
    uint64_t szA = 0, capA = 0, szB = 0, capB = 0;

    if (tech && SafeReadable(tech, 0x380)) {
        // ---- 假设 A：+0x360（我们此前用 SEL 验证过的 layout A）----
        uint8_t* o = (uint8_t*)tech + 0x360;
        szA  = *(volatile uint64_t*)((uint8_t*)tech + 0x370);
        capA = *(volatile uint64_t*)((uint8_t*)tech + 0x378);
        if (szA > 0 && szA < 100 && capA >= szA) {
            const char* p = (capA > 15) ? *(const char* volatile*)o : (const char*)o;
            if (p && SafeReadable(p, (size_t)szA)) {
                uint64_t k = (szA < sizeof(keyA) - 1) ? szA : sizeof(keyA) - 1;
                memcpy(keyA, p, (size_t)k); keyA[k] = 0; kpA = keyA;
            }
        }
        // ---- 假设 B：+0x20（交接文档）----
        uint8_t* o2 = (uint8_t*)tech + 0x20;
        szB  = *(volatile uint64_t*)(o2 + 0x10);
        capB = *(volatile uint64_t*)(o2 + 0x18);
        if (szB > 0 && szB < 100 && capB >= szB) {
            const char* p = (capB > 15) ? *(const char* volatile*)o2 : (const char*)o2;
            if (p && SafeReadable(p, (size_t)szB)) {
                uint64_t k = (szB < sizeof(keyB) - 1) ? szB : sizeof(keyB) - 1;
                memcpy(keyB, p, (size_t)k); keyB[k] = 0; kpB = keyB;
            }
        }
    }

    // ==========================================================================
    // [map] tech id ↔ key 映射（2026-11-16 v2，数据源改为 A 点探针的 r15）
    // ==========================================================================
    //
    // 【为什么换数据源】
    //   旧版从 C890 的 param_3 读 —— 但实测 p3 是「大对象」（+0x4D8/+0x9F8），
    //   没有 +0xCC 也没有 key 字段 ⇒ 永远读不到。
    //   而 A 点探针的 r15 = [候选数组] = 真正的 tech 对象，
    //   +0xCC = id，key 在 +0x20 或 +0x360（两套布局都在试）。
    //
    // 【优先级】keyB（+0x20）优先 —— A 点实测 194 条全部是 +0x20 成功、+0x360 全 null。
    //
    if (tech && s_mapLogged < 300) {
        const bool useB = (kpB != nullptr);
        const bool useA = (!useB && kpA != nullptr);
        if (useB || useA) {
            int32_t tid = -1;
            bool haveId = false;
            if (SafeReadable((uint8_t*)tech + 0xCC, 4)) {
                tid = *(volatile int32_t*)((uint8_t*)tech + 0xCC);
                haveId = true;
            }
            const char* k = useB ? kpB : kpA;
            // 去重：用 (id, key) 二者之一都行；这里用 key 的哈希（id 可能不可读）
            if (haveId && !MapSeen(tid)) {
                MapRemember(tid);
                InterlockedIncrement(&s_mapLogged);
                Log("[map] id=%-5d key=%s", (int)tid, k);
            } else if (!haveId && s_mapLogged < 50) {
                // id 读不到时只记少量，帮助判断 +0xCC 是否漂移
                static volatile LONG s_mapNoId = 0;
                if (InterlockedIncrement(&s_mapNoId) <= 10)
                    Log("[map] id=<unreadable> key=%s tech=%p", k, tech);
            }
        }
    }

    Log("[selB] n=%ld i=%d tech=%p raw=%lld rsp16=%llu "
        "| A(+360): sz=%llu cap=%llu key=%s "
        "| B(+020): sz=%llu cap=%llu key=%s",
        (long)n, idx, tech, (long long)raw, (unsigned long long)rsp16,
        (unsigned long long)szA, (unsigned long long)capA, kpA ? kpA : "(null)",
        (unsigned long long)szB, (unsigned long long)capB, kpB ? kpB : "(null)");
}

// trampoline：
//   7 push (rsp%16: 0→8) → sub 0x28 (=0) → call 记录 → add 0x28
//   → pop×7（不改 flags）→ 补执行 3 条原指令（连续，flags 链完整）→ 绝对跳回
extern "C" __attribute__((naked)) void AR_SelBTramp();
__asm__(
    ".text\n"
    ".globl AR_SelBTramp\n"
    "AR_SelBTramp:\n"
    "  push %rax\n"
    "  push %rcx\n"
    "  push %rdx\n"
    "  push %r8\n"
    "  push %r9\n"
    "  push %r10\n"
    "  push %r11\n"
    "  sub $0x28, %rsp\n"
    // 参数：rcx=tech(r15) rdx=raw([rbp+0x1D8]) r8d=i(edi) r9=rsp
    "  mov %r15, %rcx\n"
    "  mov 0x1d8(%rbp), %rdx\n"
    "  mov %edi, %r8d\n"
    "  mov %rsp, %r9\n"
    "  call AR_SelBLog\n"
    "  add $0x28, %rsp\n"
    "  pop %r11\n"
    "  pop %r10\n"
    "  pop %r9\n"
    "  pop %r8\n"
    "  pop %rdx\n"
    "  pop %rcx\n"
    "  pop %rax\n"
    // ★ 补执行 3 条原指令（严格连续，无 call，flags 链完整）
    "  mov $0x8000, %ecx\n"
    "  cmp %rcx, 0x1d8(%rbp)\n"
    "  cmovge 0x1d8(%rbp), %rcx\n"
    // ★ 绝对跳回 0x820E5F
    "  mov g_selBBackAddr(%rip), %rax\n"
    "  jmp *%rax\n"
);

// 定位：Daily Tick 字符串 → 调用链 → len=1138 的函数 → 扫 20 字节模式
static bool LocateAndPatchSelB(uint64_t base) {
    // 直接在已知函数范围内按 20 字节模式搜（模式全 exe 唯一，不必先解析调用链）
    static const uint8_t kPat[20] = {
        0xB9,0x00,0x80,0x00,0x00,
        0x48,0x39,0x8D,0xD8,0x01,0x00,0x00,
        0x48,0x0F,0x4D,0x8D,0xD8,0x01,0x00,0x00
    };
    // 在 0x820B30..0x820B30+1138 内搜
    const uint32_t fnLo = 0x820B30, fnLen = 1138;
    uint32_t hit = 0; int nHit = 0;
    for (uint32_t off = 0; off + 20 <= fnLen; ++off) {
        if (memcmp((uint8_t*)(uintptr_t)(base + fnLo + off), kPat, 20) == 0) {
            hit = fnLo + off; ++nHit;
        }
    }
    if (nHit != 1) {
        Log("[selB] pattern hit %d times (expect 1) -> skip", nHit);
        return false;
    }
    Log("[selB] patch point at RVA 0x%X (unique)", hit);

    g_selBPatch = (uint8_t*)(uintptr_t)(base + hit);
    g_selBBack  = base + 0x820E5F;

    // 校验 + 保存原字节
    if (!SafeReadable(g_selBPatch, 20)) {
        Log("[selB] patch point unreadable -> skip");
        return false;
    }
    if (memcmp(g_selBPatch, kPat, 20) != 0) {
        Log("[selB] byte mismatch -> skip");
        return false;
    }
    memcpy(g_selBOrig, g_selBPatch, 20);

    // trampoline：★ 直接用 DLL 内的 AR_SelBTramp（绝对跳转可达，不需要拷贝）
    //   C890/SEL 探针的做法是拷贝 15/20 字节原指令到 VirtualAlloc 再跳回；
    //   这里不同：patch 点被「完全替换」为跳转，原 3 条指令在 trampoline 里
    //   手工补执行（见 AR_SelBTramp 末尾），所以不需要拷贝原字节。
    void* t = (void*)(uintptr_t)&AR_SelBTramp;

    // 跳回地址
    g_selBBackAddr = g_selBBack;

    // 20 字节 patch：MakeAbsJmp(15) + NOP×5
    DWORD oldProt = 0;
    if (!VirtualProtect(g_selBPatch, 20, PAGE_EXECUTE_READWRITE, &oldProt)) {
        Log("[selB] VirtualProtect failed -> skip");
        return false;
    }
    {
        uint8_t buf[20];
        uint64_t dst = (uint64_t)(uintptr_t)t;
        buf[0] = 0x48; buf[1] = 0xB8;
        memcpy(buf + 2, &dst, 8);
        buf[10] = 0xFF; buf[11] = 0xE0;
        memset(buf + 12, 0x90, 8);
        memcpy(g_selBPatch, buf, 20);
    }
    VirtualProtect(g_selBPatch, 20, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), g_selBPatch, 20);

    InterlockedExchange(&s_selBInstalled, 1);
    Log("[selB] probe INSTALLED at 0x%llX tramp=0x%llX back=0x%llX",
        (unsigned long long)(uintptr_t)g_selBPatch,
        (unsigned long long)(uintptr_t)t,
        (unsigned long long)g_selBBack);
    return true;
}


// 候选数量合理性标记（678 个科技，候选最多几十；>100 基本是读错）
static const char* CntMark(int32_t v) {
    if (v < 0) return "?";
    if (v <= 100) return "ok";
    return "BAD";
}


#if AR_ENABLE_PROBES  // C890 探针（默认关闭）
extern "C" void C890Log(void* p1, void* p2, void* p3, void* entryRsp) {
    LONG seq = InterlockedIncrement(&s_c890Seq);
    InterlockedIncrement(&s_c890Count);

    // country = p1 + 0x10（用 SafeReadable 包裹，p1 可能为 null）
    void* country = nullptr;
    if (p1 && SafeReadable(p1, 0x18)) {
        country = *(void* volatile*)((uint8_t*)p1 + 0x10);
    }

    const uint64_t p3v = (uint64_t)(uintptr_t)p3;
    bool isNewP3 = C890TrackUnique(s_c890P3Set, &s_c890UniqP3, 64, p3v);
    C890TrackUnique(s_c890CountrySet, &s_c890UniqCountry, 32, (uint64_t)(uintptr_t)country);

    LONG logged = InterlockedCompareExchange(&s_c890Logged, 0, 0);

    // 日志策略：前 500 次全记；之后只在新 param_3 或每 100 次时记一条
    bool shouldLog = (logged < 500);
    if (!shouldLog && isNewP3) shouldLog = true;
    if (!shouldLog && (seq % 100) == 0) shouldLog = true;
    if (!shouldLog) return;

    InterlockedIncrement(&s_c890Logged);
    s_c890LastP3 = p3v;
    Log("[c890] seq=%ld tick=%llu p1=%p p2=%p p3=%p country=%p",
        (long)seq, (unsigned long long)GetTickCount64(), p1, p2, p3, country);

    // ==========================================================================
    // [alt] 三领域备选列表（2026-11-16 v3）
    // ==========================================================================
    //
    // 【结构（UI 0xFCBD30 + hookA 0x81C850 两个独立函数交叉验证，逐字节核实）】
    //   slotmgr = country + 0x1620
    //   slot(area) = slotmgr + (area + 11) * 0x18
    //     slot + 0x08 = 数组指针
    //     slot + 0x14 = count（int32）
    //
    //   推导：
    //     area=0 (物理): slotmgr+0x108, array@+0x110, count@+0x11C
    //     area=1 (社会): slotmgr+0x120, array@+0x128, count@+0x134
    //     area=2 (工程): slotmgr+0x138, array@+0x140, count@+0x14C
    //
    //   hookA 里 CMP dword [RDI+RCX*8+0x11C], 1 与 UI 的
    //   ADD RAX,0x1620 / ADD RCX,0x0B / LEA RCX,[RCX+RCX*2] / LEA R12,[RAX+RCX*8]
    //   是同一个算式 ⇒ 结构置信度高。
    //
    // 【期望】用户看到物理 4 张卡 → area=0 cnt=4，area=1/2 cnt=0（研究中的槽是空的）
    //
    if (s_cntSampled < 400 && country && SafeReadable(country, 0x1620 + 0x160)) {
        uint8_t* sm = (uint8_t*)country + 0x1620;
        const uint64_t nowMs = GetTickCount64();
        bool due = (nowMs - s_cntLastTickMs >= 500);
        bool anyChange = false;
        int  cnts[3] = {-1, -1, -1};

        for (int area = 0; area < 3; ++area) {
            uint8_t* slot = sm + (size_t)(area + 11) * 0x18;
            if (!SafeReadable(slot, 0x18)) continue;
            cnts[area] = *(volatile int32_t*)(slot + 0x14);
            if (cnts[area] != s_lastAlt[area]) {
                anyChange = true;
                s_lastAlt[area] = cnts[area];
            }
        }

        if (due || anyChange) {
            s_cntLastTickMs = nowMs;
            InterlockedIncrement(&s_cntSampled);
            Log("[alt]%s seq=%ld tick=%llu phy=%d soc=%d eng=%d (expect: 玩家看到的卡数)",
                anyChange ? " CHANGED" : "",
                (long)seq, (unsigned long long)nowMs,
                cnts[0], cnts[1], cnts[2]);

            // dump 每个槽的数组内容（步长 8；先按「8 字节原始值」打印）
            for (int area = 0; area < 3; ++area) {
                if (cnts[area] < 1 || cnts[area] > 16) continue;
                uint8_t* slot = sm + (size_t)(area + 11) * 0x18;
                void* arr = *(void* volatile*)(slot + 0x08);
                if (!arr || !SafeReadable(arr, (size_t)cnts[area] * 8)) continue;

                char buf[512]; int off = 0;
                off += snprintf(buf + off, sizeof(buf) - (size_t)off, "    area=%d raw:", area);
                for (int i = 0; i < cnts[area] && off < (int)sizeof(buf) - 32; ++i) {
                    uint64_t v = *(uint64_t volatile*)((uint8_t*)arr + (size_t)i * 8);
                    off += snprintf(buf + off, sizeof(buf) - (size_t)off, " %llX",
                                    (unsigned long long)v);
                }
                Log("[alt]%s", buf);

                // 若元素像指针（高位非 0 且 8 字节对齐），尝试读它的 tech id + key
                for (int i = 0; i < cnts[area] && i < 8; ++i) {
                    uint64_t v = *(uint64_t volatile*)((uint8_t*)arr + (size_t)i * 8);
                    if (v < 0x10000 || (v & 7) != 0) continue;      // 不像指针 → 跳过
                    void* tech = (void*)(uintptr_t)v;
                    if (!SafeReadable(tech, 0x1000)) continue;
                    int32_t tid = -1;
                    if (SafeReadable((uint8_t*)tech + 0xCC, 4))
                        tid = *(volatile int32_t*)((uint8_t*)tech + 0xCC);
                    std::string key;
                    bool hk = ReadTechKey(tech, &key);
                    if (tid >= 0 || hk) {
                        Log("[alt]     area=%d [%d] ptr=%p id=%d key=%s",
                            area, i, tech, (int)tid, hk ? key.c_str() : "<unreadable>");
                    }
                }
            }
        }
    }
}

// 由安装代码在结束时打印统计
static void C890LogSummary() {
    Log("[c890] === summary: total=%ld logged=%ld uniq_p3=%ld uniq_country=%ld ===",
        (long)InterlockedCompareExchange(&s_c890Count, 0, 0),
        (long)InterlockedCompareExchange(&s_c890Logged, 0, 0),
        (long)InterlockedCompareExchange(&s_c890UniqP3, 0, 0),
        (long)InterlockedCompareExchange(&s_c890UniqCountry, 0, 0));
}

// 入口桩：保存全部易失寄存器 → 调 C890Log → 恢复 → 跳 trampoline
extern "C" __attribute__((naked)) void C890Entry();

__asm__(
    ".text\n"
    ".globl C890Entry\n"
    "C890Entry:\n"
    // ============================================================
    // 进入条件：被原 C890 的 6 个调用者之一 call 进来
    //   RCX = param_1 (slotmgr)   RDX = param_2 (&weight_out)   R8 = param_3 (候选卡)
    //   rsp % 16 == 8（call 压入了 8 字节返回地址）
    //
    // 栈对齐推演（务必别改，改之前重算）：
    //   入口 rsp%16 = 8
    //   7 次 push = 56 字节 → (8-56) mod 16 = 0  ⇒ 已经对齐，不需要 sub $8
    //   （若改成 push 6 个或 8 个，必须重新计算）
    //
    // 保存全部易失寄存器：rax rcx rdx r8 r9 r10 r11
    // ============================================================
    "  push %rax\n"
    "  push %rcx\n"
    "  push %rdx\n"
    "  push %r8\n"
    "  push %r9\n"
    "  push %r10\n"
    "  push %r11\n"
    // 栈布局（push 完 7 个后）：
    //   [rsp+0]=r11 [rsp+8]=r10 [rsp+16]=r9 [rsp+24]=r8
    //   [rsp+32]=rdx [rsp+40]=rcx [rsp+48]=rax
    // C890Log(p1=rcx, p2=rdx, p3=r8) —— Win64: RCX, RDX, R8
    // ★★★ 2026-11-16 崩溃修复：Win64 shadow space 覆盖 ★★★
    //   7 push 后 rsp=R-56，call C890Log 时被调用者的 shadow space
    //   是 [R-64, R-32)，正好盖住 r11@R-56 / r10@R-48 / r9@R-40 / r8@R-32。
    //   C890Log 序言把参数 spill 进 shadow → 覆盖保存的 tech 指针 → pop 拿垃圾 → 崩。
    //   ⇒ 必须先 sub $0x20 让出自己的 shadow space。
    //   (8 - 56 - 32) % 16 = 0  ✓ 仍然 ABI 对齐
    "  sub $0x20, %rsp\n"
    "  mov 56(%rsp), %r8\n"       // param_3  [R-32]
    "  mov 64(%rsp), %rdx\n"      // param_2  [R-24]
    "  mov 72(%rsp), %rcx\n"      // param_1  [R-16]
    "  lea 88(%rsp), %r9\n"       // entryRsp [R] = 返回地址槽
    "  call C890Log\n"
    "  add $0x20, %rsp\n"
    // 恢复（逆序）
    "  pop %r11\n"
    "  pop %r10\n"
    "  pop %r9\n"
    "  pop %r8\n"
    "  pop %rdx\n"
    "  pop %rcx\n"
    "  pop %rax\n"
    // 跳 trampoline：执行原 3 条 shadow-store，再 jmp 回 0x81E7EF
    "  jmp *g_c890Tramp(%rip)\n"
);
#endif  // AR_ENABLE_PROBES（C890 探针）
#endif  // 常驻块结束



static void ARLogStartInner(void* tech, uint64_t caller, unsigned param3) {
    LONG n = InterlockedIncrement(&g_startSeq);

    // 调用者识别：caller 是 hookA 返回地址，即「调用者体内 call 后的下一条指令」。
    // 减去 5（call rel32 的长度）就得到 call 指令本身的地址。
    // 用它对上我们已知的 6 个调用点，即可知道这次是「自动科研」还是 give_technology。
    // 注意：这里【只记录不筛选】—— 先让用户跑出真实分布再定白名单。
    const uint64_t callSite = caller ? (caller - 5) : 0;

    std::string key;
    bool haveKey = ReadTechKey(tech, &key);

    // ============ 玩家判据（2026-11-15 重做） ============
    //
    // 【旧实现有竞态 bug】IsPlayerContext() 读全局 g_arSlot：
    //   g_arSlot 在每次 hookA 时被覆盖，而 obj(=param_2) 是【当次】的 tech 对象。
    //   两者不配套 → 同一 tech 在不同时刻被标成不同 PLAYER/ai。
    //
    // 【本次改为「当次链路」】slot → +0x10 → country → +0x314C
    //   并且把三层全部写进日志，用真机数据验证每一层：
    //     slot     = g_arSlot（hookA param_1，当次）
    //     country  = *(slot + 0x10)          ← 第 2 层，未验证
    //     isai_val = *(country + 0x314C)     ← 第 3 层，未验证
    //
    // 只要这三层对得上 c890 日志里的 p1/country，链路才算证实。
    void* slot    = g_arSlot;
    void* country = CountryFromSlot(slot);
    int32_t isaiVal = -1;
    if (country && SafeReadable((uint8_t*)country + 0x314C, 4))
        isaiVal = *(volatile int32_t*)((uint8_t*)country + 0x314C);
    const bool player = IsCountryPlayer(country);

    if (haveKey) {
        RingPush("[%9llu] [hookA] tech=%s  p3=%u  caller=0x%llX  site=0x%llX  (%s-by-current-slot)  obj=%p  slot=%p  country=%p  isai=%d",
                 (unsigned long long)GetTickCount64(), key.c_str(), param3,
                 (unsigned long long)caller, (unsigned long long)callSite,
                 player ? "PLAYER" : "ai", tech, slot, country, (int)isaiVal);
    } else {
        RingPush("[%9llu] [hookA] tech=<unreadable>  p3=%u  caller=0x%llX  site=0x%llX  (%s-by-current-slot)  obj=%p  slot=%p  country=%p  isai=%d",
                 (unsigned long long)GetTickCount64(), param3,
                 (unsigned long long)caller, (unsigned long long)callSite,
                 player ? "PLAYER" : "ai", tech, slot, country, (int)isaiVal);
        // 2026-11-12：tech key 从未读出过，改为一次性完整身份诊断。
        // 只在前 5 次 + 形态变化时 dump（最多 10 次），避免 436 次 × 多 dump 撑爆日志。
        MaybeDumpTechIdentity(tech);
        return;
    }

    // 附带读出「当前候选卡」做交叉对照（只读）。
    // country+0x31B0/+0x31BC 是玩家 UI 上的 2-3 张卡（FINDINGS §2.3）。
    // 候选卡里只有 tech id（整数），不是 key —— 这里只记 id 与数量，
    // 不假装能映射成 key（那条链 §8.3 未验证）。
    if (!player) return;
    // 用【当次】country（上面已算好，不用全局）
    if (!country) return;

    std::vector<CandidateCard> cards;
    if (ReadCandidateCards(country, &cards)) {
        char buf[512];
        int pos = 0;
        pos += snprintf(buf + pos, sizeof(buf) - pos,
                        "        candidate-cards n=%zu:", cards.size());
        for (size_t i = 0; i < cards.size() && pos < (int)sizeof(buf) - 32; ++i)
            pos += snprintf(buf + pos, sizeof(buf) - pos, " id=%d", cards[i].techId);
        Log("%s", buf);
    } else {
        Log("        candidate-cards: unreadable (country=%p)", country);
    }
    (void)n;
}

// 同样是裸汇编（ARAfter2）直接 call，异常不许穿出去
extern "C" void ARLogStart(void* tech, uint64_t caller, unsigned param3) {
    try {
        ARLogStartInner(tech, caller, param3);
    } catch (...) {
        Log("[ERR] ARLogStart: exception swallowed");
    }
}

extern "C" __attribute__((naked)) void AREntryA();
__asm__(
    ".text\n"
    ".globl AREntryA\n"
    "AREntryA:\n"
    "  mov %rax, g_arRetSlot(%rip)\n"
    "  mov %rcx, g_arSlot(%rip)\n"          // param_1 = slotmgr (country+0x1620)
    "  mov %rdx, g_ar2Tech(%rip)\n"         // param_2 = 要开始研究的科技对象
    "  mov %r8b, g_ar2Param3(%rip)\n"       // param_3 低 8 位
    "  mov (%rsp), %rax\n"                  // 真实返回地址
    "  mov %rax, g_ar2Caller(%rip)\n"       // ★ 必须在 lea 之前存，否则存成 ARAfter2
    "  cmpb $0, g_ar2DoPatch(%rip)\n"       // dryrun?
    "  je 1f\n"                              // 是 → 不改写，直接转发
    "  lea ARAfter2(%rip), %rax\n"
    "  mov %rax, (%rsp)\n"                  // 改写 → ARAfter2
    "1:\n"
    "  mov g_arRetSlot(%rip), %rax\n"
    "  jmp *g_ar2Tramp(%rip)\n"             // 原函数 → ret → ARAfter2(或真实调用者)
);

// ARAfter: 原函数已跑完, out 已填好, RSP = 原调用者视角
extern "C" __attribute__((naked)) void ARAfter();
__asm__(
    ".text\n"
    ".globl ARAfter\n"
    "ARAfter:\n"
    "  push %rax\n"
    "  push %rcx\n"
    "  push %rdx\n"
    "  push %r8\n"
    "  push %r9\n"
    "  push %r10\n"
    "  push %r11\n"
    // 实测（_aligntest）：入口 rsp%16==0，7 push 后==8，
    // sub $0x30 后仍==8 → call 前违规；sub $0x38 后==0 → 合法。
    "  sub $0x38, %rsp\n"
    "  mov g_curOut(%rip), %rcx\n"       // arg1 = out (入口时存的 RDX)
    "  xor %edx, %edx\n"
    "  call ARProcess\n"                 // ARProcess(out)
    "  add $0x38, %rsp\n"
    "  pop %r11\n"
    "  pop %r10\n"
    "  pop %r9\n"
    "  pop %r8\n"
    "  pop %rdx\n"
    "  pop %rcx\n"
    "  pop %rax\n"
    "  jmp *g_retAddr(%rip)\n"
);

// ARProcess: 在主 hook（FUN_140425550）返回后运行。
//
// ============ FINDINGS §3.2 的核心结论（决定了本函数的职责） ============
//   `out` 只是「研究完成」消息的插值参数（FUN_14031E010 按键名 "TECHNOLOGY"
//   写进消息参数表）。真正决定研究哪个科技的是 `plVar12[0x6B] = param_2`。
//   ⇒ **改写 out 完全不会改变研究选择**（FINDINGS §8.2 明确要求废弃）。
//
//   所以本函数在 take 模式下【不做任何接管】——它的唯一价值是
//   在 observe 模式下记录「游戏自己选了什么」，这是验证 hook 没坏的抓手。
//   真正的 take 接管点在 hookA（改写 param_2），不在主 hook。
//
// ============ take 模式为什么还没接管 ============
//   按 FINDINGS §8.3，以下关键环节仍是「未验证」：
//     - status 与 country 的偏移关系（候选卡 tech id → 内部 key 需要它）
//     - country+0x31BC 的实际上限量级
//   t2 阶段已经证明：配置语义（PickBest）是完备且自测覆盖的，缺的是
//   「运行时把候选卡映射成科技 key」这条链。这条链没验证就不许写内存。
static bool IsPlayerContext();

// 输出 hookA 挂起的「本次开始了哪个科技」。
// 放在这里而不是 ARAfter2 里，是因为主 hook 是普通 call 进入，
// 栈环境完全正常，可以安全调用 C 函数（ARAfter2 被 ret 跳入，不能）。
static void FlushPendingStart() {
    if (InterlockedExchange((volatile LONG*)&g_pendingStartValid, 0) == 0) return;
    void* tech = (void*)InterlockedExchangePointer((void* volatile*)&g_pendingStartTech, nullptr);
    // 2026-11-12 修复：此前这里硬编码传 (0,0)，导致日志永远 caller=0x0 site=0x0。
    // 现在读 ARAfter2 转存的真实值。
    uint64_t caller = (uint64_t)InterlockedExchange64((volatile LONG64*)&g_pendingCaller, 0);
    uint32_t p3     = (uint32_t)InterlockedExchange((volatile LONG*)&g_pendingParam3, 0);
    if (!tech) return;
    try {
        ARLogStartInner(tech, caller, p3);
    } catch (...) {
        Log("[ERR] FlushPendingStart: exception swallowed");
    }
}

// ============================================================================
// ★★ 2026-11-20：ARProcess 日志大幅降噪 ★★
// ============================================================================
//
// 【实测数据】用户一份日志 1213 行：
//   ARProcess 相关   807 行  (66%)
//   [PICK]/[TAKE]      12 行  ( 1%)  ← 真正有用的
//
// 【根因】主 hook 0x428EE0 已确认是「科技显示名构造器」，
//   每次 UI 刷新都调，与选卡无关。每次 3 行纯噪声。
//
// 【新策略】
//   使用版（PROBES=0）：完全不打日志（但 hook 与功能保留）
//   维护版（PROBES=1）：单行 + 限流（前 50 + 每 100）
//
// 【同时清理的过时文案】
//   旧：take: candidate-card -> tech-key mapping still UNVERIFIED (FINDINGS 8.3)
//       → tech-key 映射早已验证，TkReadKey 正在用
//   旧：take: decision point is hook-a (param_2), not here
//       → 决策点是 0x6F334E，不是 hook-a，也不是这里
//
static void ARProcessInner(void* out) {
    PollConfig();          // 配置热重载（每次都要，不能省）
    FlushPendingStart();   // 补输出 hookA 挂起的记录

#if AR_BUILD_WITH_PROBES
    // 维护版：单行 + 限流
    if (out) {
        static volatile LONG seq = 0;
        const LONG n = InterlockedIncrement(&seq);
        if (n <= 50 || (n % 100) == 0) {
            std::string picked;
            if (ReadStdString(out, &picked)) {
                Log("[disp] n=%ld name=%s", (long)n, picked.c_str());
            } else {
                Log("[disp] n=%ld name=<unreadable> out=%p", (long)n, out);
            }
        }
    }
#else
    // 使用版：完全静默（不产生任何日志）
    (void)out;
#endif
}

// ------------------------------------------------------------------
// 崩溃防护：本函数由裸汇编 ARAfter 直接 call，一旦有 C++ 异常穿过这层
// 栈帧（栈上没有 unwind 信息），游戏会当场崩掉。
// 配置解析会分配内存（std::string / unordered_map），bad_alloc 是真实可能的，
// 所以这里必须把所有异常挡在函数内部 —— 出任何事都退回游戏原选择。
// ------------------------------------------------------------------
extern "C" void ARProcess(void* out) {
    try {
        ARProcessInner(out);
    } catch (...) {
        Log("[ERR] ARProcess: exception swallowed -> keeping game's original pick");
    }
}

// （旧 IsPlayerContext 定义已删除 —— 2026-11-15 移到文件前部并改为 IsCountryPlayer(country)）


__attribute__((naked)) static void AREntry() {
    __asm__ __volatile__(
        // 返回地址改写模式:
        //   [rsp] = 真实返回地址 → 存槽, 换成 ARAfter
        //   jmp trampoline → 原函数 → ret 到 ARAfter → 后处理 → jmp 真实返回
        "mov %rax, g_arRetSlot(%rip)\n\t"      // rax 备用
        "mov (%rsp), %rax\n\t"                 // 真实返回地址
        "mov %rax, g_retAddr(%rip)\n\t"
        "mov %rcx, g_curObj(%rip)\n\t"         // param_1(上下文) 
        "mov %rdx, g_curOut(%rip)\n\t"         // out
        "lea ARAfter(%rip), %rax\n\t"
        "mov %rax, (%rsp)\n\t"                 // 替换返回地址
        "mov g_arRetSlot(%rip), %rax\n\t"      // 恢复 rax
        "jmp *g_arTramp(%rip)\n\t"             // → 原函数
    );
}

static void ARLogInner(void* techStatus, void* out, int decided,
                       const char* name, long long w) {
    LONG n = InterlockedIncrement(&g_seq);
    PollConfig();

    // ============ 参数语义（FINDINGS §1.1，寄存器级已证实） ============
    //   `techStatus` 是主 hook(FUN_140425550) 的 arg1
    //     = hookA 的 param_2 = **科技状态对象**，不是 country！
    //     证据：0x81A924 MOV RSI,RDX（RSI 唯一赋值）+ 0x81ADD2 MOV RCX,RSI
    //
    //   ⇒ 在它上面读 +0x314C 是【错的】（前任的致命假设）：
    //     全 exe 扫描「同一基址寄存器同时触及 +0x9B8 与 +0x314C」= 0 命中，
    //     说明这是两个不同对象。读到恒 0 是必然，不是"观察到 AI"。
    //
    //   ⇒ 在它上面读 +0x9B8/+0x9C4 语义是 technology_swap 交换技术表，
    //     **不是 2-3 张候选卡**（候选卡在 country+0x31B0/+0x31BC）。
    //
    // 玩家判据必须走 hookA 记录的 slotmgr → +0x10 → country → +0x314C。
    const bool player = IsPlayerContext();

    // 读科技状态对象上的「科技总表」（FINDINGS §2.2，已证实）：
    //   status + 0x978 = 科技对象指针数组
    //   status + 0x984 = 条数
    void*  techTable = nullptr;
    int32_t techCount = -1;
    if (SafeReadable((uint8_t*)techStatus + 0x978, 8))
        techTable = *(void* volatile*)((uint8_t*)techStatus + 0x978);
    if (SafeReadable((uint8_t*)techStatus + 0x984, 4))
        techCount = *(volatile int32_t*)((uint8_t*)techStatus + 0x984);

    Log("[%9llu] #%ld %s techStatus=%p out=%p techTable=%p techCount=%d",
        (unsigned long long)GetTickCount64(), n,
        player ? "PLAYER" : "ai    ", techStatus, out, techTable, techCount);

    // out 只是「研究完成」消息的插值参数（FINDINGS §3.2）。
    // 记录它仅用于观察，绝不据此判断"选了哪个科技"。
    {
        std::string shown;
        if (ReadStdString(out, &shown))
            Log("        out(display only, NOT the choice): %s", shown.c_str());
        else
            Log("        out(display only, NOT the choice): <unreadable>");
    }
    (void)decided; (void)name; (void)w;
}

// ARLog 由裸汇编 call 进入，异常不许穿出去（否则游戏崩）
extern "C" __fastcall void ARLog(void* country, void* out, int decided,
                                const char* name, long long w) {
    try {
        ARLogInner(country, out, decided, name, w);
    } catch (...) {
        Log("[ERR] ARLog: exception swallowed");
    }
}

// ================= 版本闸门 + 原子安装 =================
// 发布到 GitHub 后，用户版本可能不是 4.5.2 build 9776。硬编码 RVA 指错地方
// 轻则失效重则崩游戏，所以这里的纪律是：
//   1. 先跑完整闸门检查（版本锚 → 地址 → 函数指纹），任一不过就一个 hook 都不装
//   2. 检查全过后再统一安装，任何一步写入失败 → 把已写的字节全部还原
//
// 状态位通过 AutoResearchGetState() 导出，网页/脚本可以查"DLL 就绪没有"。
static argate::State g_state = argate::State::NotChecked;
static argate::Report g_report;
static std::vector<argate::Patch> g_appliedPlan;   // 已改写的补丁（回滚用）

extern "C" {
// 供外部查询：0=not-checked 1=version-rejected 2=address-rejected
//             3=fingerprint-rejected 4=install-failed 5=unverified 6=fully-installed
__declspec(dllexport) int AutoResearchGetState() { return (int)g_state; }
// 供外部查询：返回状态名的静态字符串（不需要释放）
__declspec(dllexport) const char* AutoResearchGetStateName() {
    return argate::StateName(g_state);
}
// 供外部查询：1 = 已就绪（hook 装上且配置可读）
__declspec(dllexport) int AutoResearchIsReady() {
    return argate::IsUsable(g_state) ? 1 : 0;
}
// 供外部查询：本 DLL 支持的版本标识
__declspec(dllexport) const char* AutoResearchSupportedVersion() {
    return arver::kSupportedVersionTag;
}
__declspec(dllexport) const char* AutoResearchSupportedBuildId() {
    return arver::kSupportedBuildId;
}
__declspec(dllexport) const char* AutoResearchSupportedSha256() {
    return arver::kSupportedSha256;
}
}

// 找游戏 exe 在磁盘上的路径（= 模块文件名）
static std::string GameExePath() {
    char path[MAX_PATH];
    DWORD n = GetModuleFileNameA(nullptr, path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return std::string();
    return std::string(path);
}

// 把检查报告写进日志。版本不符与序言不符要分开说清，排查方向完全不同。
static void LogReport(const argate::Report& rep) {
    Log("[gate] ---- version gate report ----");
    Log("[gate] state  : %s", argate::StateName(rep.state));
    Log("[gate] anchor : %s", argate::AnchorName(rep.anchor));
    Log("[gate] expected: %s (build %s)", arver::kSupportedVersionTag,
        arver::kSupportedBuildId);
    Log("[gate] expected sha256: %s", arver::kSupportedSha256);
    Log("[gate] actual   sha256: %s",
        rep.actualSha256.empty() ? "<unavailable>" : rep.actualSha256.c_str());
    Log("[gate] actual   build : %s",
        rep.actualBuildId.empty() ? "<not found>" : rep.actualBuildId.c_str());
    for (size_t i = 0; i < rep.targets.size(); ++i) {
        const argate::TargetCheck& t = rep.targets[i];
        if (t.Ok()) {
            Log("[gate]   ok    %s rva=0x%X (fnLen=%u)",
                t.fnName, t.rva, t.actualFuncLen);
        } else {
            Log("[gate]   FAIL  %s rva=0x%X -> %s", t.fnName, t.rva, t.detail.c_str());
        }
    }
    for (size_t i = 0; i < rep.errors.size(); ++i)
        Log("[gate] %s", rep.errors[i].c_str());
    Log("[gate] ------------------------------");
}

// 写一段补丁：先改成可写，写入，再恢复保护属性
static bool WritePatch(const argate::Patch& p, const uint8_t* src, DWORD* savedProtect,
                       bool* didProtect) {
    uint8_t* target = (uint8_t*)(g_base + p.rva);
    DWORD old = 0;
    if (!VirtualProtect(target, arver::kPatchLen, PAGE_EXECUTE_READWRITE, &old))
        return false;
    memcpy(target, src, arver::kPatchLen);
    VirtualProtect(target, arver::kPatchLen, old, &old);
    FlushInstructionCache(GetCurrentProcess(), target, arver::kPatchLen);
    if (savedProtect) *savedProtect = old;
    if (didProtect) *didProtect = true;
    return true;
}

// 分配 trampoline：原 15 字节 + jmp 回 target+15
static uint8_t* AllocTrampoline(const uint8_t* original, uint8_t* target) {
    uint8_t* t = (uint8_t*)VirtualAlloc(nullptr, 15 + 16, MEM_COMMIT | MEM_RESERVE,
                                       PAGE_EXECUTE_READWRITE);
    if (!t) return nullptr;
    memcpy(t, original, 15);
    t[15] = 0x48;
    t[16] = 0xB8;
    uint64_t back = (uint64_t)(target + 15);
    memcpy(t + 17, &back, 8);
    t[25] = 0xFF;
    t[26] = 0xE0;
    return t;
}

// =====================================================================
// 地址解析 + 原子安装
// =====================================================================
//
// 解析优先级（captain 定的方案）：
//   1. 锚点解析（字符串锚点 + 调用链）—— 跨版本可用
//   2. SHA256/版本精确匹配             —— 兜底，保证在自己版本上一定能用
//
// 安装纪律（无论如何都不许半挂）：
//   - 必需组 = {主 hook, hookA}：这两个是同一个功能的两半
//       hookA 提供"是不是玩家"的判据，主 hook 提供候选池与选择
//       只装一个 → 看起来在工作但判据失效，比不装更糟
//     → 要么两个都装，要么一个都不装
//   - 可选组 = {str-ctor, str-dtor}：只影响能否改写 out。缺了不影响 observe。
//   - 任何一步写入失败 → 把已写的字节全部还原
//
// 注意：锚点解析成功 ≠ 可以安装。hook 会改写函数序言，还依赖调用约定和
// 栈布局。所以最后必须过"函数长度 + 序言字节与参考值一致"这一关；
// 不过就拒绝，要求用 gen_version_h.js 为新版本重新生成指纹。
// 前置声明：安装函数定义在 InstallAll 之后（避免函数内嵌套定义）
#if AR_ENABLE_PROBES
static bool InstallC890Probe(uint32_t c890Rva);
static bool InstallSelProbe(uint32_t selRva);
#endif
static bool LocateAndPatchSelB(uint64_t base);
static bool InstallTakeover(uint64_t base);
static void RemoveTakeover();
#if AR_ENABLE_RP_PROBE
static bool InstallResearchProbe(uint64_t base);
static bool InstallTakeoverV2(uint64_t base);
static bool InstallPlayerPathProbe(uint64_t base);
static void RemoveTakeoverV2();
static void RemoveResearchProbe();
#endif

static bool InstallAll() {
    const std::string exe = GameExePath();
    HMODULE mod = GetModuleHandleA(nullptr);

    // ---------- 阶段 1：锚点解析（不做任何改写） ----------
    Log("[resolve] ---- anchor-based address resolution ----");
    arresolve::Win32AnchorImage aimg;
    arresolve::Resolver resolver;
    bool anchorParsed = false;
    argate::ResolveVerdict verdict = argate::ResolveVerdict::Failed;

    if (aimg.Init(exe, (uint64_t)mod)) {
        resolver.img = &aimg;
        anchorParsed = resolver.Run();
        // 把解析报告逐行写进日志（出问题时能一眼看出是没找到还是找到了但装不上）
        std::string rep = resolver.Report();
        size_t pos = 0;
        while (pos < rep.size()) {
            size_t nl = rep.find('\n', pos);
            std::string line = rep.substr(pos, (nl == std::string::npos) ? std::string::npos
                                                                         : nl - pos);
            if (!line.empty()) Log("[resolve] %s", line.c_str());
            if (nl == std::string::npos) break;
            pos = nl + 1;
        }
        verdict = (resolver.RequiredReady() && anchorParsed)
                      ? argate::ResolveVerdict::AnchorVerified
                      : argate::ResolveVerdict::AnchorUnverified;
    } else {
        Log("[resolve] cannot build a PE view of %s", exe.c_str());
    }

    // ---------- 阶段 2：锚点不成立 → 退到 SHA256/版本闸门 ----------
    std::vector<uint32_t> hookRvas;   // 要 hook 的（按 arver 顺序：main, hookA）
    if (!argate::VerdictInstallable(verdict)) {
        Log("[resolve] anchors did not produce a verified required set -> "
            "falling back to sha256/version gate");
        argate::Win32Image img;
        if (!img.Init(exe, mod)) {
            g_state = argate::State::AddressRejected;
            Log("[gate] FATAL: cannot parse PE image -> no hook installed");
            return false;
        }
        g_report = argate::Inspect(img);
        LogReport(g_report);
        if (argate::IsUsable(g_report.state)) {
            verdict = argate::ResolveVerdict::HashFallback;
        } else {
            g_state = g_report.state;
            Log("[gate] NOT INSTALLING. Neither anchor resolution nor the hash gate "
                "could confirm this game build.");
            Log("[gate] This DLL supports %s (build %s).",
                arver::kSupportedVersionTag, arver::kSupportedBuildId);
            Log("[gate] Your game was NOT modified. Nothing to undo.");
            return false;
        }
    }

    Log("[resolve] verdict = %s", argate::ResolveVerdictName(verdict));

    // ---------- 阶段 3：确定最终要用的 RVA ----------
    uint32_t mainRva = 0, hookARva = 0;
    if (verdict == argate::ResolveVerdict::AnchorVerified) {
        const arresolve::Addr* m = resolver.Get(arresolve::Role::MainHook);
        const arresolve::Addr* a = resolver.Get(arresolve::Role::HookA);
        mainRva  = m ? m->rva : 0;
        hookARva = a ? a->rva : 0;
        if (mainRva == 0 || hookARva == 0) {
            // 理论上不会发生（RequiredReady 已检查），但绝不冒险
            g_state = argate::State::AddressRejected;
            Log("[resolve] FATAL: required set claims ready but RVA is 0 -> abort");
            return false;
        }
    } else {
        // hash 兜底：用 arver 里写死的 RVA（那是这份 DLL 编译时的构建）
        for (size_t i = 0; i < arver::kTargetCount; ++i) {
            const arver::Target& t = arver::kTargets[i];
            if (t.rva == 0) continue;
            if ((int)i == (int)arresolve::Role::MainHook) mainRva = t.rva;
            else if ((int)i == (int)arresolve::Role::HookA) hookARva = t.rva;
        }
    }
    Log("[resolve] final: main=0x%X hookA=0x%X", mainRva, hookARva);

    // ---------- 阶段 4：必需组补丁计划（要么都装，要么都不装） ----------
    struct HookSpec {
        uint32_t rva;
        uint64_t dest;
        const char* name;
    };
    // 二分排障开关：定义 AR_ONLY_MAIN_HOOK 时只装主 hook、完全不 patch hookA。
    // 用途：区分「patch 机制/主 hook 有问题」与「hookA 有问题」。
#ifdef AR_ONLY_MAIN_HOOK
    const HookSpec required[] = {
        {mainRva,  (uint64_t)&AREntry,  "main-hook"},
    };
    const size_t requiredCount = 1;
    Log("[install] BISECT BUILD: only main-hook will be installed (hook-a untouched)");
#else
    const HookSpec required[] = {
        {mainRva,  (uint64_t)&AREntry,  "main-hook"},
        {hookARva, (uint64_t)&AREntryA, "hook-a"},
    };
    const size_t requiredCount = 2;
#endif
    std::vector<uint8_t> planBuf;
    std::vector<argate::Patch> plan;

    // 先全部读原始字节（读不到就整体放弃）
    for (size_t i = 0; i < requiredCount; ++i) {
        const HookSpec& hs = required[i];
        argate::Patch p;
        p.rva = hs.rva;
        p.fnName = hs.name;
        bool ok = aimg.Init(exe, (uint64_t)mod) &&
                  aimg.ReadBytes(hs.rva, p.original, arver::kPatchLen);
        if (!ok) {
            g_state = argate::State::AddressRejected;
            Log("[install] FATAL: cannot read prologue of %s (0x%X) from game memory",
                hs.name, hs.rva);
            return false;
        }
        argate::MakeAbsJmp(p.patched, hs.dest);
        plan.push_back(p);
    }

    // ---------- 阶段 5：逐条安装，失败即回滚 ----------
    std::vector<uint8_t*> tramps;
    g_appliedPlan.clear();
    bool failed = false;
    for (size_t i = 0; i < plan.size(); ++i) {
        const argate::Patch& p = plan[i];
        uint8_t* target = (uint8_t*)(g_base + p.rva);
        uint8_t* tr = AllocTrampoline(p.original, target);
        if (!tr) {
            Log("[install] trampoline alloc failed for %s -> rolling back", p.fnName);
            failed = true;
            break;
        }
        tramps.push_back(tr);
        if (!WritePatch(p, p.patched, nullptr, nullptr)) {
            Log("[install] VirtualProtect write failed for %s -> rolling back", p.fnName);
            failed = true;
            break;
        }
        g_appliedPlan.push_back(p);
        Log("[install] %s hooked at 0x%X", p.fnName, p.rva);
    }

    if (failed) {
        Log("[install] rolling back %zu applied patch(es)...", g_appliedPlan.size());
        bool rollbackOk = true;
        for (size_t i = 0; i < g_appliedPlan.size(); ++i) {
            if (!WritePatch(g_appliedPlan[i], g_appliedPlan[i].original, nullptr, nullptr)) {
                rollbackOk = false;
                Log("[install] ROLLBACK FAILED for %s (0x%X) -- game may be unstable",
                    g_appliedPlan[i].fnName, g_appliedPlan[i].rva);
            }
        }
        for (size_t i = 0; i < tramps.size(); ++i) VirtualFree(tramps[i], 0, MEM_RELEASE);
        g_appliedPlan.clear();
        g_state = argate::State::InstallFailed;
        Log("[install] %s", rollbackOk ? "rollback complete -- game left untouched"
                                       : "ROLLBACK INCOMPLETE -- please restart the game");
        return false;
    }

    // ---------- 阶段 6：全部成功，接上 trampoline 与可选函数指针 ----------
    g_arTramp  = tramps.size() > 0 ? tramps[0] : nullptr;
    g_ar2Tramp = tramps.size() > 1 ? tramps[1] : nullptr;

    // 可选组：拿不到就留空，observe/take 的判据不依赖它们


    // ---------- 阶段 6.5：take 链路推导（hookA -> E4B0 -> C890 -> 候选卡布局）----------
    //
    // 为什么放在这里：必需组（main-hook + hook-a）已经装好，take 链路是【可选增强】。
    // 任何一级失败都只禁用 take，observe 照常工作。
    //
    // legacy 常量只用于【对照告警】，绝不作为 fallback：
    //   如果某天推导值与 legacy 不符，说明结构真的变了 —— 那是有价值的信号。
    //   但推导失败时我们不会退回去用常量。
    if (hookARva != 0) {
        arresolve::LegacyCardOffsets legacy;
        legacy.countOff = kCountryCandCount;   // 仅作参照
        legacy.arrayOff = kCountryCandIds;

        arresolve::TakeChainResult tc =
            arresolve::DeriveTakeChain(aimg, hookARva,
                                       /*e4b0ExpectLen=*/1768,
                                       /*c890ExpectLen=*/4074,
                                       &legacy);
        for (size_t i = 0; i < tc.log.size(); ++i) Log("%s", tc.log[i].c_str());

        g_takeE4B0        = tc.e4b0Ok   ? (void*)(g_base + tc.e4b0Rva) : nullptr;
        g_takeC890        = tc.c890Ok   ? (void*)(g_base + tc.c890Rva) : nullptr;
        g_cardLayoutValid = tc.layoutOk;
        g_cardCountOff    = tc.layoutOk ? tc.layout.countOff : 0;
        g_cardArrayOff    = tc.layoutOk ? tc.layout.arrayOff : 0;
        g_cardElemSize    = tc.layoutOk ? tc.layout.elemSize : 0;

        if (!tc.layoutOk) {
            Log("[WARN] candidate-card layout unavailable -> take mode disabled; "
                "observe still works (records which tech the game picked)");
        }

#if AR_ENABLE_PROBES
        // ---------- 阶段 6.6：C890 只读打点（仅 AR_ENABLE_PROBES=1 时编译）---------
        if (tc.c890Ok) {
        #if AR_BUILD_WITH_PROBES
            if (InstallC890Probe(tc.c890Rva)) {
                g_c890ProbeInstalled = true;
            } else {
                Log("[c890] probe not installed -> take stays disabled; observe unaffected");
            }
        #endif  // AR_BUILD_WITH_PROBES
        } else {
            Log("[c890] C890 not located -> probe skipped; observe unaffected");
        }

        // ---------- 阶段 6.7：SEL 探针（仅 AR_ENABLE_PROBES=1 时编译）---------
        if (tc.selOk) {
        #if AR_BUILD_WITH_PROBES
            if (InstallSelProbe(tc.selRva)) {
                g_selProbeInstalled = true;
            } else {
                Log("[sel] probe not installed -> observe unaffected");
            }
        #endif  // AR_BUILD_WITH_PROBES
        } else {
            Log("[sel] SEL not located -> probe skipped");
        }
#else
        Log("[probe] AR_ENABLE_PROBES=0 -> C890/SEL probes not compiled (clean build)");
#endif

        // ---------- 阶段 6.8：A 点探针（0x820E4B，选卡循环体内）----------
        //
        // 这是「每日 tick → 科研选择」的核心循环。记录 tech/key/raw/i/rsp16。
        // 失败不 patch，observe 不受影响。
        #if AR_BUILD_WITH_PROBES
        if (LocateAndPatchSelB(g_base)) {
            Log("[selB] take 接管点候选已接上（只读观测）");
        } else {
            Log("[selB] A 点探针未安装 -> observe 不受影响");
        }
        #endif  // AR_BUILD_WITH_PROBES

        // ======================================================================
        // ★★ 2026-11-18：已删除 take v1（AR_Takeover / 0x820ECB）死代码 ★★
        //
        // 【为什么删】
        //   v1 patch 的是 0x820ECB（0x820B30 函数内部），但那里 gameIdx 是
        //   未初始化垃圾值（实测 -1422191178），会越界崩。
        //   它一直被 if (false && ...) 禁用，存在只会误导。
        //
        // 【现在的接管在哪】
        //   tk2：0x6F334E（玩家路径，AR_TakeoverV2）—— 见下面的阶段 6.11
        // ======================================================================

        // ---------- 阶段 6.11：take v2（0x6F334E，装槽前拦截）----------
#if AR_TAKEOVER_V2_DRYRUN
        Log("[tk2] mode=DRY-RUN（只观测不改行为）");
#endif
        if (InstallTakeoverV2(g_base)) {
            Log("[tk2] take v2 已接上");
        } else {
            Log("[tk2] take v2 未安装 -> observe 不受影响");
        }

        // ---------- 阶段 6.12：AI 自动科研路径探针（0xBBC3E7）----------
        //
        // ★ 2026-11-17 语义更正：0xBBC300 是 AI 路径，不是玩家路径。
        //
        //   0x6F2590（= 0x6F334E 所在函数）入口守卫：
        //     0x6F32D0  cmpl $0,0x314C(%rbx)   ; rbx = country
        //     0x6F32D7  je   0x6F3372           ; +314C == 0 → ret
        //     0x6F32DD  cmpb $0,[0x14281B833]
        //     0x6F32E4  jne  0x6F3372           ; g833 != 0 → ret
        //   ⇒ 处理条件（+314C != 0）&&（g833 == 0）= is_human
        //   ⇒ 0x6F2590 / 0x6F334E = 【玩家路径】（我们的主接管点）
        //
        //   0xBBC300 处理 17 国全部 c314c=0（实测 225 条 [bp]）
        //   ⇒ 0xBBC300 / 0xBBC3E7 = 【AI 路径】（本探针观测的对象）
        //
        // ★ 历史错误：旧注释把两条路径写反了，根因是把变量名 isai
        //   （= [country+0x314C]）误当成 is_ai。
        //
        // 本探针只观测：真调选卡器 + 记录 bit11/global/成员判据。
        if (AR_ENABLE_BP_PROBE && InstallPlayerPathProbe(g_base)) {
            Log("[bp] 玩家路径探针已接上");
        } else {
            Log("[bp] 玩家路径探针未安装 -> observe 不受影响");
        }

        // ---------- 阶段 6.10：科研槽观测探针（0x81B360 月度结算）----------
        //
        // 记录 3 个领域的 idx / key / candCnt，并做变化检测。
        // 纯只读，无 patch 风险（10 字节 E9 rel32 → nearby 绝对跳转 → DLL 内 trampoline）。
#if AR_ENABLE_RP_PROBE
        #if AR_BUILD_WITH_PROBES
        if (InstallResearchProbe(g_base)) {
            Log("[rp] 科研槽观测已接上");
        } else {
            Log("[rp] 科研槽观测未安装 -> observe 不受影响");
        }
        #endif  // AR_BUILD_WITH_PROBES
#else
        Log("[rp] 科研槽观测未编译（AR_ENABLE_RP_PROBE=0，2026-11-16 定案）");
#endif
    } else {
        Log("[WARN] hook-a RVA is 0 -> skipping take chain derivation");
    }

    g_state = (verdict == argate::ResolveVerdict::AnchorVerified)
                  ? argate::State::FullyInstalled
                  : argate::State::Unverified;
    Log("[install] all %zu required hook(s) installed; state=%s verdict=%s",
        plan.size(), argate::StateName(g_state),
        argate::ResolveVerdictName(verdict));
    return true;




}

// ---------------------------------------------------------------------------
// C890 只读打点：安装
// ---------------------------------------------------------------------------
// 返回 true = patch 成功，false = 未 patch（take 只 observe）
//
// 【为什么不用 argate::Patch / WritePatch】
//   那套是为「入口 5 字节 jmp」设计的（kPatchLen）。
//   C890 的 3 条 shadow-store 正好 15 字节，且必须整体挪到 trampoline，
//   用统一的 15 字节 jmp 更直接。这里单独实现，逻辑更清晰。
// ---------------------------------------------------------------------------
#if AR_ENABLE_PROBES
static bool InstallC890Probe(uint32_t c890Rva) {
    g_c890Target = (void*)(g_base + c890Rva);

    // 1) 校验目标可读、前 15 字节与预期一致（防止版本漂移后盲 patch）
    if (!SafeReadable(g_c890Target, 15)) {
        Log("[c890] probe: target not readable -> skip (take disabled, observe works)");
        return false;
    }
    static const uint8_t kExpect[15] = {
        0x4C,0x89,0x44,0x24,0x18,   // mov [rsp+0x18], r8
        0x48,0x89,0x54,0x24,0x10,   // mov [rsp+0x10], rdx
        0x48,0x89,0x4C,0x24,0x08    // mov [rsp+0x08], rcx
    };
    if (memcmp(g_c890Target, kExpect, 15) != 0) {
        Log("[c890] probe: prologue mismatch (version drift?) -> skip; "
            "first bytes: %02X %02X %02X %02X %02X",
            ((uint8_t*)g_c890Target)[0], ((uint8_t*)g_c890Target)[1],
            ((uint8_t*)g_c890Target)[2], ((uint8_t*)g_c890Target)[3],
            ((uint8_t*)g_c890Target)[4]);
        return false;
    }

    // 2) 分配 trampoline：15 字节原指令 + 5 字节 jmp = 20 字节
    // 15 字节原指令 + 13 字节绝对跳转 = 28 字节；分配 64 留余量
    uint8_t* tramp = (uint8_t*)VirtualAlloc(nullptr, 64,
                                            MEM_COMMIT | MEM_RESERVE,
                                            PAGE_EXECUTE_READWRITE);
    if (!tramp) { Log("[c890] probe: VirtualAlloc failed -> skip"); return false; }

    memcpy(tramp, kExpect, 15);
    // ★ 在 trampoline 末尾写 jmp 回原函数 +15 处
    //
    // 【2026-11-15 崩溃修复】原实现用 rel32 相对跳转，但：
    //   target = 0x7FF6_2425E7E0（游戏 exe）
    //   tramp  = 0x2815_5130000（VirtualAlloc 分配）
    //   相差 137 TB，远超 E9 rel32 的 ±2GB 范围 → rel32 截断 → 跳到垃圾地址 → 崩。
    // ⇒ 必须用绝对跳转：mov rax,imm64 ; jmp rax（13 字节）
    {
        uint8_t* p = tramp + 15;
        p[0] = 0x48; p[1] = 0xB8;                 // mov rax, imm64
        uint64_t back = (uint64_t)(uintptr_t)((uint8_t*)g_c890Target + 15);
        memcpy(p + 2, &back, 8);
        p[10] = 0xFF; p[11] = 0xE0;               // jmp rax
    }
    FlushInstructionCache(GetCurrentProcess(), tramp, 28);
    g_c890Tramp = tramp;

    // 3) 写 patch：入口 15 字节改成 jmp C890Entry
    DWORD oldProt = 0;
    if (!VirtualProtect(g_c890Target, 15, PAGE_EXECUTE_READWRITE, &oldProt)) {
        Log("[c890] probe: VirtualProtect(rw) failed -> skip");
        VirtualFree(tramp, 0, MEM_RELEASE); g_c890Tramp = nullptr;
        return false;
    }
    {
        // ★ 【2026-11-15 崩溃修复】同样不能用 rel32：
        //   C890Entry 在 DLL 里（≈0x39A681579），target 在 exe 里（0x7FF6_...），
        //   相差 140 TB，E9 rel32 会截断跳飞。
        // ⇒ 用 argate::MakeAbsJmp（15 字节绝对跳转，项目里已有的正确实现）
        argate::MakeAbsJmp((uint8_t*)g_c890Target, (uint64_t)(uintptr_t)&C890Entry);
    }
    VirtualProtect(g_c890Target, 15, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), g_c890Target, 15);

    Log("[c890] probe INSTALLED: target=0x%llX tramp=0x%llX "
        "(read-only tap: records seq/tick/p1/p2/p3/country)",
        (unsigned long long)(uintptr_t)g_c890Target,
        (unsigned long long)(uintptr_t)tramp);
    return true;
}
#endif  // AR_ENABLE_PROBES


// ================= 初始化 =================
static void Init() {
    g_base = (uint64_t)GetModuleHandleA(nullptr);
    // ★ 2026-11-20：日志放 DLL 自己的目录（不是 exe 目录）
    const std::string logDir = DllDir();
    if (logDir.empty()) return;   // 拿不到 DLL 目录 → 静默（不乱写 exe 目录）
    const std::string logPath = logDir + "\\auto_research.log";
    g_log = fopen(logPath.c_str(), "w");
    if (!g_log) return;   // 日志都开不了就彻底静默（不做事最安全）

    InitializeCriticalSection(&g_cs);
    // 配置锁必须在任何 PollConfig()/ConfigSnapshot() 之前就绪
    InitializeCriticalSection(&g_cfgCs);
    g_cfgCsReady = 1;

    // ★ 2026-11-20：注册 VEH 崩溃捕获（诊断版）
    //   用 AddVectoredExceptionHandler（比 SetUnhandledExceptionFilter 更早拿到）
    AddVectoredExceptionHandler(1, &CrashHandler);

    Log("==============================================================");
    Log("auto_research.dll");
    Log("  supports : %s (build %s)", arver::kSupportedVersionTag,
        arver::kSupportedBuildId);
    Log("  built for: sha256 %s", arver::kSupportedSha256);
    Log("  base     : 0x%llX", (unsigned long long)g_base);
    Log("  config   : %s", ConfigPath().c_str());
    Log("             pure-numeric weights (>0 / 0 / <0), default mode=%s",
        arcfg::ModeName(arcfg::Defaults().mode));
    Log("  log      : %s", logPath.c_str());
    Log("--------------------------------------------------------------");
Log("  build    : 2026-11-20 v1.0.0 LIVE-PLAYER (player=0x6F334E 接管；ai=0xBBC3E7 已禁)");
    Log("  features :");
    // ★★ 2026-11-20：功能清单按实际构建分支（幅辅必须准确）★★
#if AR_BUILD_WITH_PROBES
    Log("    [ON ] observe        记录游戏选了哪个科技（主 hook 0x428EE0）");
    Log("    [ON ] [alt]          三领域备选数量采样");
    Log("    [ON ] [selB]         选卡循环内的 tech/key/raw 观测（0x820E4B）");
    Log("    [ON ] [tak-DBG]      候选数组与 gamePick 对比诊断");
    Log("    [ON ] [tak-SKIP]     成员判据：gamePick 不在候选数组 → 不干预");
    Log("    [ON ] [disp]         科技显示名构造（单行 + 限流）");
#else
    Log("    [OFF] observe        记录游戏选了哪个科技（使用版关闭，减少噪声）");
    Log("    [OFF] [alt]          三领域备选数量采样（使用版关闭）");
    Log("    [OFF] [selB]         选卡循环内的观测（使用版关闭）");
    Log("    [ON ] [tak-DBG]      候选数组诊断（仅前 20 次，之后静默）");
    Log("    [ON ] [tak-SKIP]     成员判据记录（前 20 + 每 100 次）");
    Log("    [OFF] [disp]         显示名构造记录（使用版关闭）");
#endif
    Log("    [ON ] L1 偏移推导    从函数体指令推导候选卡布局");
    Log("    [ON ] 玩家判据      country+0x314C != 0（三条独立证据）");
    Log("    [ON ] [tk2] take v3   0x6F334E ** LIVE **（玩家路径真接管）");
    Log("    [ON ] take 真接管   AR_TAKEOVER_V2_DRYRUN=0（LIVE）");
    Log("    [ON ] VEH 崩溃捕获   记录 code/rip/fault module，不吞异常");
    Log("    [OFF] [bp]           AI 路径探针 0xBBC3E7（已确认无用，两版都关）");
    Log("    [OFF] [bp-pid]       pid 诊断（随 [bp] 一起关闭）");
    Log("    [OFF] [rp] 科研槽   0x81B360（AR_ENABLE_RP_PROBE=0）");
    Log("    [OFF] [c890]/[map]   C890 探针 + tech id<->key（AR_ENABLE_PROBES=0）");
    Log("  ----------------------------------------------------------");
    Log("  ⚠ 【强制读】本版本【禁止热卸载】：运行中 FreeLibrary 会崩");
    Log("    原因：RemoveTakeoverV2/RemoveResearchProbe 在 AR_ENABLE_PROBES=0 时被预处理掉");
    Log("    正确做法：关游戏 → 替换 DLL → 重启游戏");
    Log("    （当前注入器只 load 不 unload，所以实际不会触发；但手动操作必须避开）");
    Log("==============================================================");

    // ---- 先加载配置，据此决定是否改写返回地址（dryrun）----
    // 必须在 InstallAll() 之前，因为 AREntryA 一装上就会读这个标志。
    {
        arcfg::PollResult r = PollConfig();
        arcfg::Config cfg = ConfigSnapshot();
        // 用 ar_config.h 里的纯函数决定，便于离线自测覆盖
        g_ar2DoPatch = arcfg::ShouldPatchReturnAddress(cfg.mode);
        Log("[cfg] initial load: mode=%s patch=%s (poll=%s)",
            arcfg::ModeName(cfg.mode),
            g_ar2DoPatch ? "ON" : "OFF (dryrun: hook-a will observe only)",
            arcfg::PollResultName(r));
        if (cfg.mode == arcfg::Mode::DryRun) {
            Log("[cfg] DRYRUN: hook-a entry will be patched, but the return address");
            Log("[cfg]         will NOT be rewritten -> verifies patch safety alone.");
        }
    }

    // 游戏内 std::string 构造/析构地址：只有闸门通过后才有意义，
    // 但这里先不赋值 —— 版本不对时它们指向错误函数，绝不能留着被误用。
    // 由 InstallAll() 成功后统一装配（见下方）。

    if (!InstallAll()) {
        Log("==============================================================");
        Log("[gate] FINAL STATE: %s", argate::StateName(g_state));
        Log("[gate] The DLL is inert. Your game has NOT been modified.");
        Log("[gate] If this is a version mismatch, either:");
        Log("[gate]   1) use a DLL built for your game version, or");
        Log("[gate]   2) report the version at the project page.");
        Log("==============================================================");
        return;
    }

    // 闸门通过且 hook 已装。
    //
    // 注意：g_arTramp / g_ar2Tramp 已经在
    // InstallAll() 的「阶段 6」里用【锚点解析出的 RVA】装配好了。
    // 这里【绝对不能再赋值】—— 否则会用硬编码的旧版本 RVA 覆盖解析结果，
    // 版本一变就指向错误函数。（2026-11-11 发现并修复的第 4 例
    // 「代码写了但接线错了」：InstallAll 解析对了，Init 又覆盖了。）
    //
    // g_getPlayer 目前没有锚点（FINDINGS §7.5：1945 个调用者，无唯一特征），
    // 且 auto_research.cpp 里从未调用它，属于死代码 —— 保持 nullptr。

    // 注意：切换 @mode 到/从 dryrun 需要重启游戏才生效。
    // 刻意不做热切换 —— 返回地址是否已被改写是「安装期」状态，
    // 运行中改变它会与已有栈帧不一致，风险高于收益。
    PollConfig();
    Log("==============================================================");
    Log("[gate] FINAL STATE: %s", argate::StateName(g_state));
    Log("[gate] init done");
    Log("==============================================================");
}

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls((HMODULE)0);
        Init();
    } else if (reason == DLL_PROCESS_DETACH) {
        // C890 打点统计：卸载时输出总量（回答「每次决策被调几次」的必要数据）
#if AR_ENABLE_PROBES
        if (g_c890ProbeInstalled) C890LogSummary();
        if (g_selProbeInstalled) SelLogSummary();
        RemoveTakeover();
        RemoveTakeoverV2();
#if AR_ENABLE_RP_PROBE
        RemoveResearchProbe();
#endif
#endif
        // ====================================================================
        // ★★ 2026-11-20：退出时打一条完整汇总（用户明确要求）★★
        // ====================================================================
        //
        // 【为什么放在这里】
        //   一局只有 ~219 次决策，「每 500 次」永远够不到 → 必须在退出时打。
        //
        // 【安全性】
        //   · 计数器用 InterlockedCompareExchange 无锁读，不可能死锁
        //   · 此时进程正在退出，并发极低
        //   · fprintf + fflush + fclose 一口气写完
        //   · 即使写失败，也不影响游戏退出（已在退出中）
        //
        if (g_log) {
            const LONG tot     = InterlockedCompareExchange(&s_tk2RealPicks, 0, 0)
                               + InterlockedCompareExchange(&s_tk2NoOps, 0, 0);
            const LONG real    = InterlockedCompareExchange(&s_tk2RealPicks, 0, 0);
            const LONG noop    = InterlockedCompareExchange(&s_tk2NoOps, 0, 0);
            const LONG player  = InterlockedCompareExchange(&s_tk2PlayerPicks, 0, 0);
            const LONG ai      = InterlockedCompareExchange(&s_tk2AiTicks, 0, 0);
            const LONG tie     = InterlockedCompareExchange(&s_tieTotal, 0, 0);
            const LONG tieHit  = InterlockedCompareExchange(&s_tieHitGame, 0, 0);
            const LONG pickKey = InterlockedCompareExchange(&s_pickKey, 0, 0);
            const LONG pickKp  = InterlockedCompareExchange(&s_pickKeep, 0, 0);

            fprintf(g_log,
                "[汇总] 总决策=%ld 真选卡=%ld 早退=%ld 玩家=%ld AI=%ld | "
                "并列=%ld 撞上原选=%ld | [PICK] 接管=%ld 保留=%ld\n",
                (long)tot, (long)real, (long)noop, (long)player, (long)ai,
                (long)tie, (long)tieHit, (long)pickKey, (long)pickKp);
            fprintf(g_log, "=== detach ===\n");
            fflush(g_log);
            fclose(g_log);
            g_log = nullptr;
        }
    }
    return TRUE;
}
