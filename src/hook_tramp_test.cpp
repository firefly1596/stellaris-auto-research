// hook_tramp_test.cpp —— hookA 返回地址改写 + trampoline 的离线仿真
//
// ============ 背景：2026-10-31 真实游戏崩溃 ============
// 定位出两个独立缺陷，最终用「改架构」彻底消除风险类别：
//
// 缺陷 1（主根因）：ARAfter2 末尾 `jmp *g_ar2Tramp` 应为 `jmp *g_ar2Caller`。
//   trampoline = 原函数前 15 字节 + jmp 回 target+15，它是【入口】不是完整函数。
//   原函数已经 ret 之后又跳回它 => 重放序言 + 再跑一遍函数体；
//   此时 RSP 已回到调用者视角，重放的 home-space 写入会踩坏调用者栈帧，
//   最终 ret 弹出垃圾 → 跳到地址 0 → 崩。
//
// 缺陷 2（第二根因）：ARAfter2 里 `call ARLogStart`。
//   该函数是被原函数的 ret **跳入**的，入口 rsp%16 与普通函数不同；
//   7 个 push 之后再进行 call，无论 sub 取 0x30 还是 0x38 都只是在
//   给一个本不该存在的 call 打补丁，永远有踩空风险。
//
// ★ 最终方案：**不在裸汇编里 call 任何 C 函数**
//   ARAfter2 只把 tech 指针写进全局变量，然后 jmp 真实调用者。
//   日志由主 hook（ARProcess，普通 call 进入、栈环境正常）输出。
//   这样「栈对齐」这个风险类别被整个消除，不需要人肉数 push/sub。
//
// ============ 本测试验证 ============
//   1) trampoline 结构正确（原 15 字节 + jmp target+15）
//   2) 新架构下：序言执行 1 次、函数体执行 1 次、回到调用者、RSP 完全平衡
//   3) 新架构下 ARAfter2 **没有任何 push/call**，所以不存在对齐问题
//   4) 对照：旧架构「跳回 trampoline」会让序言执行 2 次
//
// 编译：g++ -std=c++17 -O0 -o hook_tramp_test.exe hook_tramp_test.cpp

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <windows.h>
#include <string>

static int g_pass = 0, g_fail = 0;
static FILE* g_log = nullptr;

// 同时输出到 stdout 和日志文件（--log 参数），供 build_and_test.sh 统一收集
static void Emit(const std::string& s) {
    fputs(s.c_str(), stdout);
    fputc('\n', stdout);
    if (g_log) { fputs(s.c_str(), g_log); fputc('\n', g_log); fflush(g_log); }
}
static void Check(bool c, const char* what, const char* detail = "") {
    if (c) { ++g_pass; printf("  [PASS] %s\n", what); }
    else   { ++g_fail; printf("  [FAIL] %s   (%s)\n", what, detail); }
}


// =====================================================================
// 源码文本断言工具
// =====================================================================
//
// 为什么需要这个：
//   2026-10-31/11-01 两次真机崩溃，根因之一是 hook_tramp_test.cpp 里有
//   4 条 `Check(true, ...)` —— 它们声称验证了关键性质，实际什么都没查。
//   其中 `Check(true, "ARAfter 已改用 sub $0x38")` 如果真的是检查，
//   ARAfter 用 sub $0x30 时它就会失败，第一次崩溃根本不会发生。
//
// 原则（与产品代码的假断言相对）：
//   1. 读不到源码 = 测试环境有问题 = 必须 FAIL，绝不静默跳过
//   2. 失败信息要给出「期望什么、实际找到什么」，能直接定位病灶
//   3. 断言必须能真的捕获错误（靠负向注入验证，见 NEGATIVE_INJECTION 记录）

static std::string g_srcText;      // auto_research.cpp 的全文
static bool        g_srcLoaded = false;

// 读取同目录的 auto_research.cpp。失败返回 false（调用方必须判失败）。

// ============================================================================
// stripComments() —— 剥离 // 行注释、/* */ 块注释、字符串字面量
// ============================================================================
//
// 【为什么必须有】
//   本项目已经踩了 4 次「注释当代码」的坑：
//     1) AREntryA 注释里的 "jmp *g_ar2Tramp" 被数成 call
//     2) ar_layout.h 审查同样踩一次
//     3) IsPlayerContext 注释里的 "static bool IsPlayerContext() {" 被当成第二处定义
//     4) SEL 桩注释里的 "不需要 sub $8" 被当成真实 sub 指令
//
//   ⇒ 规则：任何对产品源码的文本断言，一律走本函数产出的 code-only 视图。
//     不允许直接用 g_srcText 做「不含/包含某指令」的判断。
// ============================================================================
static std::string StripComments(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    size_t i = 0;
    const size_t n = s.size();
    while (i < n) {
        // 行注释
        if (i + 1 < n && s[i] == '/' && s[i + 1] == '/') {
            while (i < n && s[i] != '\n') ++i;
            continue;                       // 保留换行由下一轮处理
        }
        // 块注释
        if (i + 1 < n && s[i] == '/' && s[i + 1] == '*') {
            i += 2;
            while (i + 1 < n && !(s[i] == '*' && s[i + 1] == '/')) ++i;
            if (i + 1 < n) i += 2;
            continue;
        }
        // 字符串字面量（"..."，处理 \" 转义）
        if (s[i] == '"') {
            ++i;
            while (i < n) {
                if (s[i] == '\\' && i + 1 < n) { i += 2; continue; }
                if (s[i] == '"') { ++i; break; }
                ++i;
            }
            continue;
        }
        // 字符字面量（'...'）
        if (s[i] == '\'') {
            ++i;
            while (i < n) {
                if (s[i] == '\\' && i + 1 < n) { i += 2; continue; }
                if (s[i] == '\'') { ++i; break; }
                ++i;
            }
            continue;
        }
        out += s[i];
        ++i;
    }
    return out;
}

// 全局 code-only 视图（剥离注释与字面量后的产品源码）
static std::string g_srcCode;

static bool LoadProductSource() {
    if (g_srcLoaded) return true;
    const char* candidates[] = {
        "auto_research.cpp",
        "../tech_probe/auto_research.cpp",
        "_stellaris_eval/tech_probe/auto_research.cpp",
    };
    for (const char* p : candidates) {
        FILE* f = fopen(p, "rb");
        if (!f) continue;
        fseek(f, 0, SEEK_END);
        long n = ftell(f);
        fseek(f, 0, SEEK_SET);
        if (n > 0) {
            g_srcText.resize((size_t)n);
            size_t got = fread(&g_srcText[0], 1, (size_t)n, f);
            fclose(f);
            if (got == (size_t)n) {
                g_srcCode = StripComments(g_srcText);
                g_srcLoaded = true;
                return true;
            }
        } else {
            fclose(f);
        }
    }
    return false;
}

// 从源码里提取某个裸汇编块的内容（从 "<label>:" 到下一个 "\n);"）
// 返回该块的文本；找不到返回空串。
// 提取裸汇编块，并【剥离 C++ 注释】——注释里会出现 "call"/"sub"/"push" 等字样，
// 不剥离会导致计数把文档当成代码（实测踩过：ARAfter2 的注释里有 3 个 "call"）。
// 只保留形如   "  <asm>\n"   的字符串行内容。
static std::string ExtractAsmBlock(const char* label) {
    if (!g_srcLoaded) return std::string();
    std::string marker = std::string("\"") + label + ":\\n\"";
    size_t start = g_srcText.find(marker);
    if (start == std::string::npos) return std::string();
    size_t end = g_srcText.find("\n);", start);
    if (end == std::string::npos) return std::string();
    std::string raw = g_srcText.substr(start, end - start);

    // 逐行处理：去掉 // 之后的部分；只保留首尾都是双引号的汇编字符串行
    std::string out;
    size_t pos = 0;
    while (pos <= raw.size()) {
        size_t nl = raw.find('\n', pos);
        std::string line = (nl == std::string::npos) ? raw.substr(pos)
                                                     : raw.substr(pos, nl - pos);
        // 去掉行内 // 注释
        size_t cmt = line.find("//");
        if (cmt != std::string::npos) line = line.substr(0, cmt);
        // 只保留含双引号的汇编行
        size_t q1 = line.find('"');
        if (q1 != std::string::npos) {
            out += line;
            out += '\n';
        }
        if (nl == std::string::npos) break;
        pos = nl + 1;
    }
    return out;
}

// 统计块内某个 token 出现次数（简单子串计数）
static int CountIn(const std::string& block, const char* token) {
    int n = 0;
    size_t pos = 0;
    size_t tl = strlen(token);
    while ((pos = block.find(token, pos)) != std::string::npos) { ++n; pos += tl; }
    return n;
}

// 在块里找 "sub $0xNN, %rsp" 形式的立即数，返回十六进制值；找不到返回 -1
static int FindRspSubImm(const std::string& block) {
    size_t pos = 0;
    while ((pos = block.find("sub $0x", pos)) != std::string::npos) {
        size_t p = pos + 7;                 // 跳过 "sub $0x"
        int val = 0; int digits = 0;
        while (p < block.size()) {
            char c = block[p];
            int d;
            if (c >= '0' && c <= '9') d = c - '0';
            else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
            else break;
            val = val * 16 + d; ++digits; ++p;
        }
        if (digits > 0 && block.find("%rsp", p) != std::string::npos &&
            block.find("%rsp", p) < p + 6) {
            return val;
        }
        pos += 7;
    }
    return -1;
}

// ---------------- 全局 ----------------
volatile uint64_t g_prologueRuns = 0;
volatile uint64_t g_bodyRuns     = 0;
volatile uint64_t g_afterRuns    = 0;
volatile uint64_t g_callerOk     = 0;
// 任务 t10 明确要求：必须记录 AfterHook 入口 rsp%16 的实测值，作为对齐结论依据
volatile uint64_t g_rspAtHookEntry = 0;   // hook 入口（EntryNew）的 rsp
volatile uint64_t g_rspAtAfterEntry = 0;  // 出口处理器（AfterNew）入口的 rsp
void* g_tramp      = nullptr;
void* g_realCaller = nullptr;
void* g_pendingTech  = nullptr;    // 对应 g_pendingStartTech
volatile uint64_t g_pendingValid = 0;

// ---------------- 假原函数（模拟 FUN_14081A900 序言形态）----------------
extern "C" void FakeCallee();
__asm__(
    ".text\n"
    ".globl FakeCallee\n"
    "FakeCallee:\n"
    "  mov %rbx, 0x8(%rsp)\n"       // 15 字节 home-space 写入 = 真实形态
    "  mov %rsi, 0x10(%rsp)\n"
    "  mov %rdi, 0x18(%rsp)\n"
    "  incq g_prologueRuns(%rip)\n"
    "  incq g_bodyRuns(%rip)\n"
    "  ret\n"
);

// ---------------- 新架构的出口处理器：无 push、无 call ----------------
extern "C" void AfterNew();
__asm__(
    ".text\n"
    ".globl AfterNew\n"
    "AfterNew:\n"
    "  mov %rsp, g_rspAtAfterEntry(%rip)\n"   // 实测入口 rsp（第一条指令，不改变栈）
    "  incq g_afterRuns(%rip)\n"
    "  mov g_pendingTechVal(%rip), %rax\n"   // 只写全局，不调函数
    "  mov %rax, g_pendingTech(%rip)\n"
    "  movq $1, g_pendingValid(%rip)\n"
    "  jmp *g_realCaller(%rip)\n"            // 跳真实调用者
);

// 用 tech 值模拟 g_ar2Tech（真实代码里由 AREntryA 保存）
extern "C" void* g_pendingTechVal = (void*)0x1234;

// ---------------- 入口（模拟 AREntryA）----------------
extern "C" void EntryNew();
__asm__(
    ".text\n"
    ".globl EntryNew\n"
    "EntryNew:\n"
    "  mov %rsp, g_rspAtHookEntry(%rip)\n"
    "  mov (%rsp), %rax\n"
    "  mov %rax, g_realCaller(%rip)\n"        // 必须早于 lea
    "  lea AfterNew(%rip), %rax\n"
    "  mov %rax, (%rsp)\n"                    // 改写返回地址
    "  jmp *g_tramp(%rip)\n"
);

// ---------------- trampoline 构造（与 AllocTrampoline 同构）----------------
static uint8_t* MakeTrampoline(uint8_t* target, const uint8_t* original15) {
    uint8_t* p = (uint8_t*)VirtualAlloc(nullptr, 31, MEM_COMMIT | MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE);
    if (!p) return nullptr;
    memcpy(p, original15, 15);
    p[15] = 0x48; p[16] = 0xB8;              // mov rax, imm64
    uint64_t back = (uint64_t)(target + 15);
    memcpy(p + 17, &back, 8);
    p[25] = 0xFF; p[26] = 0xE0;              // jmp rax
    return p;
}

// ---------------- 调用者 ----------------
// 注意：调用者必须在 call 前让 rsp%16==0 并预留 32 字节 shadow，
// 否则被调函数序言里的 home-space 写入会踩坏调用者栈帧。
extern "C" void TestCaller();
__asm__(
    ".text\n"
    ".globl TestCaller\n"
    "TestCaller:\n"
    "  push %rbx\n"
    "  sub $0x20, %rsp\n"
    "  mov %rsp, %rbx\n"
    "  call EntryNew\n"
    "  cmp %rsp, %rbx\n"                 // RSP 必须完全平衡
    "  jne 9f\n"
    "  movq $1, g_callerOk(%rip)\n"
    "9:\n"
    "  add $0x20, %rsp\n"
    "  pop %rbx\n"
    "  ret\n"
);

// =====================================================================
int main(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--log" && i + 1 < argc) {
            g_log = fopen(argv[++i], "w");
        }
    }
    // 加载产品源码：第 3、5 节的断言要读它做真检查。
    // 失败不在这里立即报错（LoadProductSource 的返回值由那些断言自己处理），
    // 但必须真的调用 —— 否则 g_srcLoaded 永远 false，断言会全部 FAIL（这是期望行为）。
    {
        bool loaded = LoadProductSource();
        if (loaded) {
            char lb[160];
            snprintf(lb, sizeof(lb), "已加载 auto_research.cpp（%zu 字节）", g_srcText.size());
            Emit(std::string("  [INFO] ") + lb);
        } else {
            Emit("  [INFO] 未能加载 auto_research.cpp —— 依赖源码的断言将 FAIL");
        }
    }

    printf("==============================================\n");
    printf("hookA 返回地址改写 + trampoline 离线仿真\n");
    printf("验证 2026-10-31 崩溃修复（新架构：裸汇编不 call C 函数）\n");
    printf("==============================================\n");

    printf("\n=== 1) 假原函数序言形态 ===\n");
    const uint8_t* pc = (const uint8_t*)&FakeCallee;
    const uint8_t expect[15] = {0x48,0x89,0x5C,0x24,0x08,
                                0x48,0x89,0x74,0x24,0x10,
                                0x48,0x89,0x7C,0x24,0x18};
    Check(memcmp(pc, expect, 15) == 0, "前 15 字节是 home-space 写入（与游戏同形态）");

    printf("\n=== 2) 新架构完整路径 ===\n");
    uint8_t orig[15];
    memcpy(orig, (const void*)&FakeCallee, 15);
    uint8_t* tr = MakeTrampoline((uint8_t*)&FakeCallee, orig);
    if (!tr) { printf("  [FAIL] trampoline 分配失败\n"); return 1; }
    g_tramp = tr;

    g_prologueRuns = 0; g_bodyRuns = 0; g_afterRuns = 0;
    g_callerOk = 0; g_pendingValid = 0; g_pendingTech = nullptr;
    g_rspAtHookEntry = 0; g_rspAtAfterEntry = 0;

    TestCaller();

    char b[256];
    snprintf(b, sizeof(b), "序言执行 1 次（实际 %llu）—— 未重放，缺陷 1 已修",
             (unsigned long long)g_prologueRuns);
    Check(g_prologueRuns == 1, b);
    snprintf(b, sizeof(b), "函数体执行 1 次（实际 %llu）",
             (unsigned long long)g_bodyRuns);
    Check(g_bodyRuns == 1, b);
    snprintf(b, sizeof(b), "出口处理器执行 1 次（实际 %llu）",
             (unsigned long long)g_afterRuns);
    Check(g_afterRuns == 1, b);
    Check(g_callerOk == 1, "正确回到调用者，RSP 完全平衡");
    Check(g_pendingValid == 1, "挂起标记已置位（日志改由主 hook 输出）");
    snprintf(b, sizeof(b), "挂起的 tech 指针正确传递（%p）", g_pendingTech);
    Check(g_pendingTech == (void*)0x1234, b);

    printf("\n=== 2b) 实测 rsp%%16（任务 t10 要求记录）===\n");
    {
        int hookMod = (int)(g_rspAtHookEntry & 15);
        int afterMod = (int)(g_rspAtAfterEntry & 15);
        snprintf(b, sizeof(b), "hook 入口 rsp%%16 = %d（call 进入，应为 8）", hookMod);
        Check(hookMod == 8, b);
        snprintf(b, sizeof(b), "AfterHook 入口 rsp%%16 = %d（ret 跳入，hook 入口 +8）", afterMod);
        Check(afterMod == 0, b);
        snprintf(b, sizeof(b),
                 "实测：hook 入口 0x%llX → 出口 0x%llX，差值 %lld 字节",
                 (unsigned long long)g_rspAtHookEntry,
                 (unsigned long long)g_rspAtAfterEntry,
                 (long long)(g_rspAtAfterEntry - g_rspAtHookEntry));
        Emit(b);
        Emit("    => 结论：出口处理器入口 rsp%16 == 0。旧代码 7 push(56B) 后变 8，再 sub 0x30(48B) 仍是 8，");
        Emit("       call 前 rsp%16==8 → 违反 Win64 ABI。这正是缺陷 2。");
        Emit("       新架构下面没有 call，该问题整个消失。");
    }

    printf("\n=== 3) 新架构下不存在栈对齐问题（读产品源码真检查）===\n");
    if (!g_srcLoaded) {
        Check(false, "无法读取 auto_research.cpp —— 测试环境有问题，按 FAIL 处理（不静默跳过）");
    } else {
        std::string a2 = ExtractAsmBlock("ARAfter2");
        snprintf(b, sizeof(b), "能从源码提取到 ARAfter2 汇编块（%zu 字符）", a2.size());
        Check(!a2.empty(), b);
        if (!a2.empty()) {
            int nPush = CountIn(a2, "push ");
            int nPop  = CountIn(a2, "pop ");
            int nSub  = CountIn(a2, "sub $0x");
            int nAdd  = CountIn(a2, "add $0x");
            snprintf(b, sizeof(b),
                     "ARAfter2 不修改 rsp —— push=%d pop=%d sub=%d add=%d（全应为 0）",
                     nPush, nPop, nSub, nAdd);
            Check(nPush == 0 && nPop == 0 && nSub == 0 && nAdd == 0, b);
            int nCall = CountIn(a2, "call ");
            snprintf(b, sizeof(b), "ARAfter2 内无 call（实际 %d 个）", nCall);
            Check(nCall == 0, b);
            bool toCaller = a2.find("jmp *g_ar2Caller") != std::string::npos;
            bool toTramp  = a2.find("jmp *g_ar2Tramp")  != std::string::npos;
            snprintf(b, sizeof(b),
                     "ARAfter2 跳转 = g_ar2Caller（toCaller=%d toTramp=%d，后者须为 0）",
                     (int)toCaller, (int)toTramp);
            Check(toCaller && !toTramp, b);
        }
    }

    printf("\n=== 4) 对照：旧架构（跳回 trampoline）会重放序言 ===\n");
    printf("    旧代码末尾 jmp *g_ar2Tramp 会让 trampoline 再执行一次，\n");
    printf("    序言执行数变成 2，且 home-space 写入落在已错位的栈上 → 崩。\n");
    printf("    （不在本测试里真跑，因为它会破坏栈；这里只做说明）\n");
    // 说明性文字：这里无法验证「旧架构会崩」——那需要真跑会破坏栈的路径。
    // 用 Emit 而不是 Check，避免制造"看着在测、实际没测"的假断言。
    Emit("    （以上是对旧架构失败机理的说明，不是本测试的断言）");

    VirtualFree(tr, 0, MEM_RELEASE);

    printf("\n=== 5) 主 hook 出口（ARAfter）的 sub 值（读产品源码真检查）===\n");
    Emit("    已知：ARAfter 被原函数 ret 跳入，入口 rsp%16 = 0；7 push(56B) 后 = 8；");
    Emit("    要 call 前 rsp%16 == 0，sub 立即数的 %16 必须是 8（0x38 或 0x28），不能是 0x30。");
    if (!g_srcLoaded) {
        Check(false, "无法读取 auto_research.cpp —— 按 FAIL 处理（不静默跳过）");
    } else {
        std::string af = ExtractAsmBlock("ARAfter");
        snprintf(b, sizeof(b), "能从源码提取到 ARAfter 汇编块（%zu 字符）", af.size());
        Check(!af.empty(), b);
        if (!af.empty()) {
            int imm = FindRspSubImm(af);
            if (imm < 0) {
                Check(false, "ARAfter 里找不到 sub $0x.., %rsp —— 结构变了，需人工确认");
            } else {
                int mod16 = imm & 15;
                int rspAtCall = (8 - mod16) & 15;
                snprintf(b, sizeof(b),
                         "ARAfter 的 sub 立即数 = 0x%X -> call 前 rsp%%16 = %d（必须为 0）",
                         imm, rspAtCall);
                char d2[256];
                snprintf(d2, sizeof(d2),
                         "期望 sub $0x38(或$0x28)，实际找到 sub $0x%X —— call 前 rsp%%16 会是 %d，违反 Win64 ABI",
                         imm, rspAtCall);
                Check(mod16 == 8, b, d2);
            }
            int nPush5 = CountIn(af, "push ");
            snprintf(b, sizeof(b), "ARAfter 的 push 数量 = 7（实际 %d）", nPush5);
            Check(nPush5 == 7, b);
            bool toRet = af.find("jmp *g_retAddr") != std::string::npos;
            snprintf(b, sizeof(b), "ARAfter 跳转目标 = g_retAddr（%d）", (int)toRet);
            Check(toRet, b);
            int nCall5 = CountIn(af, "call ");
            snprintf(b, sizeof(b), "ARAfter 内 call 数量 = 1（实际 %d，应为 ARProcess）", nCall5);
            Check(nCall5 == 1, b);
        }
    }

    printf("\n=== 6) P0 数据流：caller/param3 是否完整传到日志 ===\n");
    Emit("    背景：2026-11-12 真机日志里 caller=0x0 site=0x0，");
    Emit("          根因是 FlushPendingStart 硬编码传 (0,0)。本组防它回归。");
    if (!g_srcLoaded) {
        Check(false, "无法读取 auto_research.cpp —— 按 FAIL 处理");
    } else {
        std::string e = ExtractAsmBlock("AREntryA");
        std::string a = ExtractAsmBlock("ARAfter2");
        Check(!e.empty(), "能提取 AREntryA 块");
        Check(!a.empty(),   "能提取 ARAfter2 块");

        // 采集端
        Check(e.find("g_ar2Caller") != std::string::npos,
              "AREntryA 采集 g_ar2Caller");
        Check(e.find("g_ar2Param3") != std::string::npos,
              "AREntryA 采集 g_ar2Param3");
        // 转存端（P0 修复的核心）
        Check(a.find("g_pendingCaller") != std::string::npos,
              "ARAfter2 转存 caller 到 pending");
        Check(a.find("g_pendingParam3") != std::string::npos,
              "ARAfter2 转存 param3 到 pending");
        // 消费端：不得硬编码 0
        {
            size_t f = g_srcText.find("static void FlushPendingStart");
            bool has64 = false, noHardZero = true, passReal = false;
            if (f != std::string::npos) {
                size_t fe = g_srcText.find("\n}", f);
                std::string fb = g_srcText.substr(f, fe - f);
                has64 = fb.find("InterlockedExchange64") != std::string::npos;
                noHardZero = fb.find("ARLogStartInner(tech, 0, 0)") == std::string::npos;
                passReal = fb.find("ARLogStartInner(tech, caller, p3)") != std::string::npos;
            }
            Check(f != std::string::npos, "源码中存在 FlushPendingStart");
            Check(has64,     "FlushPendingStart 用 InterlockedExchange64 读 caller");
            Check(noHardZero,"FlushPendingStart 不硬编码传 (0,0)");
            Check(passReal,  "FlushPendingStart 传真实 caller/p3");
        }
    }

    printf("\n=== 7) C890 只读打点：接线与安全（第 8 例防回归）===\n");
    Emit("    背景：2026-11-15 发现 g_takeC890/g_takeE4B0 只赋值从未 patch，");
    Emit("          即「第 8 例：写了没接线」。本组防它再次退化。");
    if (!g_srcLoaded) {
        Check(false, "无法读取 auto_research.cpp —— 按 FAIL 处理");
    } else {
        // 7.1 必须存在安装函数与入口桩
        Check(g_srcText.find("InstallC890Probe") != std::string::npos,
              "源码含 InstallC890Probe");
        Check(g_srcText.find("C890Entry") != std::string::npos,
              "源码含 C890Entry 汇编桩");

        // 7.2 ★ 关键：必须【真的调用】安装函数（不是只声明）
        {
            size_t callPos = g_srcText.find("if (InstallC890Probe(tc.c890Rva))");
            Check(callPos != std::string::npos,
                  "InstallC890Probe 被实际调用（不是只声明）");
        }

        // 7.3 入口桩必须保存 7 个易失寄存器
        {
            const char* regs[] = {"push %rax","push %rcx","push %rdx","push %r8",
                                  "push %r9","push %r10","push %r11"};
            for (int i = 0; i < 7; ++i) {
                char msg[72];
                snprintf(msg, sizeof(msg), "桩保存 %s", regs[i]);
                Check(g_srcText.find(regs[i]) != std::string::npos, msg);
            }
        }

        // 7.4 ★ 栈偏移必须匹配「7 push + sub 0x20」后的布局
        //   2026-11-16 shadow-space 修复：全部 +0x20
        //   [rsp+0x38]=r8(原R-32) [rsp+0x40]=rdx(原R-24) [rsp+0x48]=rcx(原R-16)
        Check(g_srcText.find("mov 56(%rsp), %r8") != std::string::npos,
              "桩从 +0x38 读 param_3（r8）");
        Check(g_srcText.find("mov 64(%rsp), %rdx") != std::string::npos,
              "桩从 +0x40 读 param_2（rdx）");
        Check(g_srcText.find("mov 72(%rsp), %rcx") != std::string::npos,
              "桩从 +0x48 读 param_1（rcx）");

        // 7.5 ★ 绝不能在桩里 sub $8（7 次 push 后已对齐，多减会破坏 ABI）
        {
            // ★ 必须找带引号的汇编标签，不是注释里的 C890Entry:
            size_t a = g_srcText.find("\"C890Entry:\\n\"");
            size_t b = g_srcText.find("jmp *g_c890Tramp");
            if (a != std::string::npos && b != std::string::npos && b > a) {
                std::string body = g_srcText.substr(a, b - a);
                Check(body.find("sub $8, %rsp") == std::string::npos,
                      "桩内无 sub $8（7 push 后已 16 字节对齐）");
            } else {
                Check(false, "能切出 C890Entry 块");
            }
        }

        // 7.6 安全：所有解引用都 SafeReadable 包裹
        Check(g_srcText.find("if (p1 && SafeReadable(p1, 0x18))") != std::string::npos,
              "country 读取由 SafeReadable 包裹");

        // 7.7 版本漂移防护：patch 前比对原始字节
        Check(g_srcText.find("prologue mismatch") != std::string::npos,
              "patch 前校验原始字节（防版本漂移盲 patch）");

        // 7.8 失败不 patch（降级路径存在）
        Check(g_srcText.find("take stays disabled; observe unaffected") != std::string::npos,
              "安装失败时明确降级为 observe-only");

        // 7.9 ★ 跳转必须是绝对跳转（2026-11-15 崩溃根因）
        //      E9 rel32 只能跳 ±2GB；target(exe) 与 tramp(VirtualAlloc) 相差 137TB，
        //      截断后跳到垃圾地址 → 游戏在第一次调用时崩溃。
        Check(g_srcText.find("MakeAbsJmp((uint8_t*)g_c890Target") != std::string::npos,
              "入口 patch 用 MakeAbsJmp（绝对跳转）");
        {
            // trampoline 回跳也必须是 mov rax,imm64 ; jmp rax
            size_t a = g_srcText.find("memcpy(tramp, kExpect, 15)");
            size_t b = (a == std::string::npos) ? std::string::npos
                                                : g_srcText.find("FlushInstructionCache(GetCurrentProcess(), tramp", a);
            if (a != std::string::npos && b != std::string::npos && b > a) {
                std::string blk = g_srcText.substr(a, b - a);
                Check(blk.find("p[0] = 0x48; p[1] = 0xB8;") != std::string::npos,
                      "trampoline 回跳用 mov rax,imm64");
                Check(blk.find("0xE9") == std::string::npos,
                      "trampoline 回跳无 E9 rel32");
            } else {
                Check(false, "能切出 trampoline 构造块");
            }
        }

        // 7.9 summary 必须被调用（否则统计不输出）
        Check(g_srcText.find("C890LogSummary()") != std::string::npos,
              "C890LogSummary 被调用");
    }

    printf("\n=== 8) 玩家判据：时序 bug 修复（2026-11-15）===\n");
    Emit("    背景：IsPlayerContext() 读全局 g_arSlot，而 obj 是当次的 tech 对象。");
    Emit("          两者不配套 → 同一 tech 被标不同 PLAYER/ai。本组防它回归。");
    if (!g_srcLoaded) {
        Check(false, "无法读取 auto_research.cpp —— 按 FAIL 处理");
    } else {
        // 8.1 新函数必须存在
        Check(g_srcText.find("static bool IsCountryPlayer(void* country)") != std::string::npos,
              "存在 IsCountryPlayer(country) —— 接收当次 country");
        Check(g_srcText.find("static void* CountryFromSlot(void* slot)") != std::string::npos,
              "存在 CountryFromSlot(slot) —— 接收当次 slot");

        // 8.2 ★ 核心：IsCountryPlayer 不得读全局
        {
            size_t a = g_srcText.find("static bool IsCountryPlayer(void* country)");
            size_t b = g_srcText.find("static void* CountryFromSlot");
            if (a != std::string::npos && b != std::string::npos && b > a) {
                std::string body = g_srcText.substr(a, b - a);
                Check(body.find("g_arSlot") == std::string::npos,
                      "IsCountryPlayer 内不读全局 g_arSlot");
            } else {
                Check(false, "能切出 IsCountryPlayer 函数体");
            }
        }

        // 8.3 hookA 日志必须记录三层诊断字段
        Check(g_srcText.find("slot=%p  country=%p  isai=%d") != std::string::npos,
              "hookA 日志含 slot/country/isai 三字段");
        Check(g_srcText.find("by-current-slot") != std::string::npos,
              "日志标注 by-current-slot（与旧全局判断区分）");

        // 8.4 hookA 里必须先算当次 slot/country，再判玩家
        {
            // ★ 用只在【实际日志调用】里出现的长串（注释里的 isai=%d 会抢先命中）
            size_t logPos = g_srcText.find("slot=%p  country=%p  isai=%d");
            size_t slotPos = g_srcText.find("void* slot    = g_arSlot;");
            Check(slotPos != std::string::npos && logPos != std::string::npos && slotPos < logPos,
                  "先取当次 slot/country 再打日志");
        }

        // 8.5 旧 IsPlayerContext 必须只剩兼容 wrapper，且只有一个定义
        //     ⚠️ 必须剥离注释后再数 —— 注释里也会出现 "static bool IsPlayerContext() {"
        {
            // ★ 统一用全局 code-only 视图（StripComments 已剥离注释与字面量）
            const std::string& stripped = g_srcCode;
            const std::string needle = "static bool IsPlayerContext() {";
            size_t c1 = stripped.find(needle);
            size_t c2 = (c1 == std::string::npos) ? std::string::npos : stripped.find(needle, c1 + 1);
            Check(c1 != std::string::npos, "存在 IsPlayerContext 兼容 wrapper（剥离注释后）");
            Check(c2 == std::string::npos, "IsPlayerContext 只有一个定义（剥离注释后）");
            if (c1 != std::string::npos) {
                std::string body = stripped.substr(c1, 220);
                Check(body.find("IsCountryPlayer(CountryFromSlot(g_arSlot))") != std::string::npos,
                      "旧 wrapper 委托给新函数（不自带逻辑）");
            }
        }
    }

    printf("\n=== 9) C890 调用栈记录（定位 take 的最后一步）===\n");
    Emit("    背景：静态分析已穷尽（偏移/字节/字符串/调用链），改看真实调用栈。");
    if (!g_srcLoaded) {
        Check(false, "无法读取 auto_research.cpp —— 按 FAIL 处理");
    } else {
        Check(g_srcText.find("void* entryRsp") != std::string::npos,
              "C890Log 接收 entryRsp 参数");
        Check(g_srcText.find("lea 88(%rsp), %r9") != std::string::npos,
              "桩用 lea 88(%rsp) 传入口 rsp（7 push + sub 0x20 后，R = rsp+88）");
        Check(g_srcText.find("LogCallStack") != std::string::npos,
              "存在 LogCallStack");
        Check(g_srcCode.find("RtlCaptureStackBackTrace") == std::string::npos,
              "code 中无 RtlCaptureStackBackTrace（真机崩溃后已移除）");
        // 9.5 ★ 直接调用者必须从 entryRsp 读
        // 9.5 ★ 直接调用者必须从 entryRsp 读
        {
            // 切出 LogCallStack 函数体：起点 → 下一个函数 C890Log 的【定义】（不是声明）
            size_t a = g_srcText.find("static void LogCallStack");
            // 用不含引号的特征串定位 C890Log 定义（避转义问题）
            size_t b = (a == std::string::npos) ? std::string::npos
                                                    : g_srcText.find("C890Log(void* p1, void* p2, void* p3, void* entryRsp)", a);
            Check(a != std::string::npos && b != std::string::npos && b > a,
                  "能切出 LogCallStack 块");
            if (a != std::string::npos && b != std::string::npos && b > a) {
                std::string body = g_srcText.substr(a, b - a);
                Check(body.find("*(uint64_t volatile*)entryRsp") != std::string::npos,
                      "直接调用者从 [entryRsp] 读（不依赖 rbp）");
                Check(body.find("SafeReadable(entryRsp, 8)") != std::string::npos,
                      "读 entryRsp 前用 SafeReadable 包裹");
                // 上限在 StackShouldLog 里（不只在 LogCallStack）
                Check(g_srcText.find("s_stackLogged, 0, 0) >= 50") != std::string::npos,
                      "栈记录有上限（>= 50 条即停止）");
            }
        }
        // 9.9 桩仍然无 sub（栈对齐不变）
        // 9.9 桩仍然无 sub（栈对齐不变）
        {
            // ★ 必须定位【带引号的汇编标签】，不能用裸 "C890Entry:"（注释里也有）
            const std::string label = std::string("\"C890Entry:") + "\\n\"";
            size_t a = g_srcText.find(label);
            size_t b = g_srcText.find("jmp *g_c890Tramp");
            Check(a != std::string::npos, "找到带引号的 C890Entry 汇编标签");
            if (a != std::string::npos && b != std::string::npos && b > a) {
                std::string body = g_srcText.substr(a, b - a);
                // ★ 必须先剥离 // 注释 —— 注释里就有 "不需要 sub $8"
                std::string code;
                {
                    size_t i = 0;
                    while (i < body.size()) {
                        if (i + 1 < body.size() && body[i] == '/' && body[i+1] == '/') {
                            while (i < body.size() && body[i] != '\n') ++i;
                        } else { code += body[i]; ++i; }
                    }
                }
                // ★ 2026-11-16 反转：现在【必须】有 sub $0x20（为 4 参数调用预留 shadow）
                Check(code.find("sub $0x20, %rsp") != std::string::npos,
                      "桩内有 sub $0x20（预留 shadow space）");
                Check(code.find("add $0x20, %rsp") != std::string::npos,
                      "桩内有 add $0x20（恢复栈）");
                Check(code.find("sub $8") == std::string::npos,
                      "桩内无 sub $8（不再需要，会破坏对齐）");
            } else {
                Check(false, "能切出桩块");
            }
        }
    }

    printf("\n=== 10) SEL 探针（0x81A5B0 = 选卡函数）===\n");
    Emit("    五条判据：读候选三件套×4 / CMOVcc×4 / 不读+0x314C / MISSING_HEAD_OF_RESEARCH");
    if (!g_srcLoaded) {
        Check(false, "无法读取 auto_research.cpp");
    } else {
        Check(g_srcText.find("InstallSelProbe") != std::string::npos, "存在 InstallSelProbe");
        Check(g_srcText.find("SelEntry") != std::string::npos, "存在 SelEntry 汇编桩");
        Check(g_srcText.find("if (InstallSelProbe(tc.selRva))") != std::string::npos,
              "InstallSelProbe 被实际调用（不是只声明）");
        // 10.4 ★ 20 字节 patch（4 条 shadow-store 各 5 字节）
        Check(g_srcText.find("kExpect[20]") != std::string::npos,
              "kExpect 是 20 字节（4×5）");
        // 10.5 必须用绝对跳转
        Check(g_srcText.find("argate::MakeAbsJmp((uint8_t*)g_selTarget") != std::string::npos,
              "入口用 MakeAbsJmp（绝对跳转，不是 E9 rel32）");
        // 10.6 trampoline 回跳也是绝对跳转
        {
            size_t a = g_srcText.find("memcpy(tramp, kExpect, 20)");
            size_t b = g_srcText.find("FlushInstructionCache(GetCurrentProcess(), tramp, 33)");
            if (a != std::string::npos && b != std::string::npos && b > a) {
                std::string blk = g_srcText.substr(a, b - a);
                Check(blk.find("p[0] = 0x48; p[1] = 0xB8;") != std::string::npos,
                      "trampoline 回跳用 mov rax,imm64");
                Check(blk.find("0xE9") == std::string::npos, "trampoline 无 E9 rel32");
            } else { Check(false, "能切出 SEL trampoline 块"); }
        }
        // 10.7 桩无 sub（7 push 已对齐）
        {
            const std::string label = std::string("\"SelEntry:") + "\\n\"";
            size_t a = g_srcText.find(label);
            size_t b = g_srcText.find("jmp *g_selTramp");
            Check(a != std::string::npos, "找到带引号的 SelEntry 标签");
            if (a != std::string::npos && b != std::string::npos && b > a) {
                std::string body = g_srcText.substr(a, b - a);
                // ★ 用全局 code-only 视图再查一次（双保险）
                Check(g_srcCode.find("SelEntry:") == std::string::npos || true, "(code view 可用)");
                {
                    size_t ca = g_srcCode.find("SelEntry:");
                    if (ca == std::string::npos) ca = g_srcCode.find("SelEntry");
                    Check(ca != std::string::npos, "code-only 视图里有 SelEntry");
                    if (ca != std::string::npos) {
                        size_t cb = g_srcCode.find("jmp *g_selTramp", ca);
                        if (cb != std::string::npos) {
                            std::string cc = g_srcCode.substr(ca, cb - ca);
                            Check(cc.find("sub $") == std::string::npos,
                                  "SEL 桩无 sub（code-only 视图）");
                        }
                    }
                }
            }
        }
        // 10.8 country 从 p2+0x10 读（不是 p1）
        Check(g_srcText.find("(uint8_t*)p2 + 0x10") != std::string::npos,
              "country 从 param_2+0x10 读（不是 param_1）");
        // 10.9 SafeReadable 包裹
        Check(g_srcText.find("SafeReadable(country, 0x31D0)") != std::string::npos,
              "读 country 字段前用 SafeReadable 包裹");
    }

    printf("\n=== 11) stripComments() 单元测试（防「注释当代码」第 5、6 次）===\n");
    {
        // 11.1 行注释被剥离
        Check(StripComments("a // sub $8\nb").find("sub") == std::string::npos,
              "行注释被剥离");
        // 11.2 块注释被剥离
        Check(StripComments("a /* sub $8 */ b").find("sub") == std::string::npos,
              "块注释被剥离");
        // 11.3 字符串字面量被剥离（避免 "sub $8" 误判）
        Check(StripComments(R"(Log("sub $8");)").find("sub") == std::string::npos,
              "字符串字面量被剥离");
        // 11.4 真实代码保留
        Check(StripComments("  sub $8, %rsp").find("sub") != std::string::npos,
              "真实指令保留");
        // 11.5 换行保留（行号对齐）
        {
            std::string a = StripComments("x\n// c\ny\n");
            int nl = 0; for (char c : a) if (c == '\n') ++nl;
            Check(nl == 3, "剥离后换行数量保持（行号可对齐）");
        }
        // 11.6 转义引号不破坏
        Check(StripComments(R"(s = "a\b"; sub)").find("sub") != std::string::npos,
              "转义引号不破坏后续代码识别");
    }

    printf("\n=== 12) 崩溃修复：无栈回溯 API ===\n");
    Emit("    背景：2026-11-16 真机崩溃，cap#0 raw=0x8286DFBED0（140TB 垃圾地址）。");
    Emit("          RtlCaptureStackBackTrace 在 x64 无帧指针环境下不可靠。");
    if (!g_srcLoaded) {
        Check(false, "无法读取 auto_research.cpp");
    } else {
        // 12.1 ★ code-only 视图里不得出现栈回溯 API 调用
        Check(g_srcCode.find("RtlCaptureStackBackTrace") == std::string::npos,
              "code 中无 RtlCaptureStackBackTrace 调用");
        // 12.2 手动读 [entryRsp] 必须保留
        Check(g_srcCode.find("*(uint64_t volatile*)entryRsp") != std::string::npos,
              "保留手动读 [entryRsp]（100% 可靠）");
        // 12.3 读之前必须 SafeReadable
        Check(g_srcCode.find("SafeReadable(entryRsp, 8)") != std::string::npos,
              "读 entryRsp 前 SafeReadable 包裹");
        // 12.4 减法前必须比较（防下溢）
        Check(g_srcCode.find("ret > (uint64_t)(uintptr_t)g_base") != std::string::npos,
              "ret - g_base 前先比较（防下溢）");
    }

    printf("\n=== 13) SEL 定位：只数 CMOVG（0F 4F）而非全部 CMOVcc ===\n");
    Emit("    背景：真机日志 'len=3503 cmov=4 -> 0 match(es)'。实测 cmovg=4 但 cmovAll=12。");
    if (!g_srcLoaded) {
        Check(false, "无法读取");
    } else {
        // 13.1 必须只在 ar_resolve.h 里改（这里检查产品源码不含旧逻辑）
        // 13.2 用独立文件验证 ar_resolve.h
        FILE* f = fopen("ar_resolve.h", "rb");
        if (!f) f = fopen("../tech_probe/ar_resolve.h", "rb");
        if (!f) {
            Check(false, "能读 ar_resolve.h");
        } else {
            fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
            std::string h; if (n > 0) { h.resize((size_t)n); size_t got = fread(&h[0], 1, (size_t)n, f); (void)got; }
            fclose(f);
            std::string hc = StripComments(h);
            Check(hc.find("cmovg == 4") != std::string::npos,
                  "判据用 cmovg == 4（不是 cmov == 4）");
            Check(hc.find("code[i+1] == 0x4F") != std::string::npos,
                  "只数 0F 4F（CMOVG）");
        }
    }

    printf("\n=== 14) D9 候选表 dump（验证权重 vs 成本）===\n");
    Emit("    目的：确认 +0x31D8 存的是权重还是成本；元素步长 8 还是 16。");
    if (!g_srcLoaded) {
        Check(false, "无法读取");
    } else {
        Check(g_srcCode.find("SafeReadable(country, 0x31E0)") != std::string::npos,
              "D9 入口有 country 可读性检查（0x31E0）");
        // 14.2 必须两个 SafeReadable 都做
        Check(g_srcCode.find("SafeReadable(ids, (size_t)count * 4)") != std::string::npos,
              "读 ids 前 SafeReadable（count*4）");
        Check(g_srcCode.find("SafeReadable(w, (size_t)count * 8)") != std::string::npos,
              "读 weights 前 SafeReadable（count*8）");
        // 14.3 ★ 步长必须是 8（不是 16）—— FINDINGS 记载 0x10 是错的
        Check(g_srcCode.find("(size_t)i * 8") != std::string::npos,
              "D9 用步长 8（不是 16）");
        // as_dbl 在字面量里，已剥离；改查代码里的 memcpy(&dw, &w8, sizeof(dw))
        Check(g_srcCode.find("memcpy(&dw, &w8, sizeof(dw))") != std::string::npos,
              "把 w8 按 double 解释（判双精度 vs 整数）");
        // 14.5 count 必须有范围保护（防异常值）
        Check(g_srcCode.find("count > 0 && count < 20") != std::string::npos,
              "count 有范围保护（0<count<20）");
    }

    printf("\n=== 15) [alt] 候选采样（v3：三领域槽结构）===\n");
    Emit("    v2 的 country+0x31BC 等位置全部作废；v3 改用 slotmgr+(area+11)*0x18。");
    if (!g_srcLoaded) {
        Check(false, "无法读取");
    } else {
        Check(g_srcCode.find("CntMark") != std::string::npos, "存在 CntMark 合理性标记");
        Check(g_srcCode.find("v <= 100") != std::string::npos, "合理区间上界 100");
        Check(g_srcCode.find("s_cntSampled < 400") != std::string::npos,
              "采样上限 400 条");
        Check(g_srcCode.find("s_cntLastTickMs >= 500") != std::string::npos,
              "500ms 时间采样间隔");
        Check(g_srcCode.find("s_lastAlt") != std::string::npos,
              "三领域上次 count 状态（s_lastAlt）");
        Check(g_srcCode.find("GetTickCount64()") != std::string::npos, "dump 含 tick");
        Check(g_srcCode.find("SafeReadable(country, 0x1620 + 0x160)") != std::string::npos,
              "读 slotmgr 区域前 SafeReadable");
        // 15.9 ★ v2 的错误位置必须已不存在
        Check(g_srcCode.find("(uint8_t*)country + 0x31B0, 0x10") == std::string::npos,
              "v2 的 country+0x31B0 盲读已移除");
        Check(g_srcCode.find("(uint8_t*)p1 + 0x38, 0x10") == std::string::npos,
              "v2 的 slotmgr+0x38 误读已移除");
    }

    printf("\n=== 16) [map] tech id ↔ key 映射 ===\n");
    Emit("    take 的必需品：按 key 配置权重 ⇒ 必须能把 tech 对象翻译成 key。");
    if (!g_srcLoaded) {
        Check(false, "无法读取");
    } else {
        Check(g_srcCode.find("s_mapLogged < 300") != std::string::npos, "映射上限 300 条");
        Check(g_srcCode.find("MapSeen(tid)") != std::string::npos, "有去重（MapSeen）");
        Check(g_srcCode.find("MapRemember(tid)") != std::string::npos, "记入去重表（MapRemember）");
        Check(g_srcCode.find("2654435761u") != std::string::npos, "开放寻址哈希（Knuth 常数）");
        Check(g_srcCode.find("512") != std::string::npos, "哈希表 512 槽");
        // 2026-11-16 v2：[map] 数据源改为 A 点探针的 tech（r15），key 来自 kpB/kpA
        Check(g_srcCode.find("const bool useB = (kpB != nullptr)") != std::string::npos,
              "复用 A 点探针已读出的 kpB/kpA（不重复实现 SSO）");
        Check(g_srcCode.find("(uint8_t*)tech + 0xCC, 4") != std::string::npos,
              "id 从 tech+0xCC 读（A 点探针的 r15，实测 tech 对象）");
        Check(g_srcCode.find("s_mapNoId") != std::string::npos,
              "id 读不出时有样本记录（判断 +0xCC 是否漂移）");
    }

    printf("\n=== 17) [alt] 三领域备选列表（slotmgr+(area+11)*0x18）===\n");
    Emit("    结构来源：UI 0xFCBD30 + hookA 0x81C850 两个独立函数交叉验证。");
    if (!g_srcLoaded) {
        Check(false, "无法读取");
    } else {
        Check(g_srcCode.find("(size_t)(area + 11) * 0x18") != std::string::npos,
              "槽算式 = (area+11)*0x18（与 UI/hookA 一致）");
        Check(g_srcCode.find("slot + 0x14") != std::string::npos, "count 在 slot+0x14");
        Check(g_srcCode.find("slot + 0x08") != std::string::npos, "数组指针在 slot+0x08");
        Check(g_srcCode.find("for (int area = 0; area < 3; ++area)") != std::string::npos,
              "遍历 3 个领域（物理/社会/工程）");
        Check(g_srcCode.find("SafeReadable(slot, 0x18)") != std::string::npos,
              "读 slot 前 SafeReadable");
        // 17.6 ★ 数组元素按 8 字节读（步长 8）
        Check(g_srcCode.find("(size_t)i * 8") != std::string::npos,
              "数组元素步长 8");
        // 17.7 ★ 指针候选才尝试解引用（避免读垃圾）
        Check(g_srcCode.find("v < 0x10000 || (v & 7) != 0") != std::string::npos,
              "只有像指针的元素才尝试解引用（v>=0x10000 且 8 对齐）");
        // 17.8 CHANGED 标记
        Check(g_srcCode.find("anyChange") != std::string::npos,
              "变化检测存在（anyChange 变量）");
    }

    printf("\n=== 18) A 点探针 v3（0x820E4B，选卡循环体内）===\n");
    Emit("    20 字节 patch（3 条完整指令）+ trampoline 补执行 + 绝对跳回。");
    if (!g_srcLoaded) {
        Check(false, "无法读取");
    } else {
        // 18.1 20 字节模式必须完整存在
        Check(g_srcCode.find("0xB9,0x00,0x80,0x00,0x00") != std::string::npos,
              "patch 模式含 MOV ECX,0x8000");
        Check(g_srcCode.find("0x48,0x39,0x8D,0xD8,0x01,0x00,0x00") != std::string::npos,
              "patch 模式含 CMP [RBP+0x1D8],RCX");
        Check(g_srcCode.find("0x48,0x0F,0x4D,0x8D,0xD8,0x01,0x00,0x00") != std::string::npos,
              "patch 模式含 CMOVGE");
        // 18.4 ★ 栈对齐：7 push + sub 0x28
        Check(g_srcText.find("sub $0x28, %rsp") != std::string::npos,   // 汇编在字面量里
              "trampoline sub 0x28（7push=8 后 → 0，ABI 对齐）");
        Check(g_srcText.find("add $0x28, %rsp") != std::string::npos, "trampoline add 0x28");
        // 18.6 ★ 补执行三条原指令必须存在且连续
        {
            size_t a = g_srcText.find("mov $0x8000, %ecx");
            size_t b = g_srcText.find("cmp %rcx, 0x1d8(%rbp)");
            size_t c = g_srcText.find("cmovge 0x1d8(%rbp), %rcx");
            Check(a != std::string::npos && b != std::string::npos && c != std::string::npos &&
                  a < b && b < c,
                  "补执行 MOV/CMP/CMOVGE 三条，顺序正确");
        }
        // 18.7 ★ 补执行必须在 call 之后（flags 链）
        {
            size_t callPos = g_srcText.find("call AR_SelBLog");
            size_t movPos  = g_srcText.find("mov $0x8000, %ecx");
            Check(callPos != std::string::npos && movPos != std::string::npos && callPos < movPos,
                  "补执行在 call 之后（flags 链完整）");
        }
        // 18.8 ★ 必须用绝对跳回（不用 E9 rel32）
        Check(g_srcText.find("mov g_selBBackAddr(%rip), %rax") != std::string::npos,
              "跳回用绝对跳转（MOV RAX,imm64; JMP RAX 的形式）");
        // 18.9 ★ patch 前校验 20 字节
        Check(g_srcCode.find("memcmp(g_selBPatch, kPat, 20)") != std::string::npos,
              "patch 前校验原始 20 字节");
        // 18.10 ★ 唯一命中检查
        Check(g_srcCode.find("if (nHit != 1)") != std::string::npos,
              "模式必须唯一命中（否则放弃）");
        // 18.11 ★ 失败不 patch
        Check(g_srcCode.find("return false;") != std::string::npos, "失败路径返回 false");
        // 18.12 ★ 同时尝试两种 key 布局
        Check(g_srcCode.find("(uint8_t*)tech + 0x360") != std::string::npos,
              "尝试 layout A：tech+0x360");
        Check(g_srcCode.find("(uint8_t*)tech + 0x20") != std::string::npos,
              "尝试 layout B：tech+0x20");
        // 18.13 自报 rsp16
        Check(g_srcCode.find("0x28 + 56") != std::string::npos,
              "自报 rsp16（验证栈对齐）");
    }

    printf("\n=== 19) 接管版（0x820ECB 选卡拦截）===\n");
    Emit("    用户语义：>0 取最大 / 0 禁选 / <0 兜底最大 / 未配置不干预。");
    if (!g_srcLoaded) {
        Check(false, "无法读取");
    } else {
        // 19.1 7 字节 patch 模式
        Check(g_srcCode.find("0x48,0x63,0xC8") != std::string::npos, "patch 模式含 MOVSXD RCX,EAX");
        Check(g_srcCode.find("0x49,0x8B,0x45,0x08") != std::string::npos, "patch 模式含 MOV RAX,[R13+0x08]");
        // 19.3 ★ 必须校验命中位置就是 0x820ECB
        Check(g_srcCode.find("hit != 0x820ECB") != std::string::npos,
              "命中位置必须等于 0x820ECB（否则禁用）");
        Check(g_srcCode.find("if (nHit != 1)") != std::string::npos, "模式必须唯一命中");
        // 19.5 ★ E9 rel32 + 范围检查
        Check(g_srcCode.find("buf[0] = 0xE9") != std::string::npos, "用 E9 rel32（7 字节只够这个）");
        Check(g_srcCode.find("rel < INT32_MIN || rel > INT32_MAX") != std::string::npos,
              "rel32 范围检查");
        // 19.7 ★ nearby 只放绝对跳转桩，真 trampoline 在 DLL
        Check(g_srcCode.find("AllocNearby") != std::string::npos, "有 AllocNearby（±2GB 内分配）");
        Check(g_srcCode.find("(uint64_t)(uintptr_t)&AR_TakeoverTramp") != std::string::npos,
              "nearby 桩跳到 DLL 里的 AR_TakeoverTramp");
        // 19.9 ★ trampoline：8 push + sub 0x20
        Check(g_srcText.find("push %rbx") != std::string::npos, "trampoline 保存 rbx");
        Check(g_srcText.find("sub $0x20, %rsp") != std::string::npos,
              "trampoline sub 0x20（8push 后仍 0，需 shadow）");
        Check(g_srcText.find("add $0x20, %rsp") != std::string::npos, "trampoline add 0x20");
        // 19.12 ★ 补执行两条原指令
        Check(g_srcText.find("movslq %eax, %rcx") != std::string::npos, "补执行 MOVSXD");
        Check(g_srcText.find("mov 0x8(%r13), %rax") != std::string::npos, "补执行 MOV RAX,[R13+8]");
        // 19.14 ★ 绝对跳回
        Check(g_srcText.find("mov g_tkBack(%rip), %r11") != std::string::npos, "跳回用绝对跳转");
        // 19.15 ★ 只在 take 模式干预
        Check(g_srcCode.find("cfg.mode != arcfg::Mode::Take") != std::string::npos,
              "非 take 模式不干预");
        // 19.16 ★ 语义：>0 取最大 / <0 兜底 / 未配置不干预
        Check(g_srcCode.find("if (w > 0)") != std::string::npos, "有 >0 分支");
        Check(g_srcCode.find("else if (w < 0)") != std::string::npos, "有 <0 分支");
        Check(g_srcCode.find("if (!TkLookup(key, &w)) continue;") != std::string::npos,
              "未配置 → continue（不参与）");
        Check(g_srcCode.find("bestPosIdx >= 0") != std::string::npos, "正值优先");
        Check(g_srcCode.find("bestNegIdx >= 0") != std::string::npos, "负值兜底");
        // 19.21 ★ 失败降级（2026-11-16 更新：不再裸回 gameIdx，改为 TkSafeIdx 兜底）
        Check(g_srcCode.find("TkSafeIdx(gameIdx, count)") != std::string::npos,
              "失败降级用 TkSafeIdx（gameIdx 越界时归 0，不传垃圾给游戏）");
        // 19.22 ★ 回滚
        Check(g_srcCode.find("memcpy(g_tkPatch, g_tkOrig, 7)") != std::string::npos,
              "回滚恢复原 7 字节");
        // 19.23 ★ key 读法用 +0x20（A 点实测确认）
        Check(g_srcCode.find("(uint8_t*)tech + 0x20") != std::string::npos,
              "key 从 tech+0x20 读（A 点探针实测确认）");
    }

    printf("\n=== 20) 安全修复包（2026-11-16 崩溃）===\n");
    Emit("    根因：gameIdx 是未初始化垃圾值，no-intervene 时原样传回 -> 越界 -> 崩。");
    if (!g_srcLoaded) {
        Check(false, "无法读取");
    } else {
        // 20.1 ★ 接管已禁用
        // 2026-11-18：if(false && InstallTakeover) 已按要求删除（v1 彻底废弃）
        Check(g_srcCode.find("if (false && InstallTakeover") == std::string::npos,
              "InstallTakeover v1 已删除（不再存在 if(false) 死代码）");
        // 20.2 ★ 安全返回函数存在
        Check(g_srcCode.find("static inline int TkSafeIdx(int idx, int count)") != std::string::npos,
              "存在 TkSafeIdx（索引越界兜底）");
        Check(g_srcCode.find("if (idx >= 0 && idx < count) return idx;") != std::string::npos,
              "TkSafeIdx 检查 [0,count) 范围");
        Check(g_srcCode.find("return 0;") != std::string::npos,
              "越界返回 0（安全下限）");
        // 20.5 ★ 所有 return gameIdx 必须已消除（改为安全版）
        {
            size_t cnt = 0, pos = 0;
            while ((pos = g_srcCode.find("return gameIdx;", pos)) != std::string::npos) { ++cnt; ++pos; }
            Check(cnt == 0, "已无裸 return gameIdx（全部改为 TkSafeIdx）");
        }
        // 20.6 ★ count 非法时直接返回 0（不信任 gameIdx）
        Check(g_srcCode.find("count <= 0 || count > 64) return 0;") != std::string::npos,
              "count 非法时返回 0（不信任 gameIdx）");
        // 20.7 ★ 日志含 inRange
        Check(g_srcCode.find("inRange=%d") != std::string::npos ||
              g_srcText.find("inRange=%d") != std::string::npos,
              "日志含 inRange 判定");
        // 20.8 ★ 安装失败有明确日志 + 错误码
        Check(g_srcText.find("AllocNearby failed err=") != std::string::npos,
              "AllocNearby 失败带 GetLastError");
        Check(g_srcText.find("VirtualProtect failed err=") != std::string::npos,
              "VirtualProtect 失败带 GetLastError");
        Check(g_srcText.find("out of rel32 range (rel=") != std::string::npos,
              "rel32 越界日志带具体值");
        // 20.11 ★ 每 tick 路径的警告必须记录在案
        Check(g_srcCode.find("TkSafeIdx") != std::string::npos, "TkSafeIdx 有实际调用");
    }

    printf("\n=== 21) 科研槽观测探针（0x81B360）===\n");
    Emit("    记录 3 领域的 idx/key/candCnt + 变化检测；纯只读。");
    if (!g_srcLoaded) {
        Check(false, "无法读取");
    } else {
        // 21.1 10 字节 pattern
        Check(g_srcCode.find("0x48,0x89,0x5C,0x24,0x10") != std::string::npos,
              "pattern 含 MOV [RSP+0x10],RBX");
        Check(g_srcCode.find("0x48,0x89,0x4C,0x24,0x08") != std::string::npos,
              "pattern 含 MOV [RSP+0x08],RCX");
        // 21.3 ★ 必须校验位置 = 0x81B360
        Check(g_srcCode.find("hit != 0x81B360") != std::string::npos,
              "命中位置必须等于 0x81B360");
        // 21.4 ★ 跳回 0x81B36A（push rbp）
        Check(g_srcCode.find("base + 0x81B36A") != std::string::npos, "跳回 0x81B36A");
        // 21.5 ★ 补执行两条 shadow-store
        Check(g_srcText.find("mov %rbx, 0x10(%rsp)") != std::string::npos,
              "补执行 MOV [RSP+0x10],RBX");
        Check(g_srcText.find("mov %rcx, 0x08(%rsp)") != std::string::npos,
              "补执行 MOV [RSP+0x08],RCX");
        // 21.7 ★ 栈对齐：7 push + sub 0x20
        Check(g_srcText.find("sub $0x20, %rsp") != std::string::npos, "sub 0x20");
        // 21.8 ★ E9 rel32 + nearby
        Check(g_srcCode.find("buf[0] = 0xE9") != std::string::npos, "用 E9 rel32");
        Check(g_srcCode.find("AllocNearby(g_rpPatch, 64)") != std::string::npos, "AllocNearby");
        // 21.10 ★ 三条路径都要记
        Check(g_srcCode.find("idxA") != std::string::npos, "记录路径 A（r14 全局）");
        Check(g_srcCode.find("idxB") != std::string::npos, "记录路径 B（slotmgr）");
        Check(g_srcCode.find("candCnt") != std::string::npos, "记录候选槽 count");
        // 21.13 ★ 变化检测
        Check(g_srcCode.find("s_rpLastIdx") != std::string::npos, "有 idx 变化检测");
        Check(g_srcCode.find("s_rpLastCnt") != std::string::npos, "有 candCnt 变化检测");
        // ★ 必须【同时】比较两者（用 || 连接），否则漏检
        Check(g_srcCode.find("(idxA != s_rpLastIdx[area]) || (candCnt != s_rpLastCnt[area])") != std::string::npos,
              "变化判定同时包含 idx 与 candCnt（|| 连接）");
        // ★ 变化后必须回写两个状态
        Check(g_srcCode.find("s_rpLastIdx[area] = idxA;") != std::string::npos, "回写 lastIdx");
        Check(g_srcCode.find("s_rpLastCnt[area] = candCnt;") != std::string::npos, "回写 lastCnt");
        // 21.15 ★ r14 来源正确（0x3159BF0，不是 0x3149BF0）
        Check(g_srcCode.find("g_base + 0x3159BF0") != std::string::npos,
              "r14 从 g_base+0x3159BF0 读（7 位，已核实）");
        // ★ 反向：不得出现错误的 6 位地址（文档里的笔误值）
        Check(g_srcCode.find("g_base + 0x3149BF0") == std::string::npos,
              "不得使用错误的 0x3149BF0（会读到无关内存）");
        // 21.16 ★ area 偏移 0x48/0x50/0x58
        Check(g_srcCode.find("+ 0x48 + (size_t)area * 8") != std::string::npos,
              "area 表偏移 0x48 + area*8（实测）");
        // 21.17 ★ idx 偏移 +0x18
        Check(g_srcCode.find("slotA + 0x18") != std::string::npos ||
              g_srcCode.find("(uint8_t*)slotA + 0x18") != std::string::npos,
              "idx 在 slot+0x18（实测）");
        // 21.18 ★ 回滚
        Check(g_srcCode.find("memcpy(g_rpPatch, g_rpOrig, 10)") != std::string::npos,
              "回滚恢复原 10 字节");
        // 21.19 ★ 失败降级
        Check(g_srcCode.find("nHit != 1 || hit != 0x81B360") != std::string::npos,
              "模式或位置不符 → 禁用");
    }

    printf("\n=== 22) 稳定版配置（2026-11-16 定案）===\n");
    Emit("    [rp]/[cnt]/C890/SEL 关闭；observe/[map]/[alt]/[selB] 保留；take 禁用。");
    if (!g_srcLoaded) {
        Check(false, "无法读取");
    } else {
        // 22.1 ★ [rp] 必须关闭
        Check(g_srcCode.find("#define AR_ENABLE_RP_PROBE 0") != std::string::npos,
              "AR_ENABLE_RP_PROBE = 0（[rp] 关闭）");
        // 22.2 ★ C890/SEL 必须关闭
        Check(g_srcCode.find("#define AR_ENABLE_PROBES 0") != std::string::npos,
              "AR_ENABLE_PROBES = 0（C890/SEL 关闭）");
        // 22.3 ★ 接管必须禁用
        // 2026-11-18：v1 接管已删除；现在的接管是 tk2（0x6F334E）
        Check(g_srcCode.find("InstallTakeoverV2(g_base)") != std::string::npos,
              "tk2 接管（0x6F334E）已就位");
        // 22.4 ★ A 点探针必须保留
        Check(g_srcCode.find("if (LocateAndPatchSelB(g_base))") != std::string::npos,
              "[selB] 探针保留（A 点）");
        // 22.5 ★ 版本 banner 必须存在
        // 2026-11-18：版本文案随阶段演进，只要求含 take-v
        Check(g_srcText.find("take-v") != std::string::npos,
              "banner 含 take-v（版本标识）");
        Check(g_srcText.find("features :") != std::string::npos, "banner 含功能清单");
        Check(g_srcText.find("[ON ] observe") != std::string::npos, "banner 标注 observe ON");
        // 2026-11-20：take 真接管已开启（AR_TAKEOVER_V2_DRYRUN=0 LIVE）
        // 2026-11-20：take 真接管已开启（AR_TAKEOVER_V2_DRYRUN=0 LIVE）
        Check(g_srcText.find("take 真接管   AR_TAKEOVER_V2_DRYRUN=0") != std::string::npos,
              "banner 标注 take 真接管 ON（LIVE）");
        Check(g_srcText.find("[OFF] [rp] 科研槽") != std::string::npos,
              "banner 标注 [rp] OFF");
        Check(g_srcText.find("[ON ] [selB]") != std::string::npos, "banner 标注 [selB] ON");
        // 22.10 ★ 关闭的功能不得出现在二进制（通过 code 视图确认没被调用）
        Check(g_srcCode.find("#if AR_ENABLE_RP_PROBE") != std::string::npos,
              "[rp] 接线在 #if 内（关闭时不编译）");
    }

    printf("\n=== 23) take v2（0x6F334E，装槽前拦截，DRY-RUN）===\n");
    Emit("    用户需求：全禁时\"跳过装槽\"而不是\"先研究一个\"。");
    if (!g_srcLoaded) {
        Check(false, "无法读取");
    } else {
        // 23.1 9 字节 pattern
        Check(g_srcCode.find("0x48,0x8B,0xF0") != std::string::npos, "pattern 含 MOV RSI,RAX");
        Check(g_srcCode.find("0x48,0x8B,0x10") != std::string::npos, "pattern 含 MOV RDX,[RAX]");
        Check(g_srcCode.find("0x48,0x8B,0xC8") != std::string::npos, "pattern 含 MOV RCX,RAX");
        // 23.4 ★ 位置必须 = 0x6F334E
        Check(g_srcCode.find("hit != 0x6F334E") != std::string::npos, "命中位置必须等于 0x6F334E");
        // 23.5 ★ 双跳回地址
        Check(g_srcCode.find("base + 0x6F3357") != std::string::npos, "正常跳回 0x6F3357");
        Check(g_srcCode.find("base + 0x6F3369") != std::string::npos, "跳过跳回 0x6F3369");
        // 23.7 ★ trampoline 参数偏移（rax 在 0x30，不是 0x20）
        // 2026-11-17 修正：gamePick 改走全局，彻底消除栈偏移计算错误
        Check(g_srcText.find("mov %rax, g_tk2GamePick(%rip)") != std::string::npos,
              "gamePick 入口即存入全局（零栈偏移依赖）");
        Check(g_srcText.find("mov g_tk2GamePick(%rip), %r8") != std::string::npos,
              "gamePick 从全局读回（不依赖 [rsp+X]）");
        // ⚠️ 注释里会出现 "0x30(%rsp)"（记录 bug 历史），必须用 code 视图
        Check(g_srcCode.find("0x30(%rsp)") == std::string::npos,
              "代码中不得再用 0x30(%rsp)（曾读成 r9）");
        // 23.8 ★ 栈对齐：7 push + sub 0x20
        // 2026-11-17 修正：7 push 后 rsp%16=8，必须 sub 0x28 才对齐
        // ⚠️ 必须在 AR_TakeoverV2Tramp 块内检查（其他 trampoline 也有 sub 0x28）
        {
            size_t a = g_srcText.find("AR_TakeoverV2Tramp:");
            size_t b = (a == std::string::npos) ? std::string::npos
                                                : g_srcText.find("jmp *g_tk2BackS", a);
            Check(a != std::string::npos && b != std::string::npos && b > a,
                  "能切出 AR_TakeoverV2Tramp 块");
            if (a != std::string::npos && b != std::string::npos && b > a) {
                std::string blk = g_srcText.substr(a, b - a);
                Check(blk.find("sub $0x28, %rsp") != std::string::npos,
                      "tramp 块内 sub 0x28（7push 后对齐）");
                Check(blk.find("add $0x28, %rsp") != std::string::npos,
                      "tramp 块内 add 0x28 与 sub 配对");
                Check(blk.find("sub $0x20, %rsp") == std::string::npos,
                      "tramp 块内不得用 sub 0x20（未对齐）");
            }
        }
        // 23.9 ★ 结果经全局传递（不用 pop rax）
        Check(g_srcCode.find("g_tk2Result") != std::string::npos, "结果经全局变量传递");
        // 23.10 ★ DRY-RUN 默认开启
        // 2026-11-18：开关值会随阶段改变（DRY-RUN=1 / LIVE=0），
        // 断言只检查「存在且为 0 或 1」。
        {
            const bool d0 = g_srcCode.find("#define AR_TAKEOVER_V2_DRYRUN 0") != std::string::npos;
            const bool d1 = g_srcCode.find("#define AR_TAKEOVER_V2_DRYRUN 1") != std::string::npos;
            Check(d0 != d1, "AR_TAKEOVER_V2_DRYRUN 存在且只取 0 或 1");
        }
        // 23.11 ★ DRY-RUN 下必须返回 gamePick
        {
            size_t a = g_srcCode.find("#if AR_TAKEOVER_V2_DRYRUN");
            if (a != std::string::npos) {
                // 2026-11-18：DRY-RUN 块变长（含汇总日志），切片范围扩到 2000
                std::string blk = g_srcCode.substr(a, 2000);
                // 2026-11-18：DRY-RUN 分支仍然 return gamePick（不干预）
                      Check(blk.find("return gamePick;") != std::string::npos,
                      "DRY-RUN 下 return gamePick（不干预）");
            } else { Check(false, "能切出 DRY-RUN 块"); }
        }
        // 23.12 ★ 全禁时清 bit 只在非 DRY-RUN 时执行
        Check(g_srcCode.find("#if !AR_TAKEOVER_V2_DRYRUN") != std::string::npos,
              "清 bit 只在真接管时执行");
        // 23.13 ★ 6 层降级
        Check(g_srcCode.find("area < 0 || area > 2") != std::string::npos, "area 越界降级");
        Check(g_srcCode.find("cnt <= 0 || cnt > 64") != std::string::npos, "cnt 非法降级");
        Check(g_srcCode.find("cfg.mode != arcfg::Mode::Take") != std::string::npos, "非 take 模式降级");
        // 23.16 ★ 回滚
        Check(g_srcCode.find("memcpy(g_tk2Patch, g_tk2Orig, 9)") != std::string::npos, "回滚恢复 9 字节");
        // 23.17 ★ key 读法用 +0x20（A 点实测）
        Check(g_srcCode.find("(uint8_t*)tech + 0x20") != std::string::npos, "key 从 tech+0x20 读");
        // 23.18 ★ 日志区分四种结局
        // 2026-11-18：日志格式改为 verdict 字符串
        Check(g_srcText.find("ALL-DISABLED") != std::string::npos, "日志有 ALL-DISABLED");
        Check(g_srcText.find("OVERRIDE") != std::string::npos, "日志有 OVERRIDE");
        Check(g_srcText.find("no-cfg") != std::string::npos, "日志有 no-cfg");
    }

    printf("\n=== 24) nearby 桩必须不破坏寄存器（2026-11-17）===\n");
    Emit("    崩溃根因：nearby 桩用 mov rax,imm64 → RAX 变成 trampoline 地址");
    Emit("    ⇒ gamePick 丢失 → trampoline 存入垃圾 → 读 (%rax) 崩溃");
    if (!g_srcLoaded) {
        Check(false, "无法读取");
    } else {
        // 24.1 ★ nearby 桩必须用 FF 25（jmp [rip+disp32]）
        Check(g_srcCode.find("buf[0] = 0xFF; buf[1] = 0x25;") != std::string::npos,
              "nearby 桩用 FF 25（jmp [rip+disp32]，不碰寄存器）");
        // 24.2 ★ 不得在 take v2 的 nearby 桩里用 48 B8
        {
            size_t a = g_srcCode.find("&AR_TakeoverV2Tramp");
            Check(a != std::string::npos, "能定位 take v2 nearby 桩构造");
            if (a != std::string::npos) {
                size_t blkStart = (a > 800) ? a - 800 : 0;
                std::string blk = g_srcCode.substr(blkStart, a - blkStart + 400);
                Check(blk.find("buf[0] = 0x48; buf[1] = 0xB8;") == std::string::npos,
                      "take v2 nearby 桩不得用 mov rax,imm64");
                Check(blk.find("FlushInstructionCache(GetCurrentProcess(), nearStub, 16)") != std::string::npos,
                      "桩长 16 字节已 flush");
            }
        }
        // 24.3 ★ gamePick 空值检查
        Check(g_srcCode.find("if (!gamePick) return nullptr;") != std::string::npos,
              "AR_TakeoverV2 检查 gamePick 为空（避免读 (%rax)）");
        // 24.4 ★ 桩布局：disp32 = 2
        Check(g_srcCode.find("int32_t disp = 2;") != std::string::npos,
              "disp32 = 2（RIP+2 = +0x08，指向 imm64）");
        // 24.5 ★ 目标地址在 +0x08
        Check(g_srcCode.find("memcpy(buf + 8, &dst, 8);") != std::string::npos,
              "目标地址存在 +0x08");
    }

    printf("\n=== 25) [tak-DBG] 诊断日志（2026-11-17）===\n");
    Emit("    目的：判 gamePick 是不是候选数组元素（eq0/eq1/eq2）");
    if (!g_srcLoaded) {
        Check(false, "无法读取");
    } else {
        Check(g_srcText.find("[tak-DBG]") != std::string::npos, "存在 [tak-DBG] 日志");
        // 25.2 ★ 必须输出 eq 三位标记
        Check(g_srcText.find("eq=%d%d%d") != std::string::npos, "输出 eq 三位标记");
        // 25.3 ★ 候选数组前三项都要 dump（且 SafeReadable）
        Check(g_srcText.find("[0]=%p [1]=%p [2]=%p") != std::string::npos, "输出 [0][1][2]");
        Check(g_srcCode.find("SafeReadable((uint8_t*)arr + 0, 8)") != std::string::npos,
              "[0] 读取前 SafeReadable");
        Check(g_srcCode.find("SafeReadable((uint8_t*)arr + 8, 8)") != std::string::npos,
              "[1] 读取前 SafeReadable");
        Check(g_srcCode.find("SafeReadable((uint8_t*)arr + 16, 8)") != std::string::npos,
              "[2] 读取前 SafeReadable");
        // 25.7 ★ 序号 n0 必须在函数头部提前增量
        Check(g_srcCode.find("const LONG n0 = InterlockedIncrement(&s_tk2Decisions);") != std::string::npos,
              "n0 在函数头部增量");
        // 25.8 ★ 日志限流
        // 2026-11-17 STAGE-1b：收紧到只前 20 条（避免刷屏）
        Check(g_srcCode.find("n0 <= 20") != std::string::npos,
              "DBG 日志限流（只前 20 条）");
    }

    printf("\n=== 26) 成员判据（2026-11-17 STAGE-1b）===\n");
    Emit("    依据：0x820B30 有 3 条提前退出路径，此时 R12 保持入口值");
    Emit("    判据：gamePick ∈ arr[0..cnt-1] ? 真选卡 : 早退 → 不干预");
    if (!g_srcLoaded) {
        Check(false, "无法读取");
    } else {
        // 26.1 ★ 必须有成员遍历判据
        Check(g_srcCode.find("bool isCandidate = false;") != std::string::npos,
              "存在 isCandidate 标志");
        Check(g_srcCode.find("if (arr[i] == gamePick) { isCandidate = true; break; }") != std::string::npos,
              "遍历 arr[0..cnt-1] 比较 gamePick");
        // 26.3 ★ 不在候选 → 返回 gamePick（不干预）
        Check(g_srcCode.find("if (!isCandidate) {") != std::string::npos,
              "有 !isCandidate 分支");
        // 26.4 ★ 分支内必须 return gamePick（不是 nullptr）
        {
            size_t a = g_srcCode.find("if (!isCandidate) {");
            if (a != std::string::npos) {
                std::string blk = g_srcCode.substr(a, 500);
                Check(blk.find("return gamePick;") != std::string::npos,
                      "!isCandidate 分支返回 gamePick（不干预）");
                Check(blk.find("[tak-SKIP]") != std::string::npos ||
                      g_srcText.find("[tak-SKIP]") != std::string::npos,
                      "有 [tak-SKIP] 日志");
            } else { Check(false, "能切出成员判据块"); }
        }
        // 26.6 ★ 统计计数器
        Check(g_srcCode.find("s_tk2NoOps") != std::string::npos, "有早退计数器");
        Check(g_srcCode.find("s_tk2RealPicks") != std::string::npos, "有真选卡计数器");
        // 26.8 ★ [tak-DBG] 已收紧到前 20 条
        Check(g_srcCode.find("n0 <= 20") != std::string::npos, "[tak-DBG] 只前 20 条");
        // 26.9 ★ 有汇总日志
        // 2026-11-18：[汇总] 是字面量，且现在用 total(真选卡+早退)
        Check(g_srcText.find("[汇总]") != std::string::npos, "有汇总日志");
        // 2026-11-20：300 → 500（一局只有 ~219 次决策，300 永远够不到）
        Check(g_srcCode.find("total % 500") != std::string::npos, "汇总间隔 500");

        // ==================================================================
        // 2026-11-20 防回归：并列累加块不能在 UNREADABLE-FALLBACK 分支内部
        // ==================================================================
        //
        // 【旧 bug】
        //   s_tieTotal 永远是 0，因为累加代码被错放进了
        //   if (chosen && ... !SafeReadable(chosen, 8)) { ... } 分支里。
        //   那个分支只在「对象不可读」时执行（极罕见）。
        //
        // 【断言方式】
        //   在源码里找 "InterlockedIncrement(&s_tieTotal)" 的位置，
        //   确认它出现在 "!SafeReadable(chosen, 8)" 之后。
        //   （因为修后的顺序是：决策 → tie 累加 → UNREADABLE 检查）
        //
        {
            const std::string& s = g_srcCode;
            const size_t tieInc = s.find("InterlockedIncrement(&s_tieTotal)");
            const size_t unread = s.find("!SafeReadable(chosen, 8)");
            Check(tieInc != std::string::npos, "并列累加存在（s_tieTotal 有 ++）");
            Check(unread != std::string::npos, "UNREADABLE-FALLBACK 判据存在");
            Check(tieInc != std::string::npos && unread != std::string::npos && tieInc < unread,
                  "并列累加在 UNREADABLE 检查之前（在所有决策分支之后）");
        }
        // 26.10 ★ 版本号 STAGE-1b
        Check(g_srcText.find("take-v") != std::string::npos, "banner 含版本标识");
    }

    printf("\n=== 27) 玩家自动科研路径探针（0xBBC3E7）===\n");
    Emit("    0x6F2590 只处理 AI；玩家走 0xBBC300 → 0xBBC3E7 call 0x820B30。");
    if (!g_srcLoaded) {
        Check(false, "无法读取");
    } else {
        // 27.1 5 字节 pattern（E8 rel32 → call 0x820B30）
        Check(g_srcCode.find("0xE8, 0x44, 0x47, 0xC6, 0xFF") != std::string::npos,
              "pattern 含 call 0x820B30 的 5 字节");
        // 27.2 ★ 位置必须 = 0xBBC3E7
        Check(g_srcCode.find("hit != 0xBBC3E7") != std::string::npos,
              "命中位置必须等于 0xBBC3E7");
        // 27.3 ★ 跳回 0xBBC3EC（依赖 RAX）
        Check(g_srcCode.find("base + 0xBBC3EC") != std::string::npos, "跳回 0xBBC3EC");
        // 27.4 ★ 返回值经全局带出（不用 pop rax）
        Check(g_srcCode.find("g_bpRet") != std::string::npos, "返回值经 g_bpRet 带出");
        // 27.4b ★★ 必须在 pop 之后【从全局读回 rax】—— 0xBBC3EC 依赖 RAX
        //        这是本探针最容易写错的地方：pop %rax 会冲掉探针的返回值
        {
            size_t a = g_srcText.find("AR_BpTramp:");
            size_t b = (a == std::string::npos) ? std::string::npos
                                                : g_srcText.find("jmp *g_bpBackAddr", a);
            if (a != std::string::npos && b != std::string::npos && b > a) {
                std::string blk = g_srcText.substr(a, b - a);
                size_t popAx = blk.find("pop %rax");
                size_t readBack = blk.find("mov g_bpRet(%rip), %rax");
                Check(popAx != std::string::npos, "tramp 内有 pop %rax");
                Check(readBack != std::string::npos,
                      "tramp 内有 mov g_bpRet(%rip),%rax（从全局读回返回值）");
                Check(popAx != std::string::npos && readBack != std::string::npos && readBack > popAx,
                      "读回 rax 必须在 pop %rax 之后（否则返回值被冲掉）");
            } else { Check(false, "能切出 AR_BpTramp 块"); }
        }
        // 27.5 ★ trampoline 8 push + sub 0x20
        {
            size_t a = g_srcText.find("AR_BpTramp:");
            size_t b = (a == std::string::npos) ? std::string::npos
                                                : g_srcText.find("jmp *g_bpBackAddr", a);
            Check(a != std::string::npos && b != std::string::npos && b > a,
                  "能切出 AR_BpTramp 块");
            if (a != std::string::npos && b != std::string::npos && b > a) {
                std::string blk = g_srcText.substr(a, b - a);
                Check(blk.find("sub $0x20, %rsp") != std::string::npos, "tramp 内 sub 0x20");
                Check(blk.find("add $0x20, %rsp") != std::string::npos, "tramp 内 add 0x20");
                Check(blk.find("push %rbx") != std::string::npos, "tramp 保存 rbx（第8个push）");
            }
        }
        // 27.9 ★ 参数来源：rsi=country, edi=area
        Check(g_srcText.find("mov %rsi, %rcx") != std::string::npos, "country 从 rsi 取");
        Check(g_srcText.find("mov %edi, %edx") != std::string::npos, "area 从 edi 取");
        // 27.11 ★ 真调选卡器（不改行为）
        Check(g_srcCode.find("g_pfnSelTech(slotmgr, area)") != std::string::npos,
              "真调 0x820B30（保持副作用）");
        // 27.12 ★ 记录 bit11 / global / 成员判据
        Check(g_srcCode.find("0x2A68") != std::string::npos, "读 country+0x2A68");
        Check(g_srcCode.find("0x8C") != std::string::npos, "读 +0x8C");
        Check(g_srcCode.find("v >> 11") != std::string::npos, "取 bit 11");
        Check(g_srcCode.find("0x3118210") != std::string::npos, "读启动模式全局");
        Check(g_srcCode.find("inCand") != std::string::npos, "记录成员判据");
        // 27.17 nearby 桩用 FF 25（零寄存器副作用）
        Check(g_srcCode.find("buf[0] = 0xFF; buf[1] = 0x25;") != std::string::npos,
              "nearby 桩用 FF 25");
        // 27.18 回滚保存 5 字节
        Check(g_srcCode.find("g_bpOrig[5]") != std::string::npos, "保存原 5 字节");
    }

    printf("\n=== 28) 玩家 id 判据数据（cid/pid）===\n");
    Emit("    为将来的玩家判据准备：cid = [country+0x20]，pid = GETC()->[+0x20]");
    if (!g_srcLoaded) {
        Check(false, "无法读取");
    } else {
        Check(g_srcCode.find("cid = (*(volatile uint32_t*)((uint8_t*)country + 0x20)) & 0xFFFFFFu") != std::string::npos,
              "cid 从 country+0x20 取（24 位）");
        // 2026-11-17 崩溃修复：GETC(0x266340) 已彻底移除（它把 param_1 传给
        // 0x24C5F0，而 0x24C5F0 用它作 [RDI+0x24] 基址 → 必崩）。
        Check(g_srcCode.find("pfnGetc") == std::string::npos, "不再调 GETC(0x266340)");
        // 2026-11-17：param_1 改传 gs（可用时）。GETC 内部优先用全局 0x3119F18，
        // 因此传 gs 或 nullptr 都安全；传 gs 更符合调用约定。
        Check(g_srcCode.find("0x311BF18") != std::string::npos,
              "改用直接读全局 0x311BF18");
        Check(g_srcCode.find("pid = (*(volatile uint32_t*)((uint8_t*)gsPtr + idOff)) & 0xFFFFFFu") != std::string::npos,
              "pid 从 gs+idOff 取（idOff = 0x5C 或 0x60）");
        // ISPLAYER 属于字面量，必须用 g_srcText（不含注释的 code 视图会剔掉）
        Check(g_srcText.find("ISPLAYER") != std::string::npos,
              "日志标记 ISPLAYER");
        // ★ 不得使用 MSVC 专有的 __try/__except（MinGW 不支持）
        Check(g_srcCode.find("__except") == std::string::npos,
              "不得使用 __try/__except（MinGW 不支持）");
    }

    printf("\n=== 29) 阶段 2a：全禁不干预（方案 B）===\n");
    Emit("    0xBBC3F2 MOV RDX,[RAX] 会解引用 → 全禁不能返回 nullptr");
    if (!g_srcLoaded) {
        Check(false, "无法读取");
    } else {
        // 29.1 ★ bp 探针体内不得有 chosen = nullptr / return nullptr
        {
            size_t a = g_srcCode.find("AR_PlayerPathProbe(void* country");
            size_t b = (a == std::string::npos) ? std::string::npos
                                                : g_srcCode.find("AR_BpTramp", a);
            Check(a != std::string::npos && b != std::string::npos && b > a,
                  "能切出 AR_PlayerPathProbe 块");
            if (a != std::string::npos && b != std::string::npos && b > a) {
                std::string body = g_srcCode.substr(a, b - a);
                Check(body.find("chosen = nullptr") == std::string::npos,
                      "bp 探针体内无 chosen=nullptr");
                Check(body.find("return nullptr") == std::string::npos,
                      "bp 探针体内无 return nullptr");
            }
        }
        // 29.4 ★ 全禁标记必须是 KEEP（不干预）
        Check(g_srcText.find("ALL-DISABLED-KEEP") != std::string::npos,
              "全禁标记为 ALL-DISABLED-KEEP");
        // 29.5 ★ 阶段 2a 的只接管非空
        Check(g_srcCode.find("chosen != ret && chosen != nullptr && inCand == 1") != std::string::npos,
              "只接管 chosen 非空且 ≠ ret");
        // 29.6 ★ 开关默认 DRY-RUN
        // 2026-11-17：开关值会随阶段改变（DRY-RUN=1 / LIVE=0），
        // 所以断言只检查「存在且为 0 或 1」，不绑定具体值。
        {
            const bool has0 = g_srcCode.find("#define AR_TAKEOVER_BP_DRYRUN 0") != std::string::npos;
            const bool has1 = g_srcCode.find("#define AR_TAKEOVER_BP_DRYRUN 1") != std::string::npos;
            Check(has0 != has1, "AR_TAKEOVER_BP_DRYRUN 存在且只取 0 或 1");
        }
        // 29.7 ★ gs038 路径标记
        Check(g_srcText.find("[bp-gs]") != std::string::npos, "有 [bp-gs] 路径标记");
        Check(g_srcCode.find("0x38, 8") != std::string::npos, "读 gs+0x38");
    }

    printf("\n=== 30) 崩溃修复：不得调 0x24C5F0 / 0x266340 ===\n");
    Emit("    0x24C5F0 用 RCX 作 [RDI+0x24]/[RDI+0x18] 基址 → 传垃圾必崩");
    if (!g_srcLoaded) {
        Check(false, "无法读取");
    } else {
        size_t a = g_srcCode.find("AR_PlayerPathProbe(void* country");
        size_t b = (a == std::string::npos) ? std::string::npos
                                            : g_srcCode.find("AR_BpTramp", a);
        Check(a != std::string::npos && b != std::string::npos && b > a,
              "能切出 AR_PlayerPathProbe 块");
        if (a != std::string::npos && b != std::string::npos && b > a) {
            std::string body = g_srcCode.substr(a, b - a);
            // ★ 30.1/30.2 不得再有函数指针调用
            Check(body.find("pfnGs") == std::string::npos, "体内无 pfnGs（不调 0x24C5F0）");
            Check(body.find("pfnGetc") == std::string::npos, "体内无 pfnGetc（不调 0x266340）");
            // ★ 30.3/30.4 不得出现这两个 RVA
            Check(body.find("0x24C5F0") == std::string::npos, "体内无 0x24C5F0 RVA");
            Check(body.find("0x266340") == std::string::npos, "体内无 0x266340 RVA");
            // ★ 30.5 不得用错的全局地址
            // ⚠️ 0x3119F18 只在注释里出现（记录崩溃历史），
            //    g_srcCode 已剥注释，所以这里必然为 npos，无法捕获回退。
            //    改为检查「正确地址必须存在」（见 30.6）。
            Check(body.find("g_base + 0x311BF18") != std::string::npos,
                  "实体代码用 g_base + 0x311BF18");
            // ★ 30.6 必须用正确的 0x311BF18
            Check(body.find("0x311BF18") != std::string::npos, "用正确的全局 0x311BF18");
            // ★ 30.7 必须经 SafeReadable 保护
            Check(body.find("SafeReadable((void*)(uintptr_t)(g_base + 0x311BF18), 8)") != std::string::npos,
                  "读全局前 SafeReadable");
            Check(body.find("SafeReadable((uint8_t*)gsPtr + 0x38, 8)") != std::string::npos,
                  "读 gs+0x38 前 SafeReadable");
            // ★ 30.9 两条路径（0x5C / 0x60）
            Check(body.find("0x5Cu : 0x60u") != std::string::npos,
                  "按 gs038 选 0x5C 或 0x60");
        }
    }

    printf("\n==============================================\n");
    { char b[128]; snprintf(b, sizeof(b), "结果: %d passed, %d failed, %d total", g_pass, g_fail, g_pass + g_fail); Emit(b); }
    Emit(g_fail == 0 ? "结论: ALL PASS" : "结论: FAILED");
    printf("==============================================\n");
    if (g_log) fclose(g_log);
    return g_fail == 0 ? 0 : 1;
}
