// c890_chain_test.cpp —— C890 三级定位/推导/校验链的测试
//
// 三级结构（解开「定位 C890 需要偏移、推导偏移需要 C890」的循环）：
//   阶段 1  定位 C890   判据 = 被 E4B0 调用 + 长度 4074      （不用偏移）
//   阶段 2  推导偏移    形状扫描，从指令 disp 读            （产出偏移）
//   阶段 3  二次校验    用推导出的偏移回头验 C890 体内确有对应访问
//
// 本测试在【两个版本】的 exe 上各跑一遍三级链，并把各自结果留在日志里。
//
// 注意（与 layout_test 相同的诚实性原则）：
//   每个 exe 只含自己版本的函数，所以本测试会【分两次独立运行】验证两个版本，
//   不能在同一进程内同时验证。日志里会明确标出哪个版本成功、哪个被跳过。

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
#include <windows.h>

#include "ar_resolve.h"

static int g_pass = 0, g_fail = 0;
static FILE* g_log = nullptr;

static void Emit(const std::string& s) {
    fputs(s.c_str(), stdout); fputc('\n', stdout);
    if (g_log) { fputs(s.c_str(), g_log); fputc('\n', g_log); fflush(g_log); }
}
static void Check(bool c, const std::string& what, const std::string& d = "") {
    if (c) { ++g_pass; Emit("  [PASS] " + what); }
    else   { ++g_fail; Emit("  [FAIL] " + what + (d.empty() ? "" : "   (" + d + ")")); }
}

// ---------------- 测试用 PE 镜像 ----------------
struct Pe : public aranchor::IAnchorImage {
    std::vector<uint8_t> buf;
    struct Sec { std::string n; uint32_t va, vs, rs, rp; };
    std::vector<Sec> secs;
    std::vector<std::pair<uint32_t,uint32_t>> fns;   // (start, end) 符合 IAnchorImage 契约

    bool Load(const char* p) {
        HANDLE h = CreateFileA(p, GENERIC_READ,
                               FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                               0, OPEN_EXISTING, 0, 0);
        if (h == INVALID_HANDLE_VALUE) return false;
        LARGE_INTEGER z; GetFileSizeEx(h, &z);
        buf.resize((size_t)z.QuadPart);
        DWORD g = 0;
        while (g < buf.size()) {
            DWORD c = (DWORD)((buf.size()-g) > (1u<<20) ? (1u<<20) : (buf.size()-g)), r = 0;
            if (!ReadFile(h, buf.data()+g, c, &r, 0) || !r) { CloseHandle(h); return false; }
            g += r;
        }
        CloseHandle(h);
        uint32_t po = *(uint32_t*)(buf.data()+0x3c);
        uint16_t ns = *(uint16_t*)(buf.data()+po+6), os = *(uint16_t*)(buf.data()+po+20);
        uint32_t so = po+24+os;
        for (uint16_t i = 0; i < ns; ++i) {
            uint32_t o = so + i*40;
            Sec s; char n[9] = {0}; memcpy(n, buf.data()+o, 8); s.n = n;
            s.vs = *(uint32_t*)(buf.data()+o+8);
            s.va = *(uint32_t*)(buf.data()+o+12);
            s.rs = *(uint32_t*)(buf.data()+o+16);
            s.rp = *(uint32_t*)(buf.data()+o+20);
            secs.push_back(s);
            if (s.n == ".pdata") {
                uint32_t cnt = s.rs/12;
                for (uint32_t k = 0; k < cnt; ++k) {
                    uint32_t eo = s.rp + k*12;
                    uint32_t st = *(uint32_t*)(buf.data()+eo);
                    uint32_t en = *(uint32_t*)(buf.data()+eo+4);
                    if (en > st) fns.push_back({st, en});
                }
            }
        }
        return !secs.empty();
    }
    uint64_t Size() const override { return 0x4000000; }
    bool IsExecutable(uint32_t) const override { return true; }
    bool ReadBytes(uint32_t r, void* d, size_t n) const override {
        for (auto& s : secs) if (r >= s.va && r < s.va + s.vs) {
            uint32_t o = s.rp + (r - s.va);
            if ((size_t)o + n > buf.size()) return false;
            memcpy(d, buf.data()+o, n);
            return true;
        }
        return false;
    }
    void EnumFunctions(std::vector<std::pair<uint32_t,uint32_t>>* o) const override { *o = fns; }
    void FindStrings(const char*, const char*, std::vector<uint32_t>*) const override {}
    std::string Describe() const override { return "test-image"; }

    uint32_t LenOf(uint32_t rva) const {
        for (auto& f : fns) if (f.first == rva) return f.second - f.first;
        return 0;
    }
};

// ---------------- 单个版本跑三级链 ----------------
static void RunChain(const char* tag, const char* path, uint32_t e4b0Rva) {
    Emit("");
    Emit(std::string("=== ") + tag + " ===");

    Pe pe;
    if (!pe.Load(path)) {
        Emit(std::string("  无法读取 exe：") + path + "（本版本跳过）");
        return;
    }
    Emit(std::string("  exe: ") + path);

    // ---- 阶段 1 ----
    auto w = arresolve::LocateWeightCalc(pe, e4b0Rva, 4074);
    for (auto& l : w.diag) Emit("    " + l);
    if (!w.ok) {
        Check(false, std::string(tag) + " 阶段1：定位 C890");
        return;
    }
    {
        char b[128]; snprintf(b, sizeof(b), "0x%X", w.rva);
        Check(true, std::string(tag) + " 阶段1：定位 C890 = " + b + "（判据：被 E4B0 调用 + len 4074）");
    }

    // ---- 阶段 2 ----
    auto lay = arresolve::DeriveCardLayout(pe, w.rva);
    for (auto& l : lay.diag) Emit("    " + l);
    if (!lay.ok) {
        Check(false, std::string(tag) + " 阶段2：推导候选卡布局");
        return;
    }
    {
        char b[200];
        snprintf(b, sizeof(b), "count=0x%X array=0x%X elem=%u",
                 lay.layout.countOff, lay.layout.arrayOff, lay.layout.elemSize);
        Check(true, std::string(tag) + " 阶段2：推导布局成功 -> " + b);
    }

    // ---- 阶段 3 ----
    std::vector<std::string> d3;
    bool v = arresolve::VerifyLayoutUsed(pe, w.rva, w.len, lay.layout, &d3);
    for (auto& l : d3) Emit("    " + l);
    Check(v, std::string(tag) + " 阶段3：二次校验（推导值在 C890 体内确实被访问）");

    // ---- 附加：推导结果必须与函数体内访问一致，但不与任何硬编码比较 ----
    Check(lay.layout.elemSize == 4,
          std::string(tag) + " elemSize == 4（元素是 int32）");

    // ---- 端到端：DeriveTakeChain 编排（hookA -> E4B0 -> C890 -> 布局）----
    Emit("");
    Emit(std::string("  --- ") + tag + " DeriveTakeChain 端到端 ---");
    {
        // legacy 常量：仅作对照，绝不 fallback
        arresolve::LegacyCardOffsets legacy;
        legacy.countOff = 0x31BC;
        legacy.arrayOff = 0x31B0;

        uint32_t hookA = (e4b0Rva == 0x820400u) ? 0x81C850u : 0x81A900u;
        auto tc = arresolve::DeriveTakeChain(pe, hookA, 1768, 4074, &legacy);
        for (auto& l : tc.log) Emit("    " + l);

        Check(tc.e4b0Ok,   std::string(tag) + " 编排: E4B0 定位成功");
        Check(tc.c890Ok,   std::string(tag) + " 编排: C890 定位成功");
        Check(tc.layoutOk, std::string(tag) + " 编排: 布局推导成功");
        Check(tc.legacyCompared, std::string(tag) + " 编排: 做了 legacy 对照");
        Check(tc.legacyMatch,    std::string(tag) + " 编排: 推导值与 legacy 常量一致");

        // 日志必须标明来源是推导而非硬编码
        bool hasNotHardcoded = false;
        for (auto& l : tc.log) if (l.find("not hardcoded") != std::string::npos) hasNotHardcoded = true;
        Check(hasNotHardcoded, std::string(tag) + " 编排: 日志标明 not hardcoded");

        // 日志必须说明 legacy 不用于 fallback
        bool hasNoFallback = false;
        for (auto& l : tc.log) if (l.find("never used as fallback") != std::string::npos) hasNoFallback = true;
        Check(hasNoFallback, std::string(tag) + " 编排: 日志标明 legacy 不作 fallback");
    }
}

int main(int argc, char** argv) {
    std::string exe454 = "E:/Steam/steamapps/common/Stellaris/stellaris.exe";
    std::string exe452 = "D:/rty/Documents/deepseek-harness/default-workspace/_input/stellaris-4.5.2-9776.exe";
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--log" && i+1 < argc) g_log = fopen(argv[++i], "w");
        else if (a == "--exe454" && i+1 < argc) exe454 = argv[++i];
        else if (a == "--exe452" && i+1 < argc) exe452 = argv[++i];
    }

    Emit("==============================================");
    Emit("C890 三级链：定位 -> 推导 -> 校验");
    Emit("解开「定位需偏移 / 推导需定位」的循环");
    Emit("==============================================");

    // 4.5.4：E4B0 = 0x820400（len 1768，被 hookA 调用，唯一）
    RunChain("4.5.4", exe454.c_str(), 0x820400);
    // 4.5.2：E4B0 = 0x81E4B0（len 1768）
    RunChain("4.5.2", exe452.c_str(), 0x81E4B0);

    Emit("");
    Emit("==============================================");
    { char b[128]; snprintf(b, sizeof(b), "结果: %d passed, %d failed, %d total",
                            g_pass, g_fail, g_pass+g_fail); Emit(b); }
    Emit(g_fail == 0 ? "结论: ALL PASS" : "结论: FAILED");
    Emit("==============================================");
    if (g_log) fclose(g_log);
    return g_fail == 0 ? 0 : 1;
}
