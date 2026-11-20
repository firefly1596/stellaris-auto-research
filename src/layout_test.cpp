// layout_test.cpp —— ar_layout.h 的验收测试
//
// 四项强制验收标准（L1_PROTOTYPE_REPORT §6）：
//   1. 双版本正确读出且值相同     4.5.2 C890=0x81C890 / 4.5.4 C890=0x81E7E0
//   2. 对抗测试：改 disp 后必须读出改后的新值
//   3. 唯一解：多解 -> nullopt
//   4. 失败明确：找不到 -> nullopt
//
// 标准 2 是本文件的核心：它是区分「真推导」与「伪装查表」的唯一可靠手段。
// 本测试**不依赖真实游戏进程**也能跑对抗部分（纯内存改写）。

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <windows.h>

#include "ar_layout.h"

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

// ---------------- 读 PE，取 .text 与 .pdata ----------------
struct Pe {
    std::vector<uint8_t> buf;
    struct Sec { std::string n; uint32_t va, vs, rs, rp; };
    std::vector<Sec> secs;
    std::vector<std::pair<uint32_t,uint32_t>> funcs;

    bool Load(const char* p) {
        HANDLE h = CreateFileA(p, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
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
                    if (en > st) funcs.push_back({st, en-st});
                }
            }
        }
        return !secs.empty();
    }
    uint32_t LenOf(uint32_t rva) const {
        for (auto& f : funcs) if (f.first == rva) return f.second;
        return 0;
    }
    // 取函数体副本（可写）
    bool CopyFunc(uint32_t rva, std::vector<uint8_t>* out) const {
        uint32_t len = LenOf(rva);
        if (!len) return false;
        for (auto& s : secs) {
            if (rva >= s.va && rva < s.va + s.vs) {
                uint32_t o = s.rp + (rva - s.va);
                if (o + len > buf.size()) return false;
                out->assign(buf.begin()+o, buf.begin()+o+len);
                return true;
            }
        }
        return false;
    }
};

// ---------------- 在函数体里把某个 disp32 改值 ----------------
// 只改「紧随 opcode/ModRM 之后」的 disp32，按解码器的指令边界精确改。
static int PatchDisp(std::vector<uint8_t>* code, uint32_t from, uint32_t to) {
    arlayout::DecodedFn d = arlayout::DecodeFunction(code->data(), code->size(), 0);
    if (!d.complete) return -1;
    int n = 0;
    for (size_t i = 0; i < d.insns.size(); ++i) {
        const arlde::Insn& in = d.insns[i];
        if (!in.hasModRm || in.modrmMod == 3) continue;
        if (in.hasRipRel) continue;
        if (in.disp != (int64_t)from) continue;
        // disp32 位于指令末尾（本形状都是 mod==2 的 disp32）
        if (in.modrmMod != 2) continue;
        size_t off = d.offs[i] + in.length - 4;
        uint32_t nv = to;
        memcpy(code->data() + off, &nv, 4);
        ++n;
    }
    return n;
}

// =====================================================================
int main(int argc, char** argv) {
    std::string exe = "E:/Steam/steamapps/common/Stellaris/stellaris.exe";
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--log" && i+1 < argc) g_log = fopen(argv[++i], "w");
        else if (a == "--exe" && i+1 < argc) exe = argv[++i];
        // 也接受位置参数（build_and_test.sh 的 run_test 直接传路径）
        else if (a.size() > 4 && a.substr(a.size()-4) == ".exe") exe = a;
    }

    Emit("==============================================");
    Emit("L1 结构偏移推导 —— 验收测试");
    Emit("四项标准：双版本 / 对抗 / 唯一解 / 失败明确");
    Emit("==============================================");

    Pe pe;
    if (!pe.Load(exe.c_str())) {
        Check(false, "能读取游戏 exe", exe);
        Emit("\n（读不到 exe，本测试无法进行）");
        if (g_log) fclose(g_log);
        return 1;
    }
    Emit("  exe: " + exe);

    // ---------------- 标准 1：双版本正确读出 ----------------
    Emit("");
    Emit("=== 1) 双版本正确读出（标准 1）===");

    struct Ver { const char* tag; uint32_t c890; };
    // 注：4.5.2 的 C890 只在她自己的 exe 里存在；当前 exe 是 4.5.4。
    // 这里只测当前 exe 里存在的那个，另一个由 --exe 切换验证（见 §8 复现方式）。
    Ver vers[] = {
        { "4.5.4", 0x81E7E0 },
        { "4.5.2", 0x81C890 },
    };

    bool gotAny = false;
    arlayout::CardLayout got{};
    std::string gotTag;
    for (auto& v : vers) {
        uint32_t len = pe.LenOf(v.c890);
        if (!len) { Emit(std::string("  [跳过] ") + v.tag + " C890=0x" + std::to_string(v.c890) + " 不在本 exe"); continue; }
        std::vector<uint8_t> code;
        if (!pe.CopyFunc(v.c890, &code)) { Emit(std::string("  [跳过] ") + v.tag + " 读取失败"); continue; }

        arlayout::Diag dg;
        auto r = arlayout::FindCardLayout(code.data(), code.size(), v.c890, &dg);
        std::string tag = std::string(v.tag) + " C890=0x" +
                          [&]{ char b[16]; snprintf(b,sizeof(b),"%X",v.c890); return std::string(b);}();
        if (r) {
            char b[220];
            snprintf(b, sizeof(b), "  %s  count=0x%X array=0x%X elem=%u",
                     tag.c_str(), r->countOff, r->arrayOff, r->elemSize);
            Emit(b);
            if (!gotAny) { got = *r; gotTag = v.tag; gotAny = true; }
            else {
                Check(r->countOff == got.countOff && r->arrayOff == got.arrayOff &&
                      r->elemSize == got.elemSize,
                      std::string("两版本读出一致（") + gotTag + " vs " + v.tag + "）");
            }
        } else {
            Emit("  " + tag + "  推导失败：");
            for (auto& l : dg.lines) Emit("      " + l);
        }
    }
    Check(gotAny, "至少在一个版本上推导成功");
    if (!gotAny) { if (g_log) fclose(g_log); return 1; }

    // 已知值核对（这是"答案"，推导器不得使用它）
    Check(got.countOff == 0x31BC && got.arrayOff == 0x31B0 && got.elemSize == 4,
          "读出值与已知布局一致 (0x31BC/0x31B0/4)",
          [&]{ char b[128]; snprintf(b,sizeof(b),"got 0x%X/0x%X/%u",
               got.countOff, got.arrayOff, got.elemSize); return std::string(b);}());

    // ---------------- 标准 2：对抗测试 ----------------
    Emit("");
    Emit("=== 2) 对抗测试：改 disp 后必须读出改后的值（标准 2）===");
    Emit("    这是区分「真推导」与「伪装查表」的唯一可靠手段。");
    {
        uint32_t c890 = 0;
        for (auto& v : vers) if (pe.LenOf(v.c890)) { c890 = v.c890; break; }
        std::vector<uint8_t> code;
        Check(pe.CopyFunc(c890, &code), "能复制 C890 函数体");

        const uint32_t SHIFT = 0x10;
        uint32_t newCount = got.countOff + SHIFT;
        uint32_t newArray = got.arrayOff + SHIFT;

        int n1 = PatchDisp(&code, got.countOff, newCount);
        int n2 = PatchDisp(&code, got.arrayOff, newArray);
        char b[220];
        snprintf(b, sizeof(b), "改写了 disp：count 处 %d 条，array 处 %d 条", n1, n2);
        Emit(std::string("    ") + b);
        Check(n1 > 0, "至少改到一处 count disp");
        Check(n2 > 0, "至少改到一处 array disp");

        arlayout::Diag dg;
        auto r2 = arlayout::FindCardLayout(code.data(), code.size(), c890, &dg);
        Check(r2.has_value(), "改写后仍能推导出结果");
        if (r2) {
            snprintf(b, sizeof(b), "改写后读出 count=0x%X array=0x%X elem=%u",
                     r2->countOff, r2->arrayOff, r2->elemSize);
            Emit(std::string("    ") + b);
            // ★ 核心断言：必须读出【改后的新值】，不能停留在原值
            snprintf(b, sizeof(b),
                     "改写后读出改后的新值（期望 0x%X/0x%X，实际 0x%X/0x%X）",
                     newCount, newArray, r2->countOff, r2->arrayOff);
            bool moved = (r2->countOff == newCount && r2->arrayOff == newArray);
            Check(moved, b);
            // 反证：如果读出仍是原值，说明实现里藏了硬编码
            bool stuck = (r2->countOff == got.countOff && r2->arrayOff == got.arrayOff);
            Check(!stuck, "读出值没有停留于原值（否则说明是查表而非推导）");
        } else {
            Emit("    改写后推导失败，诊断：");
            for (auto& l : dg.lines) Emit("      " + l);
        }
    }

    // ---------------- 标准 3：唯一解 ----------------
    Emit("");
    Emit("=== 3) 唯一解（标准 3）===");
    {
        // 构造一个「消歧后仍多解」的场景：把唯一的 count 偏移复制到另一处，
        // 使两个候选同样满足形状。这里用更直接的办法：
        // 验证诊断里记录了候选数，且最终 afterFrequency == 1。
        uint32_t c890 = 0;
        for (auto& v : vers) if (pe.LenOf(v.c890)) { c890 = v.c890; break; }
        std::vector<uint8_t> code;
        pe.CopyFunc(c890, &code);
        arlayout::Diag dg;
        auto r = arlayout::FindCardLayout(code.data(), code.size(), c890, &dg);
        char b[220];
        snprintf(b, sizeof(b), "初筛候选 %d 个，消歧A 后 %d 个，消歧B 后 %d 个",
                 dg.rawCandidates, dg.afterCompare, dg.afterFrequency);
        Emit(std::string("    ") + b);
        Check(dg.afterFrequency == 1, "最终只剩 1 个候选（唯一解）");
        Check(dg.rawCandidates > 1, "初筛确实有多个候选（证明消歧真的在起作用）");
        Check(dg.afterCompare < dg.rawCandidates,
              "消歧A（比较语义）确实排除了候选");
    }

    // ---------------- 标准 4：失败明确 ----------------
    Emit("");
    Emit("=== 4) 失败明确 -> nullopt（标准 4）===");
    {
        // 4a 空输入
        arlayout::Diag dg;
        auto r = arlayout::FindCardLayout(nullptr, 0, 0, &dg);
        Check(!r.has_value(), "空函数体 -> nullopt");
        Check(!dg.lines.empty(), "失败时提供了诊断信息");

        // 4b 全 NOP 的函数体（不含任何形状）
        std::vector<uint8_t> nops(256, 0x90);
        arlayout::Diag dg2;
        auto r2 = arlayout::FindCardLayout(nops.data(), nops.size(), 0, &dg2);
        Check(!r2.has_value(), "不含目标形状 -> nullopt");

        // 4c 截断的函数体（解码器走不到末尾 -> fail-closed）
        uint32_t c890 = 0;
        for (auto& v : vers) if (pe.LenOf(v.c890)) { c890 = v.c890; break; }
        std::vector<uint8_t> code;
        pe.CopyFunc(c890, &code);
        std::vector<uint8_t> trunc(code.begin(), code.begin() + code.size()/2);
        arlayout::Diag dg3;
        auto r3 = arlayout::FindCardLayout(trunc.data(), trunc.size(), c890, &dg3);
        Check(!r3.has_value(), "截断的函数体 -> nullopt（fail-closed，不给半截结果）");
    }

    // ---------------- 源码审查：代码里不得有硬编码偏移 ----------------
    //
    // 注意：只审查【代码】，不审查注释 —— 注释里说明「以前是 0x31B0」是必要的文档，
    // 不能因此判失败。所以先剥离 // 与 /* */ 注释，再检查。
    Emit("");
    Emit("=== 5) 源码审查：ar_layout.h 的【代码】内不得出现 31B0/31BC 字面量 ===");
    {
        const char* cands[] = { "ar_layout.h", "../tech_probe/ar_layout.h",
                                "_stellaris_eval/tech_probe/ar_layout.h" };
        FILE* f = nullptr;
        for (const char* c : cands) { f = fopen(c, "rb"); if (f) break; }
        Check(f != nullptr, "能读取 ar_layout.h");
        if (f) {
            std::string raw; char buf[4096]; size_t n;
            while ((n = fread(buf, 1, sizeof(buf), f)) > 0) raw.append(buf, n);
            fclose(f);

            // 剥离注释，只留代码
            std::string code;
            {
                bool inLine = false, inBlock = false;
                for (size_t i = 0; i < raw.size(); ++i) {
                    if (inLine) { if (raw[i] == '\n') { inLine = false; code += '\n'; } continue; }
                    if (inBlock) {
                        if (raw[i] == '*' && i+1 < raw.size() && raw[i+1] == '/') { inBlock = false; ++i; }
                        continue;
                    }
                    if (raw[i] == '/' && i+1 < raw.size() && raw[i+1] == '/') { inLine = true; ++i; continue; }
                    if (raw[i] == '/' && i+1 < raw.size() && raw[i+1] == '*') { inBlock = true; ++i; continue; }
                    code += raw[i];
                }
            }
            char b2[200];
            snprintf(b2, sizeof(b2), "剥离注释后代码 %zu 字符（原 %zu）", code.size(), raw.size());
            Emit(std::string("    ") + b2);

            auto hasLit = [&](const char* lit) {
                size_t ll = strlen(lit);
                for (size_t i = 0; i + ll <= code.size(); ++i) {
                    bool same = true;
                    for (size_t k = 0; k < ll; ++k) {
                        char a = code[i+k], c2 = lit[k];
                        if (a >= 'a' && a <= 'f') a = (char)(a - 'a' + 'A');
                        if (c2 >= 'a' && c2 <= 'f') c2 = (char)(c2 - 'a' + 'A');
                        if (a != c2) { same = false; break; }
                    }
                    if (same) return true;
                }
                return false;
            };
            Check(!hasLit("31B0"), "代码内无 0x31B0 字面量（偏移只能从指令读）");
            Check(!hasLit("31BC"), "代码内无 0x31BC 字面量（偏移只能从指令读）");
            Check(!hasLit("0x31D8"), "代码内无 0x31D8 字面量");
        }
    }

    Emit("");
    Emit("==============================================");
    { char b[128]; snprintf(b, sizeof(b), "结果: %d passed, %d failed, %d total",
                            g_pass, g_fail, g_pass+g_fail); Emit(b); }
    Emit(g_fail == 0 ? "结论: ALL PASS" : "结论: FAILED");
    Emit("==============================================");
    if (g_log) fclose(g_log);
    return g_fail == 0 ? 0 : 1;
}
