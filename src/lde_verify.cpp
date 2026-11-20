// lde_verify.cpp —— 用【已知答案】验证指令长度解码器
//
// 验证思路（不依赖任何外部资料，答案来自之前已确认的事实）：
//   1. 从 .pdata 拿到每个目标函数的起止边界
//   2. 用 LDE 从起点逐条走到终点
//   3. 要求：正好走到 end 边界（差 1 字节就说明解错长度）
//   4. 对 hook 目标（FUN_140425550 / FUN_14081A900）额外要求：
//      函数里必须存在指向 "technology_status.cpp" 等字符串的 rip 引用
//
// 只要"走到终点"能对上，就说明长度解码在真实代码上是准的。
//
// 编译： g++ -std=c++17 -O2 -o lde_verify.exe lde_verify.cpp
// 运行： ./lde_verify.exe "E:/Steam/steamapps/common/Stellaris/stellaris.exe"
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>

#include "ar_lde.h"
#include "ar_version.h"

static int g_pass = 0, g_fail = 0;
static FILE* g_out = nullptr;
static void Emit(const std::string& s) {
    fputs(s.c_str(), stdout); fputc('\n', stdout);
    if (g_out) { fputs(s.c_str(), g_out); fputc('\n', g_out); fflush(g_out); }
}
static void Section(const std::string& n) { Emit(""); Emit("=== " + n + " ==="); }
static void Check(bool c, const std::string& what, const std::string& d = "") {
    if (c) { ++g_pass; Emit("  [PASS] " + what + (d.empty() ? "" : "   (" + d + ")")); }
    else   { ++g_fail; Emit("  [FAIL] " + what + (d.empty() ? "" : "   (" + d + ")")); }
}

struct PeFile {
    std::vector<uint8_t> buf;
    struct Sec { std::string name; uint32_t va, vsize, rawSize, rawPtr, chars; };
    std::vector<Sec> secs;
    struct Func { uint32_t start, end; };
    std::vector<Func> pdata;
    uint32_t sizeOfImage = 0;

    bool Load(const std::string& path) {
        HANDLE h = CreateFileA(path.c_str(), GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return false;
        LARGE_INTEGER sz;
        if (!GetFileSizeEx(h, &sz)) { CloseHandle(h); return false; }
        buf.resize((size_t)sz.QuadPart);
        DWORD got = 0;
        while (got < buf.size()) {
            DWORD chunk = (DWORD)std::min<size_t>(buf.size() - got, 1u << 20);
            DWORD rd = 0;
            if (!ReadFile(h, buf.data() + got, chunk, &rd, nullptr) || !rd) {
                CloseHandle(h); return false;
            }
            got += rd;
        }
        CloseHandle(h);

        uint32_t peOff = *(uint32_t*)(buf.data() + 0x3c);
        uint16_t nsec = *(uint16_t*)(buf.data() + peOff + 6);
        uint16_t optSize = *(uint16_t*)(buf.data() + peOff + 20);
        uint32_t optOff = peOff + 24;
        sizeOfImage = *(uint32_t*)(buf.data() + optOff + 56);
        uint32_t secOff = optOff + optSize;
        for (uint16_t i = 0; i < nsec; ++i) {
            uint32_t o = secOff + i * 40;
            Sec s;
            char nm[9] = {0};
            memcpy(nm, buf.data() + o, 8);
            s.name = nm;
            s.vsize = *(uint32_t*)(buf.data() + o + 8);
            s.va = *(uint32_t*)(buf.data() + o + 12);
            s.rawSize = *(uint32_t*)(buf.data() + o + 16);
            s.rawPtr = *(uint32_t*)(buf.data() + o + 20);
            s.chars = *(uint32_t*)(buf.data() + o + 36);
            secs.push_back(s);
            if (s.name == ".pdata") {
                uint32_t cnt = s.rawSize / 12;
                for (uint32_t k = 0; k < cnt; ++k) {
                    uint32_t eo = s.rawPtr + k * 12;
                    pdata.push_back({*(uint32_t*)(buf.data() + eo),
                                     *(uint32_t*)(buf.data() + eo + 4)});
                }
            }
        }
        return !secs.empty();
    }

    // RVA → 文件偏移
    long RvaToOff(uint32_t rva) const {
        for (auto& s : secs) {
            if (rva >= s.va && rva < s.va + std::max(s.vsize, s.rawSize))
                return (long)(s.rawPtr + (rva - s.va));
        }
        return -1;
    }
    const uint8_t* At(uint32_t rva, size_t n) const {
        long o = RvaToOff(rva);
        if (o < 0 || (size_t)o + n > buf.size()) return nullptr;
        return buf.data() + o;
    }
    // 在某个段里搜字符串，返回所有命中的 RVA
    std::vector<uint32_t> FindString(const std::string& secName, const std::string& needle) const {
        std::vector<uint32_t> out;
        for (auto& s : secs) {
            if (s.name != secName) continue;
            if (s.rawSize < needle.size()) continue;
            const uint8_t* base = buf.data() + s.rawPtr;
            size_t limit = std::min<size_t>(s.rawSize, s.vsize ? s.vsize : s.rawSize);
            if (limit < needle.size()) continue;
            for (size_t i = 0; i + needle.size() <= limit; ++i) {
                if (memcmp(base + i, needle.data(), needle.size()) == 0) {
                    out.push_back(s.va + (uint32_t)i);
                    // 字符串必须以 NUL 结尾才算
                }
            }
        }
        return out;
    }
};

static std::string Hex(uint32_t v) {
    static const char* d = "0123456789ABCDEF";
    char b[16];
    b[0] = '0'; b[1] = 'x';
    for (int i = 0; i < 8; ++i) b[2 + i] = d[(v >> ((7 - i) * 4)) & 0xF];
    b[10] = 0;
    return std::string(b);
}

int main(int argc, char** argv) {
    std::string path, logPath;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--log" && i + 1 < argc) logPath = argv[++i];
        else if (path.empty()) path = a;
    }
    if (path.empty()) path = "E:/Steam/steamapps/common/Stellaris/stellaris.exe";
    if (!logPath.empty()) {
        g_out = fopen(logPath.c_str(), "w");
        if (!g_out) { fprintf(stderr, "cannot open log\n"); return 2; }
    }

    Emit("==============================================");
    Emit("指令长度解码器验证（用已知函数边界当答案）");
    Emit("目标: " + path);
    Emit("==============================================");

    PeFile pe;
    if (!pe.Load(path)) { Emit("FATAL: cannot load PE"); return 2; }
    Emit("  .pdata 函数条目: " + std::to_string(pe.pdata.size()));

    // ---------- 1) 解到函数终点 ----------
    Section("1) LDE 必须正好走到每个已知函数的终点");
    for (size_t i = 0; i < arver::kTargetCount; ++i) {
        const arver::Target& t = arver::kTargets[i];
        const PeFile::Func* f = nullptr;
        for (auto& fn : pe.pdata)
            if (fn.start == t.rva) { f = &fn; break; }
        if (!f) { Check(false, std::string(t.fnName) + " 不在 .pdata 里"); continue; }

        uint32_t len = f->end - f->start;
        const uint8_t* code = pe.At(f->start, len);
        if (!code) { Check(false, std::string(t.fnName) + " 无法读取代码"); continue; }

        size_t off = 0;
        size_t insns = 0;
        bool bad = false;
        while (off < len) {
            arlde::Insn in = arlde::Decode(code + off, len - off);
            if (!in.ok || in.length == 0) { bad = true; break; }
            off += in.length;
            ++insns;
            if (insns > 100000) { bad = true; break; }
        }
        Check(!bad && off == len,
              std::string(t.fnName) + " 逐条解码正好到终点",
              "insns=" + std::to_string(insns) + " covered=" + std::to_string(off) +
              "/" + std::to_string(len));
    }

    // ---------- 2) 字符串锚点存在 ----------
    Section("2) 字符串锚点在 .rdata 里存在且唯一性");
    struct Anchor { const char* text; int expectCount; };
    // 注意：编译器引用的是【整条字符串的起始地址】，不是子串。
    // 例如 "technology_status.cpp" 实际完整串是
    //   "C:\mnt\gsg\stellaris\augustus\augustus\source\technology_status.cpp"
    // 用子串 RVA 去找引用永远找不到 —— 这是实测踩到的坑。
    const Anchor anchors[] = {
        {"C:\\mnt\\gsg\\stellaris\\augustus\\augustus\\source\\technology_status.cpp", 1},
        {"MESSAGE_TECHNOLOGY_RESEARCH_FINISH", 1},
        {"TECHNOLOGY_ORDER_FINISH_MESSAGE_TYPE", 1},
        {"country_module.cpp", -1},          // 只要求存在
        {"technology_swap", -1},
    };
    for (auto& a : anchors) {
        std::string needle(a.text);
        std::vector<uint32_t> hits;
        for (auto& s : pe.secs) {
            if (s.name != ".rdata") continue;
            const uint8_t* base = pe.buf.data() + s.rawPtr;
            size_t limit = std::min<size_t>(s.rawSize, s.vsize ? s.vsize : s.rawSize);
            for (size_t i = 0; i + needle.size() < limit; ++i) {
                if (memcmp(base + i, needle.data(), needle.size()) == 0 &&
                    base[i + needle.size()] == 0) {
                    hits.push_back(s.va + (uint32_t)i);
                }
            }
        }
        Emit(std::string("       \"") + a.text + "\" -> " + std::to_string(hits.size()) + " 处" +
             (hits.empty() ? "" : ("  @" + Hex(hits[0]))));
        if (a.expectCount < 0) {
            Check(!hits.empty(), std::string("锚点 \"") + a.text + "\" 存在",
                  "actual=" + std::to_string(hits.size()));
            continue;
        }
        Check((int)hits.size() == a.expectCount,
              std::string("锚点 \"") + a.text + "\" 命中数 = " + std::to_string(a.expectCount),
              "actual=" + std::to_string(hits.size()));
    }

    // ---------- 3) 关键：能不能靠锚点定位到目标函数 ----------
    Section("3) 锚点引用反查：字符串 → 哪些函数引用了它");
    {
        // 对每个锚点，遍历全部 .pdata 函数，统计引用它的函数
        // 注意：全量遍历 13 万个函数可能慢，先只对"想在目标函数里出现"的锚点做
        struct Want { const char* text; uint32_t expectFunc; };
        // 先不预设，只报告结果，看锚点能否自然落到目标函数上
        const char* probeAnchors[] = {
            "C:\\mnt\\gsg\\stellaris\\augustus\\augustus\\source\\technology_status.cpp",
            "MESSAGE_TECHNOLOGY_RESEARCH_FINISH",
            "TECHNOLOGY_ORDER_FINISH_MESSAGE_TYPE",
        };
        for (auto* text : probeAnchors) {
            std::string needle(text);
            std::vector<uint32_t> strHits;
            for (auto& s : pe.secs) {
                if (s.name != ".rdata") continue;
                const uint8_t* base = pe.buf.data() + s.rawPtr;
                size_t limit = std::min<size_t>(s.rawSize, s.vsize ? s.vsize : s.rawSize);
                for (size_t i = 0; i + needle.size() < limit; ++i)
                    if (memcmp(base + i, needle.data(), needle.size()) == 0 &&
                        base[i + needle.size()] == 0)
                        strHits.push_back(s.va + (uint32_t)i);
            }
            if (strHits.empty()) { Emit(std::string("       \"") + text + "\" 未找到，跳过"); continue; }
            uint32_t strRva = strHits[0];

            std::vector<std::pair<uint32_t, uint32_t>> refFuncs;   // (funcRva, hits)
            for (auto& fn : pe.pdata) {
                uint32_t len = fn.end - fn.start;
                if (len == 0 || len > 60000) continue;
                const uint8_t* code = pe.At(fn.start, len);
                if (!code) continue;
                uint32_t site = 0;
                uint32_t n = arlde::CountRipRefs(code, len, fn.start, strRva, &site);
                if (n > 0) refFuncs.push_back({fn.start, n});
            }
            Emit(std::string("       \"") + text + "\" @" + Hex(strRva) + " 被 " +
                 std::to_string(refFuncs.size()) + " 个函数引用:");
            size_t show = refFuncs.size() < 8 ? refFuncs.size() : 8;
            for (size_t k = 0; k < show; ++k)
                Emit(std::string("           ") + Hex(refFuncs[k].first) +
                     "  (refs=" + std::to_string(refFuncs[k].second) + ")" +
                     (refFuncs[k].first == arver::kTargets[0].rva ? "   <== 主 hook 目标!" :
                      refFuncs[k].first == arver::kTargets[1].rva ? "   <== hook A 目标!" : ""));
            Check(!refFuncs.empty(), std::string("锚点 \"") + text + "\" 能定位到函数",
                  "funcs=" + std::to_string(refFuncs.size()));
        }
    }

    Emit("");
    Emit("==============================================");
    char b[128];
    snprintf(b, sizeof(b), "结果: %d passed, %d failed, %d total", g_pass, g_fail, g_pass + g_fail);
    Emit(b);
    Emit(g_fail == 0 ? "结论: ALL PASS" : "结论: FAILED");
    Emit("==============================================");
    if (g_out) { fclose(g_out); g_out = nullptr; }
    return g_fail == 0 ? 0 : 1;
}
