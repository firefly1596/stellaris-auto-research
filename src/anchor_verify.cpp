// anchor_verify.cpp —— 在真实 stellaris.exe 上验证锚点解析
//
// 这是 t7 的**核心验收**：不靠硬编码 RVA，纯从二进制内容解析出
//   hook-a = kTargets[1].rva（字符串锚点，两条互证）
//   main-hook = kTargets[0].rva（从 hook-a 的调用链推导）
// 然后与"已知正确答案"比对，证明解析器是对的。
//
// 编译： g++ -std=c++17 -O2 -o anchor_verify.exe anchor_verify.cpp
// 运行： ./anchor_verify.exe "E:/.../stellaris.exe" [--log FILE]
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>

#include "ar_anchor.h"
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
static std::string H(uint32_t v) {
    char b[16];
    static const char* d = "0123456789ABCDEF";
    b[0] = '0'; b[1] = 'x';
    for (int i = 0; i < 8; ++i) b[2 + i] = d[(v >> ((7 - i) * 4)) & 0xF];
    b[10] = 0;
    return std::string(b);
}

// ---------------- 文件映像（实现 IAnchorImage） ----------------
class FileAnchorImage : public aranchor::IAnchorImage {
public:
    bool Load(const std::string& path) {
        HANDLE h = CreateFileA(path.c_str(), GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return false;
        LARGE_INTEGER sz;
        if (!GetFileSizeEx(h, &sz)) { CloseHandle(h); return false; }
        buf_.resize((size_t)sz.QuadPart);
        DWORD got = 0;
        while (got < buf_.size()) {
            DWORD chunk = (DWORD)std::min<size_t>(buf_.size() - got, 1u << 20);
            DWORD rd = 0;
            if (!ReadFile(h, buf_.data() + got, chunk, &rd, nullptr) || !rd) {
                CloseHandle(h); return false;
            }
            got += rd;
        }
        CloseHandle(h);

        uint32_t peOff = *(uint32_t*)(buf_.data() + 0x3c);
        uint16_t nsec = *(uint16_t*)(buf_.data() + peOff + 6);
        uint16_t optSize = *(uint16_t*)(buf_.data() + peOff + 20);
        uint32_t optOff = peOff + 24;
        sizeOfImage_ = *(uint32_t*)(buf_.data() + optOff + 56);
        uint32_t secOff = optOff + optSize;
        for (uint16_t i = 0; i < nsec; ++i) {
            uint32_t o = secOff + i * 40;
            Sec s;
            char nm[9] = {0};
            memcpy(nm, buf_.data() + o, 8);
            s.name = nm;
            s.vsize = *(uint32_t*)(buf_.data() + o + 8);
            s.va = *(uint32_t*)(buf_.data() + o + 12);
            s.rawSize = *(uint32_t*)(buf_.data() + o + 16);
            s.rawPtr = *(uint32_t*)(buf_.data() + o + 20);
            s.chars = *(uint32_t*)(buf_.data() + o + 36);
            secs_.push_back(s);
            if (s.name == ".pdata") {
                uint32_t cnt = s.rawSize / 12;
                for (uint32_t k = 0; k < cnt; ++k) {
                    uint32_t eo = s.rawPtr + k * 12;
                    funcs_.push_back(std::make_pair(*(uint32_t*)(buf_.data() + eo),
                                                    *(uint32_t*)(buf_.data() + eo + 4)));
                }
            }
        }
        return !secs_.empty();
    }

    uint64_t Size() const override { return sizeOfImage_; }

    bool IsExecutable(uint32_t rva) const override {
        for (size_t i = 0; i < secs_.size(); ++i) {
            const Sec& s = secs_[i];
            if (rva >= s.va && rva < s.va + s.vsize)
                return (s.chars & IMAGE_SCN_MEM_EXECUTE) != 0;
        }
        return false;
    }

    bool ReadBytes(uint32_t rva, void* dst, size_t n) const override {
        for (size_t i = 0; i < secs_.size(); ++i) {
            const Sec& s = secs_[i];
            if (rva < s.va || rva >= s.va + s.vsize) continue;
            uint32_t off = s.rawPtr + (rva - s.va);
            if ((size_t)off + n > buf_.size()) return false;
            memcpy(dst, buf_.data() + off, n);
            return true;
        }
        return false;
    }

    void EnumFunctions(std::vector<std::pair<uint32_t, uint32_t> >* out) const override {
        *out = funcs_;
    }

    // 关键：只匹配【完整的、NUL 结尾的】字符串
    void FindStrings(const char* sectionName, const char* needle,
                     std::vector<uint32_t>* out) const override {
        out->clear();
        size_t nlen = strlen(needle);
        for (size_t i = 0; i < secs_.size(); ++i) {
            const Sec& s = secs_[i];
            if (s.name != sectionName) continue;
            size_t limit = std::min<size_t>(s.rawSize, s.vsize ? s.vsize : s.rawSize);
            if (limit < nlen + 1) continue;
            const uint8_t* base = buf_.data() + s.rawPtr;
            for (size_t p = 0; p + nlen + 1 <= limit; ++p) {
                if (memcmp(base + p, needle, nlen) != 0) continue;
                if (base[p + nlen] != 0) continue;              // 必须紧跟 NUL
                // 且前面必须是 NUL（即它是整条字符串的开头）
                if (p != 0 && base[p - 1] != 0) continue;
                out->push_back(s.va + (uint32_t)p);
            }
        }
    }

    std::string Describe() const override { return "FileAnchorImage"; }

private:
    struct Sec {
        std::string name;
        uint32_t va, vsize, rawSize, rawPtr, chars;
    };
    std::vector<uint8_t> buf_;
    std::vector<Sec> secs_;
    std::vector<std::pair<uint32_t, uint32_t> > funcs_;
    uint32_t sizeOfImage_ = 0;
};

// =====================================================================
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
    Emit("锚点解析验证（不依赖硬编码 RVA）");
    Emit("目标: " + path);
    Emit("==============================================");

    FileAnchorImage img;
    if (!img.Load(path)) { Emit("FATAL: cannot load PE"); return 2; }

    // 已知正确答案（来自 ar_version.h，仅用于【验证】解析器是否正确）
    const uint32_t kHookA = arver::kTargets[1].rva;
    const uint32_t kMainHook = arver::kTargets[0].rva;

    // ---------- 1) 字符串锚点解析 hookA ----------
    Section("1) 字符串锚点 → hookA（需 >=2 票互证）");
    const aranchor::AnchorSpec hookAAnchors[] = {
        {"MESSAGE_TECHNOLOGY_RESEARCH_FINISH", ".rdata",
         "科研完成消息 key，只在技术状态里用"},
        {"TECHNOLOGY_ORDER_FINISH_MESSAGE_TYPE", ".rdata",
         "科研完成消息类型，只在技术状态里用"},
    };
    aranchor::VoteResult va = aranchor::ResolveByStrings(
        img, hookAAnchors, sizeof(hookAAnchors) / sizeof(hookAAnchors[0]), 60000, 2);
    Emit("  解析过程:");
    {
        std::string d = va.detail;
        size_t pos = 0;
        while (pos < d.size()) {
            size_t nl = d.find('\n', pos);
            Emit("    " + d.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos));
            if (nl == std::string::npos) break;
            pos = nl + 1;
        }
    }
    Check(va.ok(), "字符串锚点解析出了 hookA",
          va.ok() ? (H(va.rva) + " votes=" + std::to_string(va.votes)) : "unresolved");
    Check(va.rva == kHookA, std::string("解析结果 == ar_version.h 记录的 hook-a (0x") + [&]{char b[16];snprintf(b,sizeof(b),"%X",kHookA);return std::string(b);}() + ")",
          "got " + H(va.rva) + " want " + H(kHookA));
    Check(va.votes >= 2, "至少 2 个独立锚点互证", "votes=" + std::to_string(va.votes));

    // ---------- 2) 调用链推导 mainHook ----------
    Section("2) 调用链：hookA 的直接被调者中找出主 hook");
    std::vector<aranchor::CallEdge> edges;
    if (va.ok()) {
        edges = aranchor::DirectCallsFrom(img, va.rva);
        Emit("  hookA 直接调用 " + std::to_string(edges.size()) + " 个函数入口:");
        for (size_t i = 0; i < edges.size(); ++i) {
            char buf[128];
            snprintf(buf, sizeof(buf), "     -> %s  (call site %s)%s",
                     H(edges[i].callee).c_str(), H(edges[i].site).c_str(),
                     edges[i].callee == kMainHook ? "   <== 主 hook 目标!" : "");
            Emit(buf);
        }
    }
    Check(!edges.empty(), "hookA 的调用链解析成功",
          "edges=" + std::to_string(edges.size()));

    // 找 mainHook：在调用链里，用"函数长度 + 序言字节"作为互证
    // （不直接用 RVA，否则就不是锚点解析了）
    uint32_t derivedMain = 0;
    uint32_t derivedBy = 0;
    {
        std::vector<std::pair<uint32_t, uint32_t> > funcs;
        img.EnumFunctions(&funcs);
        for (size_t i = 0; i < edges.size(); ++i) {
            uint32_t callee = edges[i].callee;
            uint32_t len = 0;
            for (size_t k = 0; k < funcs.size(); ++k)
                if (funcs[k].first == callee) { len = funcs[k].second - funcs[k].first; break; }
            if (len == 0) continue;
            // 目标函数特征：长度 1000..2000（4.5.2/4.5.4 实测主 hook 都是 1294 字节）
            // 且序言是编译器为该函数生成的典型形态
            if (len < 1000 || len > 2000) continue;
            uint8_t pro[4] = {0};
            if (!img.ReadBytes(callee, pro, 4)) continue;
            // 通用的"保存 RSI/RDI 的叶级函数序言"特征：
            //   48 89 5C 24 ??  (mov [rsp+X], rbx)
            if (pro[0] == 0x48 && pro[1] == 0x89 && pro[2] == 0x5C && pro[3] == 0x24) {
                derivedMain = callee;
                derivedBy = edges[i].site;
                break;
            }
        }
    }
    Check(derivedMain != 0, "从调用链推导出主 hook 候选",
          derivedMain ? (H(derivedMain) + " via call site " + H(derivedBy)) : "not found");
    Check(derivedMain == kMainHook, std::string("推导结果 == ar_version.h 记录的主 hook (0x") + [&]{char b[16];snprintf(b,sizeof(b),"%X",kMainHook);return std::string(b);}() + ")",
          "got " + H(derivedMain) + " want " + H(kMainHook));

    // ---------- 3) 互证：结论与序言/长度一致 ----------
    Section("3) 互证：解析结果与 ar_version.h 的函数指纹一致");
    {
        std::vector<std::pair<uint32_t, uint32_t> > funcs;
        img.EnumFunctions(&funcs);
        const uint32_t rvas[2] = {va.rva ? va.rva : kHookA, derivedMain ? derivedMain : kMainHook};
        for (int i = 0; i < 2; ++i) {
            uint32_t rva = rvas[i];
            const arver::Target* t = nullptr;
            for (size_t k = 0; k < arver::kTargetCount; ++k)
                if (arver::kTargets[k].rva == rva) t = &arver::kTargets[k];
            if (!t) { Check(false, "找不到对应目标记录"); continue; }
            uint32_t len = 0;
            for (size_t k = 0; k < funcs.size(); ++k)
                if (funcs[k].first == rva) { len = funcs[k].second - funcs[k].first; break; }
            Check(len == t->funcLen,
                  std::string(t->fnName) + " 函数长度一致",
                  "len=" + std::to_string(len) + " want " + std::to_string(t->funcLen));
            uint8_t pro[arver::kPrologueLen] = {0};
            bool rd = img.ReadBytes(rva, pro, arver::kPrologueLen);
            Check(rd && memcmp(pro, t->expect, arver::kPrologueLen) == 0,
                  std::string(t->fnName) + " 序言字节一致");
        }
    }

    // ---------- 4) 稳健性：错误锚点不应乱认 ----------
    Section("4) 稳健性：错误/歧义锚点必须拒绝");
    {
        const aranchor::AnchorSpec bogus[] = {
            {"THIS_STRING_DOES_NOT_EXIST_ANYWHERE_12345", ".rdata", "不存在的锚点"},
        };
        aranchor::VoteResult v = aranchor::ResolveByStrings(img, bogus, 1, 60000, 1);
        Check(!v.ok(), "不存在的锚点 → 解析失败（不瞎猜）", std::string("rva=")+H(v.rva)+" votes="+std::to_string(v.votes));
    }
    {
        // 单独一个锚点只给 1 票，要求 2 票时必须失败
        const aranchor::AnchorSpec one[] = {
            {"MESSAGE_TECHNOLOGY_RESEARCH_FINISH", ".rdata", "单锚点"},
        };
        aranchor::VoteResult v = aranchor::ResolveByStrings(img, one, 1, 60000, 2);
        Check(!v.ok(), "只有 1 票但要求 >=2 票 → 拒绝", std::string("rva=")+H(v.rva)+" votes="+std::to_string(v.votes));
    }
    {
        // 子串用法（不是整条字符串）必须找不到 —— 记录这个坑
        const aranchor::AnchorSpec sub[] = {
            {"technology_status.cpp", ".rdata", "子串（不是完整串）"},
        };
        aranchor::VoteResult v = aranchor::ResolveByStrings(img, sub, 1, 60000, 1);
        Check(!v.ok(), "用子串当锚点 → 找不到（必须用完整字符串）", std::string("rva=")+H(v.rva)+" votes="+std::to_string(v.votes));
    }

    Emit("");
    Emit("==============================================");
    char b[160];
    snprintf(b, sizeof(b), "结果: %d passed, %d failed, %d total", g_pass, g_fail, g_pass + g_fail);
    Emit(b);
    Emit(g_fail == 0 ? "结论: ALL PASS" : "结论: FAILED");
    Emit("==============================================");
    if (g_out) { fclose(g_out); g_out = nullptr; }
    return g_fail == 0 ? 0 : 1;
}
