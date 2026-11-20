// anchor_perturb_test.cpp —— 锚点解析的"版本漂移"稳健性测试（t7 核心验收）
//
// 为什么需要它：
//   证明"锚点解析跨版本可用"不能只靠在原版 exe 上跑一次 —— 那和硬编码 RVA
//   没有区别（原版上硬编码当然也对）。必须构造"RVA 全变了"的镜像，看解析器
//   还能不能凭内容找到正确函数。
//
// 做法：把整个映像的 RVA 统一加一个偏移（模拟版本漂移/重新链接后地址整体位移），
// 同时保持代码字节、字符串、.pdata 条目之间的相对关系不变。
// 解析器如果依赖硬编码地址就会全错；如果真靠内容锚定就会照旧命中。
//
// 编译： g++ -std=c++17 -O2 -static -o anchor_perturb_test.exe anchor_perturb_test.cpp
// 运行： ./anchor_perturb_test.exe "E:/.../stellaris.exe" [--log FILE]
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
#include <map>

#include "ar_resolve.h"

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

// 一个"整体平移"的映像：所有对外暴露的 RVA 都加 SHIFT，
// 内部读文件时再减回去。等价于"游戏重新链接后函数整体挪位，但内容不变"。
class ShiftedImage : public aranchor::IAnchorImage {
public:
    bool Load(const std::string& path, uint32_t shift) {
        shift_ = shift;
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
        sizeOfImage_ = *(uint32_t*)(buf_.data() + optOff + 56) + shift;
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
            secs_.push_back(s);
            if (s.name == ".pdata") {
                uint32_t cnt = s.rawSize / 12;
                for (uint32_t k = 0; k < cnt; ++k) {
                    uint32_t eo = s.rawPtr + k * 12;
                    uint32_t a = *(uint32_t*)(buf_.data() + eo);
                    uint32_t b = *(uint32_t*)(buf_.data() + eo + 4);
                    funcs_.push_back(std::make_pair(a + shift_, b + shift_));
                }
            }
        }
        return !secs_.empty();
    }

    uint64_t Size() const override { return (uint64_t)sizeOfImage_ + 0x1000; }

    bool IsExecutable(uint32_t) const override { return true; }

    // 对外 RVA → 内部真实 RVA
    uint32_t Unshift(uint32_t rva) const { return (rva >= shift_) ? rva - shift_ : rva; }

    bool ReadBytes(uint32_t rva, void* dst, size_t n) const override {
        uint32_t real = Unshift(rva);
        for (size_t i = 0; i < secs_.size(); ++i) {
            const Sec& s = secs_[i];
            if (real < s.va || real >= s.va + s.vsize) continue;
            uint32_t off = s.rawPtr + (real - s.va);
            if ((size_t)off + n > buf_.size()) return false;
            memcpy(dst, buf_.data() + off, n);
            return true;
        }
        return false;
    }

    void EnumFunctions(std::vector<std::pair<uint32_t, uint32_t> >* out) const override {
        *out = funcs_;
    }

    void FindStrings(const char* sectionName, const char* needle,
                     std::vector<uint32_t>* out) const override {
        out->clear();
        size_t nlen = strlen(needle);
        for (size_t i = 0; i < secs_.size(); ++i) {
            const Sec& s = secs_[i];
            if (s.name != sectionName) continue;
            size_t limit = std::min<size_t>(s.rawSize, s.vsize ? s.vsize : s.rawSize);
            if (limit < nlen + 1) continue;
            const uint8_t* b = buf_.data() + s.rawPtr;
            for (size_t p = 0; p + nlen + 1 <= limit; ++p) {
                if (memcmp(b + p, needle, nlen) != 0) continue;
                if (b[p + nlen] != 0) continue;
                if (p != 0 && b[p - 1] != 0) continue;
                out->push_back(s.va + (uint32_t)p + shift_);
            }
        }
    }

    std::string Describe() const override { return "ShiftedImage"; }

private:
    struct Sec { std::string name; uint32_t va, vsize, rawSize, rawPtr; };
    std::vector<uint8_t> buf_;
    std::vector<Sec> secs_;
    std::vector<std::pair<uint32_t, uint32_t> > funcs_;
    uint32_t shift_ = 0;
    uint32_t sizeOfImage_ = 0;
};

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
    Emit("锚点解析：版本漂移稳健性测试");
    Emit("（把整个映像的 RVA 统一平移，模拟跨版本地址变化）");
    Emit("目标: " + path);
    Emit("==============================================");

    // 基准（未平移）：确认解析器本身正确
    struct Case { uint32_t shift; const char* name; };
    const Case cases[] = {
        {0x000000, "baseline (no shift)"},
        {0x001000, "shift +0x1000"},
        {0x010000, "shift +0x10000"},
        {0x100000, "shift +0x100000"},
        {0x300000, "shift +0x300000"},
        {0x800000, "shift +0x800000"},
    };

    for (size_t ci = 0; ci < sizeof(cases) / sizeof(cases[0]); ++ci) {
        Section(std::string("用例: ") + cases[ci].name);
        ShiftedImage img;
        if (!img.Load(path, cases[ci].shift)) {
            Check(false, "加载映像失败");
            continue;
        }
        arresolve::Resolver r;
        r.img = &img;
        // SEL/GETC 参照点也要随映像一起平移（真实漂移时它们的地址同样会变）
        r.selRva = arver::kSelRva_Ref + cases[ci].shift;
        r.getcRva = arver::kGetcRva_Ref + cases[ci].shift;
        r.Run();

        const arresolve::Addr* m = r.Get(arresolve::Role::MainHook);
        const arresolve::Addr* a = r.Get(arresolve::Role::HookA);

        // 期望值 = 已知 RVA + 本次平移量（因为映像整体挪了这么多）
        uint32_t wantMain  = arver::kTargets[0].rva + cases[ci].shift;
        uint32_t wantHookA = arver::kTargets[1].rva + cases[ci].shift;

        char buf[256];
        snprintf(buf, sizeof(buf), "main-hook 解析 = 0x%X (期望 0x%X)",
                 m ? m->rva : 0, wantMain);
        Check(m && m->rva == wantMain, buf);

        snprintf(buf, sizeof(buf), "hook-a 解析 = 0x%X (期望 0x%X)",
                 a ? a->rva : 0, wantHookA);
        Check(a && a->rva == wantHookA, buf);

        Check(r.RequiredReady(), "必需组就绪");
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
