// gate_realcheck.cpp —— 用【真实的 stellaris.exe】跑一遍闸门
//
// gate_selftest 用假映像验证逻辑；这里验证"真解析器"能不能从真实的
// PE / .pdata / SHA256 / 内嵌 buildId 里读出和 ar_version.h 一致的值。
//
// 它故意加载 exe 为 DATA 映像（不执行游戏），所以可以安全地在没开游戏时跑：
//   LoadLibraryExA(path, NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE)
// 但那种方式拿到的基址不是 RVA 可寻址的正常映像。
// 因此这里用「自己映射」的方式模拟进程：
//   - SHA256 / buildId / PE 头 / .pdata 全部从磁盘读（和真实 DLL 一致）
//   - 序言字节也从磁盘按 RVA 换算成文件偏移去读
// 这样能验证除"读进程内存"外的一切。
//
// 编译（注意 -lbcrypt）：
//   g++ -std=c++17 -O2 -o gate_realcheck.exe gate_realcheck.cpp -lkernel32 -lbcrypt
// 运行：
//   ./gate_realcheck.exe "E:/Steam/steamapps/common/Stellaris/stellaris.exe" [--log FILE]
#include <windows.h>
#include <bcrypt.h>
#include <cstdio>
#include <string>
#include <vector>

#include "ar_gate.h"

static int g_pass = 0, g_fail = 0;
static FILE* g_out = nullptr;
static void Emit(const std::string& s) {
    fputs(s.c_str(), stdout); fputc('\n', stdout);
    if (g_out) { fputs(s.c_str(), g_out); fputc('\n', g_out); fflush(g_out); }
}
static void Section(const std::string& n) { Emit(""); Emit("=== " + n + " ==="); }
static void Check(bool c, const std::string& what, const std::string& detail = "") {
    if (c) { ++g_pass; Emit("  [PASS] " + what + (detail.empty() ? "" : "   (" + detail + ")")); }
    else   { ++g_fail; Emit("  [FAIL] " + what + (detail.empty() ? "" : "   (" + detail + ")")); }
}
static std::string Hex(uint64_t v) {
    static const char* d = "0123456789ABCDEF";
    std::string s(16, '0');
    for (int i = 15; i >= 0; --i) { s[i] = d[v & 0xF]; v >>= 4; }
    return s;
}

// 把一个文件的映像按 RVA 暴露成 IImage（不执行它）
class FileImage : public argate::IImage {
public:
    bool Load(const std::string& path) {
        path_ = path;
        HANDLE h = CreateFileA(path.c_str(), GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return false;
        LARGE_INTEGER sz;
        if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0) { CloseHandle(h); return false; }
        buf_.resize((size_t)sz.QuadPart);
        DWORD rd = 0, got = 0;
        while (got < buf_.size()) {
            DWORD chunk = (DWORD)((buf_.size() - got) > (1u << 20) ? (1u << 20) : (buf_.size() - got));
            if (!ReadFile(h, buf_.data() + got, chunk, &rd, nullptr) || rd == 0) {
                CloseHandle(h); return false;
            }
            got += rd;
        }
        CloseHandle(h);

        if (buf_.size() < 0x200 || !(buf_[0] == 'M' && buf_[1] == 'Z')) return false;
        uint32_t peOff = *(uint32_t*)(buf_.data() + 0x3c);
        if (!(buf_[peOff] == 'P' && buf_[peOff + 1] == 'E')) return false;
        uint16_t nsec = *(uint16_t*)(buf_.data() + peOff + 6);
        uint16_t optSize = *(uint16_t*)(buf_.data() + peOff + 20);
        uint32_t optOff = peOff + 24;
        if (*(uint16_t*)(buf_.data() + optOff) != 0x20b) return false;
        sizeOfImage_ = *(uint32_t*)(buf_.data() + optOff + 56);
        uint32_t secOff = optOff + optSize;
        for (uint16_t i = 0; i < nsec; ++i) {
            uint32_t o = secOff + (uint32_t)i * 40;
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
                uint32_t count = s.rawSize / 12;
                for (uint32_t k = 0; k < count; ++k) {
                    uint32_t eo = s.rawPtr + k * 12;
                    if (eo + 12 > buf_.size()) break;
                    pdata_.push_back({*(uint32_t*)(buf_.data() + eo),
                                      *(uint32_t*)(buf_.data() + eo + 4)});
                }
            }
        }
        return !secs_.empty();
    }

    const char* Name() const override { return path_.c_str(); }
    uint64_t Base() const override { return arver::kImageBase; }
    uint64_t Size() const override { return sizeOfImage_; }
    bool IsExecutable(uint32_t rva) const override {
        for (auto& s : secs_)
            if (rva >= s.va && rva < s.va + s.vsize)
                return (s.chars & IMAGE_SCN_MEM_EXECUTE) != 0;
        return false;
    }
    bool ReadBytes(uint32_t rva, void* dst, size_t n) const override {
        for (auto& s : secs_) {
            if (rva < s.va || rva >= s.va + s.vsize) continue;
            uint32_t off = s.rawPtr + (rva - s.va);
            if (off + n > buf_.size()) return false;
            memcpy(dst, buf_.data() + off, n);
            return true;
        }
        return false;
    }
    bool IsFunctionStart(uint32_t rva, uint32_t* funcLen) const override {
        size_t lo = 0, hi = pdata_.size();
        while (lo < hi) {
            size_t mid = (lo + hi) / 2;
            if (pdata_[mid].start == rva) {
                if (funcLen) *funcLen = pdata_[mid].end - pdata_[mid].start;
                return true;
            }
            if (pdata_[mid].start < rva) lo = mid + 1; else hi = mid;
        }
        return false;
    }
    std::string Sha256() const override { return sha256_; }
    std::string EmbeddedBuildId() const override { return buildId_; }

    void SetSha256(const std::string& s) { sha256_ = s; }
    void SetBuildId(const std::string& s) { buildId_ = s; }
    const std::string& BuildId() const { return buildId_; }
    const std::string& Sha() const { return sha256_; }

private:
    struct Sec { std::string name; uint32_t va, vsize, rawSize, rawPtr, chars; };
    struct Func { uint32_t start, end; };
    std::string path_;
    std::vector<uint8_t> buf_;
    std::vector<Sec> secs_;
    std::vector<Func> pdata_;
    uint64_t sizeOfImage_ = 0;
    std::string sha256_;
    std::string buildId_;
};

// 用 bcrypt 算 SHA256（与 DLL 里同一套 API）
static std::string FileSha256(const std::string& path) {
    HANDLE h = CreateFileA(path.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return std::string();
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    std::string hex;
    DWORD cbObj = 0, cbHash = 0, cbData = 0;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) {
        CloseHandle(h); return std::string();
    }
    do {
        if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbObj, sizeof(cbObj), &cbData, 0) != 0) break;
        if (BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&cbHash, sizeof(cbHash), &cbData, 0) != 0) break;
        std::vector<uint8_t> obj(cbObj), digest(cbHash);
        if (BCryptCreateHash(hAlg, &hHash, obj.data(), cbObj, nullptr, 0, 0) != 0) break;
        std::vector<uint8_t> chunk(1 << 20);
        DWORD rd = 0;
        bool okAll = true;
        while (ReadFile(h, chunk.data(), (DWORD)chunk.size(), &rd, nullptr) && rd > 0) {
            if (BCryptHashData(hHash, chunk.data(), rd, 0) != 0) { okAll = false; break; }
        }
        if (!okAll) break;
        if (BCryptFinishHash(hHash, digest.data(), cbHash, 0) != 0) break;
        static const char* d = "0123456789abcdef";
        hex.reserve(cbHash * 2);
        for (DWORD i = 0; i < cbHash; ++i) { hex += d[digest[i] >> 4]; hex += d[digest[i] & 0xF]; }
    } while (0);
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    CloseHandle(h);
    return hex;
}

// 找内嵌 buildId（和 DLL 里的逻辑一致）
static std::string FindBuildId(const std::string& path) {
    HANDLE h = CreateFileA(path.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return std::string();
    LARGE_INTEGER sz;
    if (!GetFileSizeEx(h, &sz)) { CloseHandle(h); return std::string(); }
    size_t limit = (size_t)((sz.QuadPart < (64LL << 20)) ? sz.QuadPart : (64LL << 20));
    std::vector<char> buf(limit);
    DWORD rd = 0;
    if (!ReadFile(h, buf.data(), (DWORD)limit, &rd, nullptr)) { CloseHandle(h); return std::string(); }
    CloseHandle(h);
    std::string hay(buf.data(), rd);
    size_t pos = 0;
    while ((pos = hay.find(" v", pos)) != std::string::npos) {
        size_t hh = pos + 2, q = hh;
        int dots = 0;
        while (q < hay.size() && q - hh < 16 &&
               ((hay[q] >= '0' && hay[q] <= '9') || hay[q] == '.')) {
            if (hay[q] == '.') ++dots;
            ++q;
        }
        if (dots != 2) { ++pos; continue; }
        while (q < hay.size() && (hay[q] == ' ' || hay[q] == '\t')) ++q;
        if (q + 32 > hay.size()) { ++pos; continue; }
        bool ok = true;
        for (size_t i = 0; i < 32; ++i) {
            char c = hay[q + i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) { ok = false; break; }
        }
        if (!ok) { ++pos; continue; }
        size_t r = q + 32;
        while (r < hay.size() && (hay[r] == ' ' || hay[r] == '\t')) ++r;
        if (r < hay.size() && hay[r] == '(') return hay.substr(q, 32);
        ++pos;
    }
    return std::string();
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
    Emit("闸门真机验证：对真实 stellaris.exe 跑完整检查");
    Emit("目标: " + path);
    Emit("==============================================");

    FileImage img;
    if (!img.Load(path)) { Emit("FATAL: cannot load PE: " + path); return 2; }

    // ---- 1) 真解析器读出的值必须和 ar_version.h 一致 ----
    Section("1) 生成值 vs 真实 exe");
    std::string sha = FileSha256(path);
    std::string buildId = FindBuildId(path);
    img.SetSha256(sha);
    img.SetBuildId(buildId);

    Emit("  真实 sha256 : " + sha);
    Emit("  头文件 sha256: " + std::string(arver::kSupportedSha256));
    Emit("  真实 buildId: " + buildId);
    Emit("  头文件 buildId: " + std::string(arver::kSupportedBuildId));

    Check(!sha.empty(), "能算出 SHA256（文件可共享读取）");
    Check(sha == std::string(arver::kSupportedSha256),
          "SHA256 与 ar_version.h 完全一致", sha.substr(0, 16) + "...");
    Check(buildId == std::string(arver::kSupportedBuildId),
          "buildId 与 ar_version.h 完全一致", buildId);
    Check(img.Size() == arver::kSupportedSizeOfImage, "SizeOfImage 与头文件一致",
          std::to_string(img.Size()));

    // ---- 2) 真实 exe 应通过闸门 ----
    Section("2) 真实 exe 通过闸门");
    argate::Report rep = argate::Inspect(img);
    Emit("  state=" + std::string(argate::StateName(rep.state)) +
         " anchor=" + argate::AnchorName(rep.anchor));
    for (auto& t : rep.targets) {
        Emit(std::string("    ") + (t.Ok() ? "[ok]   " : "[FAIL] ") + t.fnName +
             " rva=0x" + Hex(t.rva).substr(12) +
             " fnLen=" + std::to_string(t.actualFuncLen) +
             (t.Ok() ? "" : ("  -> " + t.detail)));
    }
    Check(rep.state == argate::State::FullyInstalled,
          "真实 exe → FullyInstalled", argate::StateName(rep.state));
    Check(rep.anchor == argate::Anchor::Sha256Exact, "版本锚 = sha256-exact");
    bool allTargetsOk = true;
    for (auto& t : rep.targets) if (!t.Ok()) allTargetsOk = false;
    Check(allTargetsOk, "全部 " + std::to_string(arver::kTargetCount) + " 个目标通过",
          "n=" + std::to_string(rep.targets.size()));

    // ---- 3) 逐项确认每个目标在真实 exe 里的实际值 ----
    Section("3) 每个目标的真实函数长度");
    for (size_t i = 0; i < arver::kTargetCount; ++i) {
        const arver::Target& t = arver::kTargets[i];
        uint32_t len = 0;
        bool isFunc = img.IsFunctionStart(t.rva, &len);
        Check(isFunc && len == t.funcLen,
              std::string(t.fnName) + " 是函数入口且长度 = " + std::to_string(t.funcLen),
              "actual=" + std::to_string(len));
    }

    // ---- 4) 负向：改坏 SHA & 序言，必须被拒 ----
    Section("4) 负向：篡改后必须被拒（在真 exe 上）");
    {
        FileImage bad = img;
        bad.SetSha256(std::string(64, '0'));
        bad.SetBuildId("ffffffffffffffffffffffffffffffff");
        argate::Report r = argate::Inspect(bad);
        Check(r.state == argate::State::VersionRejected,
              "假 SHA + 假 buildId → VersionRejected", argate::StateName(r.state));
        // 负向验证发现的缺陷：只检查 targets.empty() 不够 ——
        // 当 Inspect() 压根没开始检查（state=not-checked）时 targets 也是空的，
        // 会导致本条假通过。必须同时确认 state 确实是 VersionRejected。
        Check(r.state == argate::State::VersionRejected && r.targets.empty(),
              "版本被拒时不做多余检查（且确认是因版本拒绝而停）",
              std::string("state=") + argate::StateName(r.state) +
              " targets=" + std::to_string(r.targets.size()));
    }
    // 序言篡改：改 FileImage 的 ReadBytes 结果不方便，用另一个子类
    class Tampered : public FileImage {
    public:
        uint32_t target = 0;
        size_t idx = 0;
        uint8_t val = 0;
        bool ReadBytes(uint32_t rva, void* dst, size_t n) const override {
            if (!FileImage::ReadBytes(rva, dst, n)) return false;
            if (rva == target && idx < n) ((uint8_t*)dst)[idx] = val;
            return true;
        }
    };
    {
        Tampered bad;
        bad.Load(path);
        bad.SetSha256(sha);
        bad.SetBuildId(buildId);
        bad.target = arver::kTargets[0].rva;
        bad.idx = 0;
        bad.val = 0xCC;
        argate::Report r = argate::Inspect(bad);
        Check(r.state == argate::State::FingerprintRejected,
              "真 exe 上篡改序言 → FingerprintRejected（版本对但被改过）",
              argate::StateName(r.state));
    }

    Emit("");
    Emit("==============================================");
    char buf[128];
    snprintf(buf, sizeof(buf), "结果: %d passed, %d failed, %d total",
             g_pass, g_fail, g_pass + g_fail);
    Emit(buf);
    Emit(g_fail == 0 ? "结论: ALL PASS" : "结论: FAILED");
    Emit("==============================================");
    if (g_out) { fclose(g_out); g_out = nullptr; }
    return g_fail == 0 ? 0 : 1;
}
