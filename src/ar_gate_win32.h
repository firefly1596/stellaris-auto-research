// ar_gate_win32.h —— 版本闸门的真实实现（把运行中的游戏进程包装成 IImage）
//
// 与 ar_gate.h 的关系：闸门逻辑在 ar_gate.h（纯逻辑、可离线测），
// 这里只负责"怎么问真实进程/真实文件"，不含任何判断逻辑。
//
// 两个容易踩的坑，这里都处理了：
//   1. 用 CreateFileA 打开 stellaris.exe 算 SHA256 时，游戏正以
//      FILE_SHARE_READ 打开着自己。必须以 FILE_SHARE_READ|WRITE|DELETE 打开，
//      否则会 Sharing Violation，导致"读不到哈希"→ 误判成版本不符。
//   2. 解析 .pdata 需要读 PE 头。运行中的映像头部不一定可读
//      （有些保护会把 PE 头设为 PAGE_READONLY/NOACCESS），所以优先从磁盘
//      读 PE 头，内存只用来取序言字节。
#pragma once
#ifndef AR_GATE_WIN32_H
#define AR_GATE_WIN32_H

#include <windows.h>
#include <bcrypt.h>
#include <cstdio>
#include <string>
#include <vector>

#include "ar_gate.h"

// bcrypt 的 SHA256 需要链接 -lbcrypt（MinGW 不支持 #pragma comment，编译命令里带上）

namespace argate {

class Win32Image : public IImage {
public:
    // exePath: 磁盘上的 stellaris.exe 路径（算 SHA256 / 读 PE 头用）
    // module : 已加载的模块句柄（取基址和序言字节用）
    bool Init(const std::string& exePath, HMODULE module) {
        exePath_ = exePath;
        module_ = module;
        if (!module_) return false;
        base_ = (uint64_t)module_;
        if (!ParsePeFromDisk()) return false;
        return true;
    }

    const char* Name() const override { return exePath_.c_str(); }
    uint64_t Base() const override { return base_; }
    uint64_t Size() const override { return sizeOfImage_; }

    bool IsExecutable(uint32_t rva) const override {
        for (size_t i = 0; i < sections_.size(); ++i) {
            const Sec& s = sections_[i];
            if (rva < s.va || rva >= s.va + s.vsize) continue;
            // 可执行 = IMAGE_SCN_MEM_EXECUTE，且不是纯 guard
            return (s.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        }
        return false;
    }

    bool ReadBytes(uint32_t rva, void* dst, size_t n) const override {
        if (rva >= sizeOfImage_) return false;
        const void* p = (const void*)(base_ + rva);
        // 不直接解引用：先确认这段内存可读（防止目标版本错得离谱时 AV）
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery(p, &mbi, sizeof(mbi))) return false;
        if (mbi.State != MEM_COMMIT) return false;
        if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return false;
        uintptr_t end = (uintptr_t)p + n;
        uintptr_t regionEnd = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (end > regionEnd) return false;
        memcpy(dst, p, n);
        return true;
    }

    bool IsFunctionStart(uint32_t rva, uint32_t* funcLen) const override {
        // .pdata 已从磁盘解析成有序表；二分查找
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

    std::string Sha256() const override {
        if (cachedSha_.empty()) cachedSha_ = ComputeFileSha256(exePath_);
        return cachedSha_;
    }

    std::string EmbeddedBuildId() const override {
        if (cachedBuildId_.empty()) cachedBuildId_ = FindEmbeddedBuildId(exePath_);
        return cachedBuildId_;
    }

    const std::string& ExePath() const { return exePath_; }

private:
    struct Sec { uint32_t va, vsize; uint32_t characteristics; };
    struct Func { uint32_t start, end; };

    std::string exePath_;
    HMODULE module_ = nullptr;
    uint64_t base_ = 0;
    uint64_t sizeOfImage_ = 0;
    std::vector<Sec> sections_;
    std::vector<Func> pdata_;
    mutable std::string cachedSha_;
    mutable std::string cachedBuildId_;

    static bool ReadWholeFile(const std::string& path, std::vector<uint8_t>* out) {
        // 关键：以允许共享的方式打开 —— 游戏正打开着自己的 exe
        HANDLE h = CreateFileA(path.c_str(), GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return false;
        LARGE_INTEGER sz;
        if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0 || sz.QuadPart > (1LL << 31)) {
            CloseHandle(h);
            return false;
        }
        out->resize((size_t)sz.QuadPart);
        size_t got = 0;
        while (got < out->size()) {
            DWORD chunk = (DWORD)((out->size() - got) > (1u << 20) ? (1u << 20)
                                                                  : (out->size() - got));
            DWORD rd = 0;
            if (!ReadFile(h, out->data() + got, chunk, &rd, nullptr) || rd == 0) {
                CloseHandle(h);
                return false;
            }
            got += rd;
        }
        CloseHandle(h);
        return true;
    }

    bool ParsePeFromDisk() {
        std::vector<uint8_t> b;
        if (!ReadWholeFile(exePath_, &b)) return false;
        if (b.size() < 0x200) return false;
        if (!(b[0] == 'M' && b[1] == 'Z')) return false;
        uint32_t peOff = *(uint32_t*)(b.data() + 0x3c);
        if (peOff + 24 > b.size()) return false;
        if (!(b[peOff] == 'P' && b[peOff + 1] == 'E')) return false;
        uint16_t optSize = *(uint16_t*)(b.data() + peOff + 20);
        uint16_t nsec = *(uint16_t*)(b.data() + peOff + 6);
        uint32_t optOff = peOff + 24;
        if (*(uint16_t*)(b.data() + optOff) != 0x20b) return false;   // PE32+
        sizeOfImage_ = *(uint32_t*)(b.data() + optOff + 56);

        uint32_t secOff = optOff + optSize;
        sections_.clear();
        for (uint16_t i = 0; i < nsec; ++i) {
            uint32_t o = secOff + (uint32_t)i * 40;
            if (o + 40 > b.size()) return false;
            Sec s;
            s.vsize = *(uint32_t*)(b.data() + o + 8);
            s.va = *(uint32_t*)(b.data() + o + 12);
            s.characteristics = *(uint32_t*)(b.data() + o + 36);
            sections_.push_back(s);
        }

        // 解析 .pdata（x64 异常目录，每个 12 字节：Begin, End, UnwindInfo）
        pdata_.clear();
        for (size_t i = 0; i < sections_.size(); ++i) {
            if (sections_[i].va == 0) continue;
            // 找到文件里的 raw 偏移
            uint32_t o = secOff + (uint32_t)i * 40;
            uint32_t rawPtr = *(uint32_t*)(b.data() + o + 20);
            uint32_t rawSize = *(uint32_t*)(b.data() + o + 16);
            // .pdata 的识别靠"在 .rdata 之后 + 大小能整除 12"不可靠，
            // 直接按名字判断：读节名
            char name[9] = {0};
            memcpy(name, b.data() + o, 8);
            if (strncmp(name, ".pdata", 8) != 0) continue;
            uint32_t count = rawSize / 12;
            for (uint32_t k = 0; k < count; ++k) {
                uint32_t eo = rawPtr + k * 12;
                if (eo + 12 > b.size()) break;
                Func f;
                f.start = *(uint32_t*)(b.data() + eo);
                f.end = *(uint32_t*)(b.data() + eo + 4);
                pdata_.push_back(f);
            }
            break;
        }
        // .pdata 已按 RVA 升序排列（PE 规范保证），可直接二分
        return !sections_.empty();
    }

    // SHA256（用 CNG/bcrypt，不自己实现算法）
    static std::string ComputeFileSha256(const std::string& path) {
        std::vector<uint8_t> b;
        if (!ReadWholeFile(path, &b)) return std::string();

        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_HASH_HANDLE hHash = nullptr;
        std::string hex;
        DWORD cbObj = 0, cbHash = 0, cbData = 0;
        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
            return std::string();
        do {
            if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                                  (PUCHAR)&cbObj, sizeof(cbObj), &cbData, 0) != 0) break;
            if (BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH,
                                  (PUCHAR)&cbHash, sizeof(cbHash), &cbData, 0) != 0) break;
            std::vector<uint8_t> obj(cbObj), digest(cbHash);
            if (BCryptCreateHash(hAlg, &hHash, obj.data(), cbObj, nullptr, 0, 0) != 0) break;
            if (BCryptHashData(hHash, b.data(), (ULONG)b.size(), 0) != 0) break;
            if (BCryptFinishHash(hHash, digest.data(), cbHash, 0) != 0) break;
            static const char* d = "0123456789abcdef";
            hex.reserve(cbHash * 2);
            for (DWORD i = 0; i < cbHash; ++i) {
                hex += d[digest[i] >> 4];
                hex += d[digest[i] & 0xF];
            }
        } while (0);
        if (hHash) BCryptDestroyHash(hHash);
        if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
        return hex;
    }

    // 在 exe 里找内嵌构建标识：
    //   "Cygnus v4.5.2  32709cf254181b032b1b309a6ea09776 (Oct  1 2026 18:22:01)"
    // 取里面那个 32 位十六进制串作为 buildId。
    static std::string FindEmbeddedBuildId(const std::string& path) {
        std::vector<uint8_t> b;
        if (!ReadWholeFile(path, &b)) return std::string();
        // 只扫前 64MB，版本串在 .rdata 里靠前的位置
        size_t limit = b.size() < (64u << 20) ? b.size() : (64u << 20);
        std::string hay((const char*)b.data(), limit);

        size_t pos = 0;
        while ((pos = hay.find(" v", pos)) != std::string::npos) {
            // 找形如 <Codename> vX.Y.Z  <32hex> 的位置
            size_t h = pos + 2;
            if (h + 32 > hay.size()) break;
            // 前向找一个 32 位十六进制串，且中间只隔空白
            size_t q = h;
            int dots = 0;
            // 跳过 X.Y.Z
            while (q < hay.size() && q - h < 16 &&
                   ((hay[q] >= '0' && hay[q] <= '9') || hay[q] == '.')) {
                if (hay[q] == '.') ++dots;
                ++q;
            }
            if (dots != 2) { ++pos; continue; }
            // 跳过空白
            while (q < hay.size() && (hay[q] == ' ' || hay[q] == '\t')) ++q;
            if (q + 32 > hay.size()) { ++pos; continue; }
            bool ok = true;
            for (size_t i = 0; i < 32; ++i) {
                char c = hay[q + i];
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) { ok = false; break; }
            }
            if (!ok) { ++pos; continue; }
            // 后面应该跟 " (" —— 编译时间
            size_t r = q + 32;
            while (r < hay.size() && (hay[r] == ' ' || hay[r] == '\t')) ++r;
            if (r < hay.size() && hay[r] == '(') return hay.substr(q, 32);
            ++pos;
        }
        return std::string();
    }
};

}  // namespace argate

#endif  // AR_GATE_WIN32_H
