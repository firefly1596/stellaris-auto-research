// ar_resolve_win32.h —— 锚点解析的真实实现（把运行中的游戏进程包装成 IAnchorImage）
//
// 与 ar_resolve.h / ar_anchor.h 的分工：
//   ar_lde.h       : 指令长度解码（纯逻辑）
//   ar_anchor.h    : 字符串锚点 + 调用链的通用算法（纯逻辑）
//   ar_resolve.h   : 目标角色编排 + 交叉验证（纯逻辑）
//   ar_resolve_win32.h : 本文件，只负责"怎么问真实进程"
//
// 实现要点（都是踩过的坑）：
//   1. PE 头优先从磁盘读：运行中的映像头部有时不可读（保护/只读），
//      而磁盘上的 stellaris.exe 一定可读。
//   2. 打开 exe 必须带 FILE_SHARE_READ|WRITE|DELETE —— 游戏正打开着自己，
//      否则 Sharing Violation，导致"读不到"被误判成"版本不符"。
//   3. 序言字节必须从【进程内存】读（那才是真正会被改写的字节）；
//      如果从磁盘读，别的 mod 已经 patch 过的内存我们看不见。
//   4. 所有内存访问先 VirtualQuery，绝不裸解引用（版本错得离谱时防 AV）。
#pragma once
#ifndef AR_RESOLVE_WIN32_H
#define AR_RESOLVE_WIN32_H

#include <windows.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>

#include "ar_resolve.h"

namespace arresolve {

class Win32AnchorImage : public aranchor::IAnchorImage {
public:
    bool Init(const std::string& exePath, uint64_t moduleBase) {
        exePath_ = exePath;
        base_ = moduleBase;
        if (!base_) return false;
        return ParsePeFromDisk();
    }

    uint64_t Size() const override { return sizeOfImage_; }

    bool IsExecutable(uint32_t rva) const override {
        for (size_t i = 0; i < secs_.size(); ++i) {
            const Sec& s = secs_[i];
            if (rva < s.va || rva >= s.va + s.vsize) continue;
            return (s.chars & IMAGE_SCN_MEM_EXECUTE) != 0;
        }
        return false;
    }

    bool ReadBytes(uint32_t rva, void* dst, size_t n) const override {
        if (rva >= sizeOfImage_) return false;
        const void* p = (const void*)(base_ + rva);
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
                if (b[p + nlen] != 0) continue;          // 必须紧跟 NUL（整串）
                if (p != 0 && b[p - 1] != 0) continue;   // 且必须是串首
                out->push_back(s.va + (uint32_t)p);
            }
        }
    }

    std::string Describe() const override { return "Win32AnchorImage"; }

    // 磁盘映像缓存的原始 buildId / sha256 留给 ar_gate 用
    const std::string& ExePath() const { return exePath_; }

private:
    struct Sec {
        std::string name;
        uint32_t va, vsize, rawSize, rawPtr, chars;
    };

    std::string exePath_;
    uint64_t base_ = 0;
    uint32_t sizeOfImage_ = 0;
    std::vector<uint8_t> buf_;
    std::vector<Sec> secs_;
    std::vector<std::pair<uint32_t, uint32_t> > funcs_;

    bool ReadWholeExe() {
        HANDLE h = CreateFileA(exePath_.c_str(), GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return false;
        LARGE_INTEGER sz;
        if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0 || sz.QuadPart > (1LL << 31)) {
            CloseHandle(h);
            return false;
        }
        buf_.resize((size_t)sz.QuadPart);
        size_t got = 0;
        while (got < buf_.size()) {
            DWORD chunk = (DWORD)((buf_.size() - got) > (1u << 20) ? (1u << 20)
                                                                  : (buf_.size() - got));
            DWORD rd = 0;
            if (!ReadFile(h, buf_.data() + got, chunk, &rd, nullptr) || rd == 0) {
                CloseHandle(h);
                return false;
            }
            got += rd;
        }
        CloseHandle(h);
        return true;
    }

    bool ParsePeFromDisk() {
        if (!ReadWholeExe()) return false;
        if (buf_.size() < 0x200) return false;
        if (!(buf_[0] == 'M' && buf_[1] == 'Z')) return false;
        uint32_t peOff = *(uint32_t*)(buf_.data() + 0x3c);
        if (peOff + 24 > buf_.size()) return false;
        if (!(buf_[peOff] == 'P' && buf_[peOff + 1] == 'E')) return false;
        uint16_t nsec = *(uint16_t*)(buf_.data() + peOff + 6);
        uint16_t optSize = *(uint16_t*)(buf_.data() + peOff + 20);
        uint32_t optOff = peOff + 24;
        if (*(uint16_t*)(buf_.data() + optOff) != 0x20b) return false;   // PE32+
        sizeOfImage_ = *(uint32_t*)(buf_.data() + optOff + 56);
        uint32_t secOff = optOff + optSize;

        for (uint16_t i = 0; i < nsec; ++i) {
            uint32_t o = secOff + (uint32_t)i * 40;
            if (o + 40 > buf_.size()) return false;
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
                funcs_.reserve(cnt);
                for (uint32_t k = 0; k < cnt; ++k) {
                    uint32_t eo = s.rawPtr + k * 12;
                    if ((size_t)eo + 12 > buf_.size()) break;
                    funcs_.push_back(std::make_pair(*(uint32_t*)(buf_.data() + eo),
                                                    *(uint32_t*)(buf_.data() + eo + 4)));
                }
            }
        }
        return !secs_.empty();
    }
};

}  // namespace arresolve

#endif  // AR_RESOLVE_WIN32_H
