// ar_config_win32.h —— 配置文件的 Win32 读取适配层
//
// 只做一件事：把"读 injected_mods\auto_research_weights.txt"包装成
// arcfg::IFileSource。不含任何游戏内存 / hook 逻辑，因此 DLL 和
// 控制台磁盘自测（config_filetest.cpp）用的是同一份代码 —— 磁盘上
// 测过的行为就是游戏里跑的行为。
//
// 快照三元组：(是否存在, 写时间戳(FILETIME 高低位拼 64 位), 文件大小)
// 只有三者全同才算"没变"，所以"时间戳被还原但内容改了"也能被发现。
#pragma once
#ifndef AR_CONFIG_WIN32_H
#define AR_CONFIG_WIN32_H

#include <windows.h>
#include <share.h>      // _fsopen / _SH_DENYNO
#include <cstdio>
#include <string>

#include "ar_config.h"

namespace arcfg {

// 单次读取最多吃这么多字节，防止误把大文件喂进来（配置撑死几十 KB）
constexpr size_t kMaxConfigBytes = 1u << 20;   // 1 MiB

class Win32FileSource : public IFileSource {
public:
    explicit Win32FileSource(const std::string& path = std::string()) : path_(path) {}
    void SetPath(const std::string& p) { path_ = p; }
    const std::string& Path() const { return path_; }

    int Read(Snapshot* snap, std::string* content) override {
        if (path_.empty()) return (int)IFileSource::Missing;

        WIN32_FILE_ATTRIBUTE_DATA fa;
        if (!GetFileAttributesExA(path_.c_str(), GetFileExInfoStandard, &fa)) {
            DWORD e = GetLastError();
            // 真·不存在 vs 路径在但没权限：两者处置不同（前者是用户主动删档）
            if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND ||
                e == ERROR_INVALID_NAME)
                return (int)IFileSource::Missing;
            return (int)IFileSource::Unreadable;
        }
        if (fa.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            return (int)IFileSource::Unreadable;

        if (snap) {
            snap->exists = true;
            snap->writeTime = ((uint64_t)fa.ftLastWriteTime.dwHighDateTime << 32) |
                              (uint64_t)fa.ftLastWriteTime.dwLowDateTime;
            snap->size = ((uint64_t)fa.nFileSizeHigh << 32) | (uint64_t)fa.nFileSizeLow;
        }

        // _SH_DENYNO：允许用户在别的程序里继续编辑/替换这个文件
        FILE* f = _fsopen(path_.c_str(), "rb", _SH_DENYNO);
        if (!f) return (int)IFileSource::Unreadable;
        if (content) {
            content->clear();
            char buf[4096];
            size_t n = 0;
            while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
                content->append(buf, n);
                if (content->size() >= kMaxConfigBytes) break;
            }
        }
        fclose(f);
        return (int)IFileSource::Ok;
    }

private:
    std::string path_;
};

}  // namespace arcfg

#endif  // AR_CONFIG_WIN32_H
