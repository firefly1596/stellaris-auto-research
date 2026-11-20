// config_filetest.cpp —— 用【真实磁盘文件】测热重载（而不是内存假文件）
//
// 为什么还要这个：config_selftest.cpp 用的是内存假文件源，能证明"逻辑对"；
// 但"保存即热重载 / 删文件即清空"最终取决于 Win32FileSource 的
// GetFileAttributesExA + FILETIME + 文件大小判断。这里用真文件跑一遍，
// 覆盖 config_selftest 覆盖不到的那一层（ar_config_win32.h）。
//
// 编译（MinGW g++）：
//   g++ -std=c++17 -O2 -o config_filetest.exe config_filetest.cpp -lkernel32
// 运行：
//   ./config_filetest.exe [--log FILE] [--dir WORKDIR]
#include <windows.h>

#include <cstdio>
#include <string>
#include <vector>

#include "ar_config.h"
#include "ar_config_win32.h"

static int g_pass = 0;
static int g_fail = 0;
static FILE* g_out = nullptr;

static void Emit(const std::string& s) {
    fputs(s.c_str(), stdout);
    fputc('\n', stdout);
    if (g_out) { fputs(s.c_str(), g_out); fputc('\n', g_out); fflush(g_out); }
}
static void Section(const std::string& n) { Emit(""); Emit("=== " + n + " ==="); }
static void Check(bool c, const std::string& what, const std::string& detail = "") {
    if (c) { ++g_pass; Emit("  [PASS] " + what + (detail.empty() ? "" : "   (" + detail + ")")); }
    else   { ++g_fail; Emit("  [FAIL] " + what + (detail.empty() ? "" : "   (" + detail + ")")); }
}

// ---------------- 日志 ----------------
static std::vector<std::string> g_logLines;
static void CaptureLog(void*, int sev, const char* msg) {
    static const char* tag[] = {"INFO", "WARN", "ERR "};
    g_logLines.push_back(std::string("[") + tag[sev] + "] " + (msg ? msg : ""));
}
static arcfg::Logger MakeLogger() {
    arcfg::Logger lg; lg.fn = &CaptureLog; lg.ctx = nullptr; return lg;
}
static void ClearLog() { g_logLines.clear(); }
static bool LogContains(const std::string& n) {
    for (size_t i = 0; i < g_logLines.size(); ++i)
        if (g_logLines[i].find(n) != std::string::npos) return true;
    return false;
}
static void DumpLog() {
    if (g_logLines.empty()) { Emit("    (log empty)"); return; }
    for (size_t i = 0; i < g_logLines.size(); ++i) Emit("    " + g_logLines[i]);
}

// ---------------- 真文件工具 ----------------
static bool WriteFileBytes(const std::string& path, const std::string& data) {
    FILE* f = fopen(path.c_str(), "wb");
    if (!f) return false;
    if (!data.empty()) fwrite(data.data(), 1, data.size(), f);
    fclose(f);
    return true;
}
static bool WriteFileText(const std::string& path, const std::string& text) {
    return WriteFileBytes(path, text);
}
static bool DeleteFileHard(const std::string& p) {
    return DeleteFileA(p.c_str()) != 0;
}
// 把 mtime 明确推到过去/未来，确保每次写盘都有可观察的时间变化
static void SetMTime(const std::string& p, int secondsAgo) {
    HANDLE h = CreateFileA(p.c_str(), FILE_WRITE_ATTRIBUTES,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    FILETIME now;
    GetSystemTimeAsFileTime(&now);
    ULARGE_INTEGER u;
    u.LowPart = now.dwLowDateTime;
    u.HighPart = now.dwHighDateTime;
    u.QuadPart -= (ULONGLONG)secondsAgo * 10000000ULL;
    FILETIME ft;
    ft.dwLowDateTime = u.LowPart;
    ft.dwHighDateTime = u.HighPart;
    SetFileTime(h, nullptr, nullptr, &ft);
    CloseHandle(h);
}

int main(int argc, char** argv) {
    std::string logPath;
    std::string workDir;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--log" && i + 1 < argc) logPath = argv[++i];
        else if (a == "--dir" && i + 1 < argc) workDir = argv[++i];
        else if (a == "-h" || a == "--help") {
            std::printf("usage: %s [--log FILE] [--dir WORKDIR]\n", argv[0]);
            return 0;
        }
    }
    if (!logPath.empty()) {
        g_out = fopen(logPath.c_str(), "w");
        if (!g_out) { std::fprintf(stderr, "cannot open log: %s\n", logPath.c_str()); return 2; }
    }
    if (workDir.empty()) {
        char tmp[MAX_PATH];
        DWORD n = GetTempPathA(MAX_PATH, tmp);
        if (n == 0 || n >= MAX_PATH) { Emit("GetTempPath failed"); return 2; }
        workDir = std::string(tmp) + "ar_cfg_filetest";
    }
    CreateDirectoryA(workDir.c_str(), nullptr);
    const std::string cfgPath = workDir + "\\auto_research_weights.txt";
    DeleteFileHard(cfgPath);

    Emit("==============================================");
    Emit("ar_config_win32.h 真磁盘热重载自测");
    Emit("工作目录: " + workDir);
    Emit("配置文件: " + cfgPath);
    Emit("==============================================");

    arcfg::Win32FileSource src(cfgPath);
    arcfg::Watcher w(&src);
    arcfg::Logger lg = MakeLogger();
    arcfg::Config cfg;

    // ---- 1) 文件不存在 → Cleared ----
    Section("1) 文件不存在 → 清空配置");
    {
        ClearLog();
        arcfg::PollResult r = w.Poll(&cfg, lg, "disk-weights.txt");
        Check(r == arcfg::PollResult::Cleared, "真·文件不存在 → Cleared",
              arcfg::PollResultName(r));
        Check(cfg.weights.empty() && cfg.mode == arcfg::Mode::Observe,
              "配置被清空为内置默认", arcfg::Describe(cfg));
        Check(LogContains("not found"), "有 not found 日志");
        DumpLog();
    }

    // ---- 2) 首次写文件 → Reloaded ----
    Section("2) 文件出现 → 加载");
    {
        std::string text =
            "# 磁盘测试 v3\r\n"
            "@mode = take\r\n"
            "@default = 150\r\n"
            "tech_a = 500\r\n"
            "tech_b = 0\r\n"
            "tech_c = -80\r\n";
        WriteFileText(cfgPath, text);
        SetMTime(cfgPath, 60);
        ClearLog();
        arcfg::PollResult r = w.Poll(&cfg, lg, "disk-weights.txt");
        Check(r == arcfg::PollResult::Reloaded, "文件出现 → Reloaded", arcfg::PollResultName(r));
        Check(cfg.mode == arcfg::Mode::Take && cfg.defaultWeight == 150,
              "指令生效", arcfg::Describe(cfg));
        Check(cfg.weights.size() == 3, "3 条权重", "n=" + std::to_string(cfg.weights.size()));
        Check(cfg.weights.count("tech_c") && cfg.weights["tech_c"] == -80,
              "负数权重保住符号（CRLF 文件）");
    }

    // ---- 3) 不动文件 → NoChange ----
    Section("3) 文件未改 → NoChange（时间戳没变要能区分）");
    {
        ClearLog();
        arcfg::PollResult r = w.Poll(&cfg, lg, "disk-weights.txt");
        Check(r == arcfg::PollResult::NoChange, "未改文件 → NoChange", arcfg::PollResultName(r));
        Check(g_logLines.empty(), "NoChange 不刷日志");
    }

    // ---- 4) 真·保存 → Reloaded（模拟编辑器保存）----
    Section("4) 保存即热重载");
    {
        std::string text = "@mode = take\n@default = 150\ntech_a = 900\ntech_new = -3\n";
        WriteFileText(cfgPath, text);
        SetMTime(cfgPath, 30);
        // 先让时间戳确实改变（有些文件系统时间粒度粗）
        ClearLog();
        arcfg::PollResult r = w.Poll(&cfg, lg, "disk-weights.txt");
        Check(r == arcfg::PollResult::Reloaded, "保存后 → Reloaded", arcfg::PollResultName(r));
        Check(cfg.weights.count("tech_a") && cfg.weights["tech_a"] == 900 &&
              cfg.weights.count("tech_new") && cfg.weights.count("tech_b") == 0,
              "新内容整体替换旧内容（不是合并）", arcfg::Describe(cfg));
        // 重载统计来自 Watcher，能证明走的是 parse 路径而不是残留旧值
        Check(w.LastStats().entries == 2 && w.LastStats().invalid == 0,
              "重载统计正确（entries=2, invalid=0）",
              "entries=" + std::to_string(w.LastStats().entries) +
              " invalid=" + std::to_string(w.LastStats().invalid));
        DumpLog();
    }

    // ---- 5) 时间戳相同但大小变 → 仍重载 ----
    Section("5) 时间戳未变但大小变 → 仍要重载");
    {
        // 把时间戳固定到同一个值，两次写入只有长度不同
        WriteFileText(cfgPath, "@mode = take\ntech_x = 1\n");
        SetMTime(cfgPath, 100);
        w.Poll(&cfg, lg, "disk-weights.txt");   // 先吃掉这次变化
        std::string longer = "@mode = observe\ntech_x = 1\ntech_yy = 2\n";  // 更长
        WriteFileText(cfgPath, longer);
        SetMTime(cfgPath, 100);                 // 时间戳拉回同一个值
        ClearLog();
        arcfg::PollResult r = w.Poll(&cfg, lg, "disk-weights.txt");
        Check(r == arcfg::PollResult::Reloaded, "mtime 相同 + size 变 → Reloaded",
              arcfg::PollResultName(r));
        Check(cfg.mode == arcfg::Mode::Observe && cfg.weights.count("tech_yy"),
              "新内容生效", arcfg::Describe(cfg));
    }

    // ---- 6) 删文件 → Cleared（不是沿用内存）----
    Section("6) 删文件 → 清空配置");
    {
        DeleteFileHard(cfgPath);
        ClearLog();
        arcfg::PollResult r = w.Poll(&cfg, lg, "disk-weights.txt");
        Check(r == arcfg::PollResult::Cleared, "删文件 → Cleared", arcfg::PollResultName(r));
        Check(cfg.weights.empty() && cfg.mode == arcfg::Mode::Observe &&
              cfg.defaultWeight == arcfg::kBuiltinDefaultWeight,
              "配置真的清空了（不沿用旧内存）", arcfg::Describe(cfg));
        DumpLog();
    }

    // ---- 7) 反复轮询不刷屏 ----
    Section("7) 文件持续不存在 → NoChange");
    {
        ClearLog();
        arcfg::PollResult r = w.Poll(&cfg, lg, "disk-weights.txt");
        Check(r == arcfg::PollResult::NoChange, "持续不存在 → NoChange（不反复刷清空日志）",
              arcfg::PollResultName(r));
    }

    // ---- 8) 重新建文件（mtime 用旧值）→ 必须重载 ----
    Section("8) 文件重新出现 → 一定重载");
    {
        WriteFileText(cfgPath, "@mode = take\ntech_back = 7\n");
        SetMTime(cfgPath, 5000);   // 很旧的 mtime
        ClearLog();
        arcfg::PollResult r = w.Poll(&cfg, lg, "disk-weights.txt");
        Check(r == arcfg::PollResult::Reloaded, "文件重现（旧 mtime）→ Reloaded",
              arcfg::PollResultName(r));
        Check(cfg.mode == arcfg::Mode::Take && cfg.weights.count("tech_back"),
              "重现内容生效", arcfg::Describe(cfg));
    }

    // ---- 9) 路径指向目录 → ReadFailed（不是 Missing）----
    Section("9) 路径是目录 → 读不到（区分于文件不存在）");
    {
        const std::string dirPath = workDir + "\\adir";
        CreateDirectoryA(dirPath.c_str(), nullptr);
        arcfg::Win32FileSource dsrc(dirPath);
        arcfg::Watcher dw(&dsrc);
        arcfg::Config dc;
        ClearLog();
        arcfg::PollResult r = dw.Poll(&dc, lg, "dir-as-config");
        Check(r == arcfg::PollResult::ReadFailed, "目录当配置 → ReadFailed",
              arcfg::PollResultName(r));
        Check(dc.weights.empty(), "配置清空");
    }

    // ---- 10) 空路径 → Missing ----
    Section("10) 空路径 → Missing");
    {
        arcfg::Win32FileSource esrc("");
        arcfg::Watcher ew(&esrc);
        arcfg::Config ec;
        ClearLog();
        arcfg::PollResult r = ew.Poll(&ec, lg, "empty-path");
        Check(r == arcfg::PollResult::Cleared, "空路径 → Cleared", arcfg::PollResultName(r));
    }

    // ---- 11) 真实文件 + 决策 ----
    Section("11) 真文件 → 决策联动");
    {
        std::string text =
            "@mode = take\n"
            "@default = 100\n"
            "tech_pos_hi = 1000\n"
            "tech_pos_lo = 1\n"
            "tech_zero   = 0\n"
            "tech_neg    = -999\n";
        WriteFileText(cfgPath, text);
        SetMTime(cfgPath, 10);
        w.Poll(&cfg, lg, "disk-weights.txt");

        std::vector<std::string> keys = {"tech_zero", "tech_pos_lo", "tech_pos_hi", "tech_neg"};
        arcfg::PickResult pr = arcfg::PickBest(keys, cfg);
        Check(keys[(size_t)pr.index] == "tech_pos_hi" &&
              pr.tier == arcfg::PickTier::Positive,
              "正数最大者胜（忽略 0 和负数）",
              "picked=" + keys[(size_t)pr.index] + " w=" + std::to_string(pr.weight));

        std::vector<std::string> negOnly = {"tech_zero", "tech_neg"};
        arcfg::PickResult pr2 = arcfg::PickBest(negOnly, cfg);
        Check(keys[0] == "tech_zero" && pr2.tier == arcfg::PickTier::NegativeFallback &&
              negOnly[(size_t)pr2.index] == "tech_neg",
              "全负（+0）→ 取绝对值最大的 tech_neg",
              "picked=" + negOnly[(size_t)pr2.index] + " w=" + std::to_string(pr2.weight));

        std::vector<std::string> allZero = {"tech_zero"};
        arcfg::PickResult pr3 = arcfg::PickBest(allZero, cfg);
        Check(pr3.status == arcfg::PickStatus::Stop, "只有 0 → 停止研究");
    }

    // ---- 12) soft/ban 在真文件里被忽略 + 日志 ----
    Section("12) 真文件里的 soft / ban 被忽略");
    {
        std::string text =
            "@mode = take\n"
            "tech_a = soft\n"
            "tech_b = ban\n"
            "tech_c = 42\n";
        WriteFileText(cfgPath, text);
        SetMTime(cfgPath, 5);
        ClearLog();
        arcfg::PollResult r = w.Poll(&cfg, lg, "disk-weights.txt");
        Check(r == arcfg::PollResult::Reloaded, "含 soft/ban 的文件仍能加载",
              arcfg::PollResultName(r));
        Check(cfg.weights.size() == 1 && cfg.weights.count("tech_c"),
              "只有纯数字条目生效", arcfg::Describe(cfg));
        Check(LogContains("no longer supported"), "日志里有 soft/ban 已废弃的提示");
        DumpLog();
    }

    // 清理
    DeleteFileHard(cfgPath);
    RemoveDirectoryA((workDir + "\\adir").c_str());
    RemoveDirectoryA(workDir.c_str());

    Emit("");
    Emit("==============================================");
    Emit(arcfg::Fmt("结果: %d passed, %d failed, %d total", g_pass, g_fail, g_pass + g_fail));
    Emit(g_fail == 0 ? "结论: ALL PASS" : "结论: FAILED");
    Emit("==============================================");
    if (g_out) { fclose(g_out); g_out = nullptr; }
    return g_fail == 0 ? 0 : 1;
}
