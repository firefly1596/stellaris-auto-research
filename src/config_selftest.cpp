// config_selftest.cpp —— ar_config.h 的离线自测（控制台程序，不碰游戏、不碰 hook）
//
// 编译（MinGW g++，见 AUTO_RESEARCH_HANDOFF.md §2.1）：
//   g++ -std=c++17 -O2 -o config_selftest.exe config_selftest.cpp
// 运行：
//   ./config_selftest.exe            → 人读输出
//   ./config_selftest.exe --log F    → 同时把同一份输出写进 F（给验收留档）
//
// 覆盖：正数 / 0 / 负数 / 全负时取数值最大 / @default / 缺文件清空 /
//       热重载 / 注释 / 空白 / UTF-8 BOM / 非法输入 / soft-ban 已删除
#include "ar_config.h"

#include <cstdio>
#include <string>
#include <vector>

// ---------------- 迷你测试框架 ----------------
static int g_pass = 0;
static int g_fail = 0;
static FILE* g_out = nullptr;   // 日志文件（可空）
static std::string g_section;

static void Emit(const std::string& s) {
    fputs(s.c_str(), stdout);
    fputc('\n', stdout);
    if (g_out) {
        fputs(s.c_str(), g_out);
        fputc('\n', g_out);
        fflush(g_out);
    }
}

static void Section(const std::string& name) {
    g_section = name;
    Emit("");
    Emit("=== " + name + " ===");
}

static void Ok(const std::string& what, const std::string& detail) {
    ++g_pass;
    Emit("  [PASS] " + what + (detail.empty() ? "" : "   (" + detail + ")"));
}

static void Bad(const std::string& what, const std::string& detail) {
    ++g_fail;
    Emit("  [FAIL] " + what + (detail.empty() ? "" : "   (" + detail + ")"));
}

static void Check(bool cond, const std::string& what, const std::string& detail = "") {
    if (cond) Ok(what, detail);
    else Bad(what, detail);
}

static void CheckEqLL(long long got, long long want, const std::string& what,
                      const std::string& detail = "") {
    if (got == want) Ok(what, detail.empty() ? ("= " + std::to_string(got)) : detail);
    else Bad(what, detail.empty()
                        ? ("got " + std::to_string(got) + ", want " + std::to_string(want))
                        : (detail + " (got " + std::to_string(got) + ", want " +
                           std::to_string(want) + ")"));
}


// ---------------- 日志捕获（供断言"日志里有明确提示"） ----------------
static std::vector<std::string> g_logLines;

static void CaptureLog(void*, int sev, const char* msg) {
    static const char* tag[] = {"INFO", "WARN", "ERR "};
    g_logLines.push_back(std::string("[") + tag[sev] + "] " + (msg ? msg : ""));
}

static arcfg::Logger MakeLogger() {
    arcfg::Logger lg;
    lg.fn = &CaptureLog;
    lg.ctx = nullptr;
    return lg;
}

static void ClearLog() { g_logLines.clear(); }

static bool LogContains(const std::string& needle) {
    for (size_t i = 0; i < g_logLines.size(); ++i)
        if (g_logLines[i].find(needle) != std::string::npos) return true;
    return false;
}

static void DumpCapturedLog() {
    if (g_logLines.empty()) {
        Emit("    (log empty)");
        return;
    }
    for (size_t i = 0; i < g_logLines.size(); ++i) Emit("    " + g_logLines[i]);
}

// ---------------- 假文件源（内存文件，用于测热重载/消失/读失败） ----------------
class FakeFile : public arcfg::IFileSource {
public:
    bool present = false;
    int  forceStatus = -1;   // -1 = 按 present 决定；其它值强制返回 Missing/Unreadable
    std::string content;
    arcfg::Snapshot snap;

    void Set(const std::string& text, uint64_t wt, uint64_t size) {
        present = true;
        forceStatus = -1;
        content = text;
        snap.exists = true;
        snap.writeTime = wt;
        snap.size = size;
    }
    void SetAuto(const std::string& text, uint64_t wt) { Set(text, wt, (uint64_t)text.size()); }
    void Remove() {
        present = false;
        forceStatus = -1;
        content.clear();
        snap = arcfg::Snapshot();
    }
    void MakeUnreadable() { present = true; forceStatus = (int)IFileSource::Unreadable; }

    int Read(arcfg::Snapshot* s, std::string* out) override {
        if (forceStatus == (int)IFileSource::Unreadable) return (int)IFileSource::Unreadable;
        if (!present) return (int)IFileSource::Missing;
        if (s) *s = snap;
        if (out) *out = content;
        return (int)IFileSource::Ok;
    }
};

// =====================================================================
// 1) 单行解析 + 整数严格性
// =====================================================================
static void TestParseInt() {
    Section("1) ParseInt 严格十进制");
    long long v = 0;
    struct Case { const char* s; bool ok; long long v; };
    const Case cases[] = {
        {"0",            true,   0},
        {"1",            true,   1},
        {"100",          true,   100},
        {"1000",         true,   1000},
        {"-1",           true,   -1},
        {"-50",          true,   -50},
        {"+7",           true,   7},
        {"9223372036854775807", true, 9223372036854775807LL},
        {"-9223372036854775807", true, -9223372036854775807LL},
        {"",             false,  0},
        {" 5",           false,  0},   // 前导空白（调用方已 trim，这里应拒绝）
        {"5 ",           false,  0},
        {"1 000",        false,  0},
        {"1.5",          false,  0},
        {"12abc",        false,  0},
        {"0x10",         false,  0},   // 只认十进制
        {"010",          true,   10},  // 十进制，不是八进制
        {"soft",         false,  0},   // 已删除的字符串写法
        {"ban",          false,  0},
        {"99999999999999999999", false, 0},  // 溢出
        {"abc",          false,  0},
        {"-",            false,  0},
        {"+",            false,  0},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        bool ok = arcfg::ParseInt(cases[i].s, &v);
        if (ok == cases[i].ok && (!ok || v == cases[i].v)) {
            Ok(std::string("ParseInt(\"") + cases[i].s + "\")",
               ok ? ("= " + std::to_string(v)) : "rejected");
        } else {
            Bad(std::string("ParseInt(\"") + cases[i].s + "\")",
                std::string("ok=") + (ok ? "true" : "false") + " v=" + std::to_string(v) +
                " (want ok=" + (cases[i].ok ? "true" : "false"));
        }
    }
}

// =====================================================================
// 2) 注释 / 空白 / 行结构
// =====================================================================
static void TestLines() {
    Section("2) 注释 / 空白 / 行结构");
    {
        arcfg::LineResult r = arcfg::ParseLine("");
        Check(r.kind == arcfg::LineKind::Blank, "空行 → Blank");
    }
    {
        arcfg::LineResult r = arcfg::ParseLine("   \t  ");
        Check(r.kind == arcfg::LineKind::Blank, "纯空白行 → Blank");
    }
    {
        arcfg::LineResult r = arcfg::ParseLine("# tech_a = 5");
        Check(r.kind == arcfg::LineKind::Comment, "整行注释 → Comment");
    }
    {
        arcfg::LineResult r = arcfg::ParseLine("  # 缩进注释");
        Check(r.kind == arcfg::LineKind::Comment, "缩进注释 → Comment");
    }
    {
        arcfg::LineResult r = arcfg::ParseLine("tech_a = 5   # 行尾注释");
        Check(r.kind == arcfg::LineKind::Entry && r.key == "tech_a" && r.number == 5,
              "行尾 # 注释被剥掉", "key=" + r.key + " v=" + std::to_string(r.number));
    }
    {
        arcfg::LineResult r = arcfg::ParseLine("\ttech_b\t=\t-30\t");
        Check(r.kind == arcfg::LineKind::Entry && r.key == "tech_b" && r.number == -30,
              "制表符/空白前后缀被 trim", "key=" + r.key + " v=" + std::to_string(r.number));
    }
    {
        arcfg::LineResult r = arcfg::ParseLine("tech_c");
        Check(r.kind == arcfg::LineKind::Invalid, "缺 '=' → Invalid", r.error);
    }
    {
        arcfg::LineResult r = arcfg::ParseLine("= 5");
        Check(r.kind == arcfg::LineKind::Invalid, "空 key → Invalid", r.error);
    }
    {
        arcfg::LineResult r = arcfg::ParseLine("tech_d =");
        Check(r.kind == arcfg::LineKind::Invalid, "空 value → Invalid", r.error);
    }
    {
        arcfg::LineResult r = arcfg::ParseLine("tech e = 5");
        Check(r.kind == arcfg::LineKind::Invalid, "key 含空格 → Invalid", r.error);
    }
    {
        arcfg::LineResult r = arcfg::ParseLine("Tech_Upper = 1");
        Check(r.kind == arcfg::LineKind::Entry && r.key == "Tech_Upper",
              "key 大小写原样保留", "key=" + r.key);
    }
}

// =====================================================================
// 3) 指令 @mode / @default
// =====================================================================
static void TestDirectives() {
    Section("3) 指令 @mode / @default");
    {
        arcfg::LineResult r = arcfg::ParseLine("@mode = take");
        Check(r.kind == arcfg::LineKind::Directive && r.mode == arcfg::Mode::Take,
              "@mode = take");
    }
    {
        arcfg::LineResult r = arcfg::ParseLine("@MODE = TAKE");
        Check(r.kind == arcfg::LineKind::Directive && r.mode == arcfg::Mode::Take,
              "@MODE = TAKE（指令名/值大小写不敏感）");
    }
    {
        arcfg::LineResult r = arcfg::ParseLine("@mode = observe");
        Check(r.kind == arcfg::LineKind::Directive && r.mode == arcfg::Mode::Observe,
              "@mode = observe");
    }
    {
        arcfg::LineResult r = arcfg::ParseLine("@mode = takeover");
        Check(r.kind == arcfg::LineKind::Invalid, "@mode 非法值 → Invalid", r.error);
    }
    {
        arcfg::LineResult r = arcfg::ParseLine("@default = 250");
        Check(r.kind == arcfg::LineKind::Directive && r.key == "@default" && r.number == 250,
              "@default = 250", "v=" + std::to_string(r.number));
    }
    {
        arcfg::LineResult r = arcfg::ParseLine("@default = -20");
        Check(r.kind == arcfg::LineKind::Directive && r.number == -20,
              "@default 允许负数", "v=" + std::to_string(r.number));
    }
    {
        arcfg::LineResult r = arcfg::ParseLine("@default = soft");
        Check(r.kind == arcfg::LineKind::Invalid, "@default 非数字 → Invalid", r.error);
    }
    {
        arcfg::LineResult r = arcfg::ParseLine("@unknown = 1");
        Check(r.kind == arcfg::LineKind::Invalid, "未知指令 → Invalid", r.error);
    }
}

// =====================================================================
// 4) 权重语义：正数 / 0 / 负数 / 全负
// =====================================================================
static void TestPickSemantics() {
    Section("4) 权重语义（纯数字）");

    // 4.1 > 0：最大者胜出
    {
        arcfg::Config c = arcfg::Defaults();
        c.weights = {{"tech_a", 100}, {"tech_b", 1000}, {"tech_c", 50}};
        std::vector<std::string> keys = {"tech_a", "tech_b", "tech_c"};
        arcfg::PickResult r = arcfg::PickBest(keys, c);
        Check(r.status == arcfg::PickStatus::Picked && r.tier == arcfg::PickTier::Positive &&
              keys[(size_t)r.index] == "tech_b",
              ">0：最大者胜出", "picked=" + (r.index >= 0 ? keys[(size_t)r.index] : "none") +
              " w=" + std::to_string(r.weight));
    }
    // 4.2 0 = 禁选
    {
        arcfg::Config c = arcfg::Defaults();
        c.weights = {{"tech_a", 0}, {"tech_b", 10}};
        std::vector<std::string> keys = {"tech_a", "tech_b"};
        arcfg::PickResult r = arcfg::PickBest(keys, c);
        Check(keys[(size_t)r.index] == "tech_b",
              "0 = 禁选，即使对手权重更低也不选它",
              "picked=" + keys[(size_t)r.index] + " w=" + std::to_string(r.weight));
    }
    // 4.3 0 在最高位也不选
    {
        arcfg::Config c = arcfg::Defaults();
        c.weights = {{"tech_zero", 0}, {"tech_low", 1}};
        std::vector<std::string> keys = {"tech_zero", "tech_low"};
        arcfg::PickResult r = arcfg::PickBest(keys, c);
        Check(keys[(size_t)r.index] == "tech_low", "0 永不选（和权重高低无关）");
    }
    // 4.4 全负 → 取【数值最大】（最接近 0）
    //
    //   ★ 2026-11-18 语义变更（用户要求）：
    //     旧：取绝对值最大 → -50 优于 -5（错）
    //     新：取数值最大     → -5 优于 -50（对）
    {
        arcfg::Config c = arcfg::Defaults();
        c.weights = {{"tech_a", -5}, {"tech_b", -50}, {"tech_c", -30}};
        std::vector<std::string> keys = {"tech_a", "tech_b", "tech_c"};
        arcfg::PickResult r = arcfg::PickBest(keys, c);
        Check(r.status == arcfg::PickStatus::Picked &&
              r.tier == arcfg::PickTier::NegativeFallback &&
              keys[(size_t)r.index] == "tech_a",
              "全负 → 取数值最大（最接近 0）", "picked=" + keys[(size_t)r.index] +
              " w=" + std::to_string(r.weight));
    }
    // 4.4b 负数两个时：-1 优于 -1000
    {
        arcfg::Config c = arcfg::Defaults();
        c.weights = {{"tech_a", -1}, {"tech_b", -1000}};
        std::vector<std::string> keys = {"tech_a", "tech_b"};
        arcfg::PickResult r = arcfg::PickBest(keys, c);
        Check(r.status == arcfg::PickStatus::Picked &&
              keys[(size_t)r.index] == "tech_a",
              "[-1, -1000] → 选 -1", "picked=" + keys[(size_t)r.index]);
    }
    // 4.5 负数 + 0 混合：0 仍然禁选，负数被选中
    {
        arcfg::Config c = arcfg::Defaults();
        c.weights = {{"tech_ban", 0}, {"tech_neg", -1}};
        std::vector<std::string> keys = {"tech_ban", "tech_neg"};
        arcfg::PickResult r = arcfg::PickBest(keys, c);
        Check(keys[(size_t)r.index] == "tech_neg" && r.tier == arcfg::PickTier::NegativeFallback,
              "0 与负数混合：0 仍禁选，选负数");
    }
    // 4.6 有正数时不走负数兜底
    {
        arcfg::Config c = arcfg::Defaults();
        c.weights = {{"tech_neg", -9999}, {"tech_pos", 1}};
        std::vector<std::string> keys = {"tech_neg", "tech_pos"};
        arcfg::PickResult r = arcfg::PickBest(keys, c);
        Check(keys[(size_t)r.index] == "tech_pos" && r.tier == arcfg::PickTier::Positive,
              "有正数时绝不走负数兜底");
    }
    // 4.7 全 0 → 停止研究
    {
        arcfg::Config c = arcfg::Defaults();
        c.weights = {{"tech_a", 0}, {"tech_b", 0}};
        std::vector<std::string> keys = {"tech_a", "tech_b"};
        arcfg::PickResult r = arcfg::PickBest(keys, c);
        Check(r.status == arcfg::PickStatus::Stop && r.index == -1,
              "全 0 → 停止研究（不选任何）");
    }
    // 4.8 空候选 → 停止研究
    {
        arcfg::Config c = arcfg::Defaults();
        std::vector<std::string> keys;
        arcfg::PickResult r = arcfg::PickBest(keys, c);
        Check(r.status == arcfg::PickStatus::Stop, "空候选 → 停止研究");
    }
    // 4.9 并列正数：取列表靠前者（稳定、可预测）
    {
        arcfg::Config c = arcfg::Defaults();
        c.weights = {{"tech_a", 100}, {"tech_b", 100}};
        std::vector<std::string> keys = {"tech_a", "tech_b"};
        arcfg::PickResult r = arcfg::PickBest(keys, c);
        Check(keys[(size_t)r.index] == "tech_a", "并列正数 → 列表靠前者胜（确定性）");
    }
    // 4.10 并列负数
    {
        arcfg::Config c = arcfg::Defaults();
        c.weights = {{"tech_a", -7}, {"tech_b", -7}};
        std::vector<std::string> keys = {"tech_a", "tech_b"};
        arcfg::PickResult r = arcfg::PickBest(keys, c);
        Check(keys[(size_t)r.index] == "tech_a", "并列负数 → 列表靠前者胜");
    }
    // 4.11 未列出的科技走 @default
    {
        arcfg::Config c = arcfg::Defaults();
        c.defaultWeight = 100;
        c.weights = {{"tech_listed", 50}};
        std::vector<std::string> keys = {"tech_listed", "tech_unlisted"};
        arcfg::PickResult r = arcfg::PickBest(keys, c);
        Check(keys[(size_t)r.index] == "tech_unlisted" && r.weight == 100,
              "@default=100：未列出科技权重 100 > 列出者 50");
    }
    // 4.12 @default = 0 → 未列出者全禁选
    {
        arcfg::Config c = arcfg::Defaults();
        c.defaultWeight = 0;
        c.weights = {{"tech_listed", 5}};
        std::vector<std::string> keys = {"tech_a", "tech_b", "tech_listed"};
        arcfg::PickResult r = arcfg::PickBest(keys, c);
        Check(keys[(size_t)r.index] == "tech_listed",
              "@default=0：未列出科技视为禁选，只剩显式列出的");
    }
    // 4.13 @default 负数 → 未列出者进负数兜底
    {
        arcfg::Config c = arcfg::Defaults();
        c.defaultWeight = -3;
        c.weights = {{"tech_listed", -10}};
        std::vector<std::string> keys = {"tech_a", "tech_listed"};
        arcfg::PickResult r = arcfg::PickBest(keys, c);
        // ★ 新语义：-3 vs -10 取数值更大的 -3
        Check(keys[(size_t)r.index] == "tech_a" &&
              r.tier == arcfg::PickTier::NegativeFallback && r.weight == -3,
              "@default=-3：兜底选 -3（-3 > -10）");
    }
    // 4.14 EffectiveWeight / HasExplicitWeight
    {
        arcfg::Config c = arcfg::Defaults();
        c.defaultWeight = 77;
        c.weights = {{"tech_a", -1}};
        CheckEqLL(arcfg::EffectiveWeight(c, "tech_a"), -1, "EffectiveWeight(列出)");
        CheckEqLL(arcfg::EffectiveWeight(c, "tech_z"), 77, "EffectiveWeight(未列出)");
        Check(arcfg::HasExplicitWeight(c, "tech_a"), "HasExplicitWeight(列出)=true");
        Check(!arcfg::HasExplicitWeight(c, "tech_z"), "HasExplicitWeight(未列出)=false");
    }
}

// =====================================================================
// 5) 整份文件解析：BOM / 注释 / 非法输入 / 重复 key
// =====================================================================
static void TestParseConfigText() {
    Section("5) 整份文件解析");

    // 5.1 UTF-8 BOM
    {
        arcfg::Config c;
        arcfg::Logger lg = MakeLogger();
        ClearLog();
        std::string text = "\xEF\xBB\xBF@mode = take\ntech_a = 500\n";
        arcfg::ParseStats st = arcfg::ParseConfigText(text, &c, lg, "t");
        Check(c.mode == arcfg::Mode::Take && c.weights.size() == 1 && c.weights["tech_a"] == 500,
              "UTF-8 BOM：首行指令仍被正确解析",
              "mode=" + std::string(arcfg::ModeName(c.mode)) +
              " entries=" + std::to_string(c.weights.size()));
        Check(st.invalid == 0, "UTF-8 BOM 不产生 invalid 行",
              "invalid=" + std::to_string(st.invalid));
        Check(st.lines == 2, "行数统计（BOM 不算一行）", "lines=" + std::to_string(st.lines));
    }
    // 5.2 \r\n 行尾
    {
        arcfg::Config c;
        arcfg::Logger lg = MakeLogger();
        ClearLog();
        std::string text = "# c\r\n@mode = take\r\ntech_a = -9\r\n\r\n";
        arcfg::ParseConfigText(text, &c, lg, "t");
        Check(c.mode == arcfg::Mode::Take && c.weights.size() == 1 && c.weights["tech_a"] == -9,
              "CRLF 行尾被正确处理（负数保住符号）");
    }
    // 5.3 非法输入不污染配置
    {
        arcfg::Config c;
        arcfg::Logger lg = MakeLogger();
        ClearLog();
        std::string text =
            "garbage line without equals\n"
            "@mode = take\n"
            "tech_ok = 100\n"
            "tech_bad = 12abc\n"
            "@default = 200\n"
            "= 5\n"
            "tech_ok2 = -25\n";
        arcfg::ParseStats st = arcfg::ParseConfigText(text, &c, lg, "t");
        CheckEqLL(c.weights.size(), 2, "非法行被丢弃，只留合法条目");
        Check(c.weights.count("tech_ok") && c.weights["tech_ok"] == 100, "tech_ok = 100 生效");
        Check(c.weights.count("tech_ok2") && c.weights["tech_ok2"] == -25,
              "tech_ok2 = -25 生效（负数保留）");
        Check(c.weights.count("tech_bad") == 0, "tech_bad = 12abc 被丢弃");
        CheckEqLL(c.defaultWeight, 200, "@default 仍然生效");
        CheckEqLL(st.invalid, 3, "invalid 行计数 = 3", "invalid=" + std::to_string(st.invalid));
        Check(LogContains("line 1") && LogContains("no '='"),
              "非法行写进了日志（带行号）");
        DumpCapturedLog();
    }
    // 5.4 soft / ban 彻底删除：当作无效行忽略，且有明确日志
    {
        arcfg::Config c;
        arcfg::Logger lg = MakeLogger();
        ClearLog();
        std::string text =
            "@mode = take\n"
            "tech_a = soft\n"
            "tech_b = ban\n"
            "tech_c = Soft\n"
            "tech_d = BAN\n"
            "tech_e = -1\n"
            "tech_f = 0\n";
        arcfg::ParseStats st = arcfg::ParseConfigText(text, &c, lg, "t");
        Check(c.weights.count("tech_a") == 0 && c.weights.count("tech_b") == 0 &&
              c.weights.count("tech_c") == 0 && c.weights.count("tech_d") == 0,
              "soft / ban（含大小写变体）被当作无效行忽略，不映射成任何数字");
        CheckEqLL(c.weights.size(), 2, "只有纯数字行生效", "entries=" +
                  std::to_string(c.weights.size()));
        Check(c.weights.count("tech_e") && c.weights["tech_e"] == -1 &&
              c.weights.count("tech_f") && c.weights["tech_f"] == 0,
              "纯数字 -1 / 0 正常生效（这才是规范写法）");
        CheckEqLL(st.invalid, 4, "soft/ban 4 行都算 invalid", "invalid=" +
                  std::to_string(st.invalid));
        Check(LogContains("soft") || LogContains("no longer supported"),
              "日志里有 soft/ban 已废弃的明确提示");
        Check(LogContains("line 2"), "日志带行号（line 2 = tech_a = soft）");
        DumpCapturedLog();
    }
    // 5.5 重复 key：后者覆盖
    {
        arcfg::Config c;
        arcfg::Logger lg = MakeLogger();
        ClearLog();
        std::string text = "tech_a = 10\ntech_a = 30\n";
        arcfg::ParseConfigText(text, &c, lg, "t");
        CheckEqLL(c.weights["tech_a"], 30, "重复 key：后者覆盖前者");
        Check(LogContains("duplicate key"), "重复 key 有日志警告");
    }
    // 5.6 只有注释 → 全默认
    {
        arcfg::Config c;
        c.mode = arcfg::Mode::Take;   // 故意弄脏，验证 ParseConfigText 会先重置
        arcfg::Logger lg = MakeLogger();
        ClearLog();
        arcfg::ParseStats st = arcfg::ParseConfigText("# just a comment\n\n# another\n", &c, lg, "t");
        Check(c.mode == arcfg::Mode::Observe && c.weights.empty() &&
              c.defaultWeight == arcfg::kBuiltinDefaultWeight,
              "只有注释的文件 → 内置默认（并清掉上一次的残留）",
              arcfg::Describe(c));
        CheckEqLL(st.comment, 2, "注释行计数 = 2");
        CheckEqLL(st.blank, 1, "空行计数 = 1");
    }
    // 5.7 UTF-16 检测
    {
        arcfg::Config c;
        arcfg::Logger lg = MakeLogger();
        ClearLog();
        std::string text;
        text.push_back((char)0xFF);
        text.push_back((char)0xFE);
        text += "t\0e\0c\0h\0", text.push_back('\0');
        arcfg::ParseConfigText(text, &c, lg, "t");
        Check(c.weights.empty(), "UTF-16 文件：不产生垃圾配置");
        Check(LogContains("UTF-16"), "UTF-16 有明确错误日志");
    }
    // 5.8 空文件
    {
        arcfg::Config c;
        arcfg::Logger lg = MakeLogger();
        ClearLog();
        std::string text;
        arcfg::ParseStats st = arcfg::ParseConfigText(text, &c, lg, "t");
        Check(c.weights.empty() && c.defaultWeight == arcfg::kBuiltinDefaultWeight &&
              c.mode == arcfg::Mode::Observe, "空文件 → 内置默认");
        CheckEqLL(st.lines, 1, "空文件按 1 行统计");
    }
    // 5.9 极端长值不崩
    {
        arcfg::Config c;
        arcfg::Logger lg = MakeLogger();
        ClearLog();
        std::string text = "tech_a = " + std::string(5000, '9') + "\n";
        arcfg::ParseStats st = arcfg::ParseConfigText(text, &c, lg, "t");
        Check(c.weights.empty() && st.invalid == 1, "超长数字 → 溢出拒绝，不崩");
    }
}

// =====================================================================
// 6) 热重载：mtime / 大小 / 文件消失 / 重新出现 / 读失败
// =====================================================================
static void TestWatcher() {
    Section("6) 热重载（mtime / 消失 / 重现 / 读失败）");

    FakeFile f;
    arcfg::Watcher w(&f);
    arcfg::Logger lg = MakeLogger();
    arcfg::Config cfg;

    // 6.1 首次：文件不存在 → Cleared
    {
        f.Remove();
        ClearLog();
        arcfg::PollResult r = w.Poll(&cfg, lg, "w.txt");
        Check(r == arcfg::PollResult::Cleared, "首次轮询时文件不存在 → Cleared",
              arcfg::PollResultName(r));
        Check(cfg.weights.empty() && cfg.mode == arcfg::Mode::Observe &&
              cfg.defaultWeight == arcfg::kBuiltinDefaultWeight,
              "Cleared 后是内置默认", arcfg::Describe(cfg));
        Check(LogContains("not found"), "清空有明确日志");
    }

    // 6.2 文件出现 → Reloaded
    {
        f.SetAuto("@mode = take\n@default = 200\ntech_a = 1000\ntech_b = -5\n", 1000);
        ClearLog();
        arcfg::PollResult r = w.Poll(&cfg, lg, "w.txt");
        Check(r == arcfg::PollResult::Reloaded, "文件出现 → Reloaded",
              arcfg::PollResultName(r));
        Check(cfg.mode == arcfg::Mode::Take && cfg.defaultWeight == 200 &&
              cfg.weights.size() == 2, "内容解析正确", arcfg::Describe(cfg));
    }

    // 6.3 时间戳/大小都没变 → NoChange（"时间戳没变"必须能区分出来）
    {
        ClearLog();
        arcfg::PollResult r = w.Poll(&cfg, lg, "w.txt");
        Check(r == arcfg::PollResult::NoChange,
              "mtime 与大小均未变 → NoChange（不重载）", arcfg::PollResultName(r));
        Check(g_logLines.empty(), "NoChange 不刷日志");
    }

    // 6.4 mtime 变（大小不变）→ Reloaded
    {
        f.SetAuto("@mode = take\n@default = 200\ntech_a = 3000\ntech_z = 7\n", 2000);
        ClearLog();
        arcfg::PollResult r = w.Poll(&cfg, lg, "w.txt");
        Check(r == arcfg::PollResult::Reloaded, "仅 mtime 变化 → Reloaded",
              arcfg::PollResultName(r));
        Check(cfg.weights.count("tech_a") && cfg.weights["tech_a"] == 3000 &&
              cfg.weights.count("tech_z") && cfg.weights.count("tech_b") == 0,
              "保存即生效：新内容替换旧内容", arcfg::Describe(cfg));
    }

    // 6.5 时间戳被"还原"但大小变了 → 仍要重载
    {
        f.SetAuto("@mode = observe\ntech_a = 1\n", 2000);   // 同 mtime，不同 size
        ClearLog();
        arcfg::PollResult r = w.Poll(&cfg, lg, "w.txt");
        Check(r == arcfg::PollResult::Reloaded, "mtime 相同但大小变 → 仍重载",
              arcfg::PollResultName(r));
        Check(cfg.mode == arcfg::Mode::Observe && cfg.weights.size() == 1,
              "内容已更新", arcfg::Describe(cfg));
    }

    // 6.6 文件被删 → Cleared（不是沿用内存旧配置）
    {
        f.Remove();
        ClearLog();
        arcfg::PollResult r = w.Poll(&cfg, lg, "w.txt");
        Check(r == arcfg::PollResult::Cleared, "文件被删 → Cleared",
              arcfg::PollResultName(r));
        Check(cfg.weights.empty() && cfg.mode == arcfg::Mode::Observe &&
              cfg.defaultWeight == arcfg::kBuiltinDefaultWeight,
              "删文件 = 清空配置，不是沿用旧内存", arcfg::Describe(cfg));
        Check(LogContains("not found"), "删文件有日志");
        // 反复轮询不应重复清空刷屏
        ClearLog();
        arcfg::PollResult r2 = w.Poll(&cfg, lg, "w.txt");
        Check(r2 == arcfg::PollResult::NoChange, "文件继续不存在 → NoChange（不刷屏）",
              arcfg::PollResultName(r2));
    }

    // 6.7 文件重新出现（mtime 故意用回旧值）→ 必须重载
    {
        f.SetAuto("@mode = take\ntech_new = 42\n", 1500);   // 旧 mtime
        ClearLog();
        arcfg::PollResult r = w.Poll(&cfg, lg, "w.txt");
        Check(r == arcfg::PollResult::Reloaded,
              "文件重新出现（即使 mtime 是旧值）→ 一定重载",
              arcfg::PollResultName(r));
        Check(cfg.mode == arcfg::Mode::Take && cfg.weights.size() == 1 &&
              cfg.weights["tech_new"] == 42, "重现后的内容生效", arcfg::Describe(cfg));
    }

    // 6.8 文件存在但读不到 → ReadFailed + 清空
    {
        f.MakeUnreadable();
        ClearLog();
        arcfg::PollResult r = w.Poll(&cfg, lg, "w.txt");
        Check(r == arcfg::PollResult::ReadFailed, "文件存在但读不到 → ReadFailed",
              arcfg::PollResultName(r));
        Check(cfg.weights.empty() && cfg.mode == arcfg::Mode::Observe,
              "读不到 = 清空配置", arcfg::Describe(cfg));
        Check(LogContains("unreadable"), "读失败有明确日志");
    }

    // 6.9 从读失败恢复
    {
        f.SetAuto("@mode = take\ntech_back = 9\n", 3000);
        ClearLog();
        arcfg::PollResult r = w.Poll(&cfg, lg, "w.txt");
        Check(r == arcfg::PollResult::Reloaded, "读失败后文件可读 → 正常重载",
              arcfg::PollResultName(r));
        Check(cfg.weights.count("tech_back") == 1, "内容生效", arcfg::Describe(cfg));
    }

    // 6.10 文件内容全是非法行 → 仍算 Reloaded，但配置是默认（不留旧条目）
    {
        f.SetAuto("tech_a = soft\ntech_b = ban\n", 4000);
        ClearLog();
        arcfg::PollResult r = w.Poll(&cfg, lg, "w.txt");
        Check(r == arcfg::PollResult::Reloaded, "全非法内容 → 仍触发 Reloaded",
              arcfg::PollResultName(r));
        Check(cfg.weights.empty(), "非法内容不残留旧配置", arcfg::Describe(cfg));
        Check(LogContains("no longer supported"), "soft/ban 在文件路径上也有废弃提示");
    }

    // 6.11 Reset() 后强制重载
    {
        w.Reset();
        ClearLog();
        arcfg::PollResult r = w.Poll(&cfg, lg, "w.txt");
        Check(r == arcfg::PollResult::Reloaded, "Reset() 后同一个快照也会重载",
              arcfg::PollResultName(r));
    }

    // 6.12 没有文件源 → 保守清空，不崩
    {
        arcfg::Watcher empty(nullptr);
        arcfg::Config c2;
        arcfg::Logger lg2 = MakeLogger();
        ClearLog();
        arcfg::PollResult r = empty.Poll(&c2, lg2, "none");
        Check(r == arcfg::PollResult::ReadFailed, "无文件源 → ReadFailed（保守）",
              arcfg::PollResultName(r));
        Check(c2.weights.empty(), "无文件源时配置为默认");
    }
}

// =====================================================================
// 7) 端到端：一份真实感的配置文件走完整链路
// =====================================================================
static void TestEndToEnd() {
    Section("7) 端到端：文件 → 解析 → 决策 → 热重载");
    FakeFile f;
    arcfg::Watcher w(&f);
    arcfg::Logger lg = MakeLogger();
    arcfg::Config cfg;
    ClearLog();

    const char* v1 =
        "\xEF\xBB\xBF"
        "# ============================================\n"
        "# 自动科研权重配置 v3（纯数字）\n"
        "#   > 0  正常权重，最大者胜出\n"
        "#   0    禁选\n"
        "#   < 0  不选；全负时取数值最大（最接近 0）\n"
        "# ============================================\n"
        "\n"
        "@mode = take\n"
        "@default = 100\n"
        "\n"
        "tech_physics_1   = 100000   # 最想要\n"
        "tech_society_1   = 0        # 禁选\n"
        "tech_eng_1-a     = -50\n"
        "\ttech_eng_2_b\t=\t-25\t\n"
        "# tech_old = soft   ← 已废弃写法，不要再写\n";
    f.SetAuto(v1, 1111);
    arcfg::PollResult r = w.Poll(&cfg, lg, "weights.txt");
    Check(r == arcfg::PollResult::Reloaded, "端到端：首次加载", arcfg::PollResultName(r));
    Check(cfg.mode == arcfg::Mode::Take && cfg.defaultWeight == 100,
          "端到端：指令生效", arcfg::Describe(cfg));
    CheckEqLL((long long)cfg.weights.size(), 4, "端到端：4 条有效权重");
    CheckEqLL(cfg.weights["tech_physics_1"], 100000, "端到端：tech_physics_1");
    CheckEqLL(cfg.weights["tech_society_1"], 0, "端到端：tech_society_1 = 0");
    CheckEqLL(cfg.weights["tech_eng_1-a"], -50, "端到端：key 里的 '-' 保留");
    CheckEqLL(cfg.weights["tech_eng_2_b"], -25, "端到端：制表符包裹仍能解析");

    // 候选：只有禁选 + 负数 → 走负数兜底
    {
        std::vector<std::string> keys = {"tech_society_1", "tech_eng_1-a", "tech_eng_2_b"};
        arcfg::PickResult p = arcfg::PickBest(keys, cfg);
        // ★ 新语义：-50 vs -25 取数值更大的 -25
        Check(keys[(size_t)p.index] == "tech_eng_2_b" &&
              p.tier == arcfg::PickTier::NegativeFallback,
              "端到端：0 禁选 + 负数 → 选数值最大的 -25",
              "picked=" + keys[(size_t)p.index] + " w=" + std::to_string(p.weight));
    }
    // 候选里出现正数权重 → 直接赢
    {
        std::vector<std::string> keys = {"tech_physics_1", "tech_eng_1-a", "tech_unknown"};
        arcfg::PickResult p = arcfg::PickBest(keys, cfg);
        Check(keys[(size_t)p.index] == "tech_physics_1" &&
              p.tier == arcfg::PickTier::Positive,
              "端到端：正数权重碾压负数",
              "picked=" + keys[(size_t)p.index] + " w=" + std::to_string(p.weight));
    }
    // 候选全是未列出科技 → @default=100 → 取第一个
    {
        std::vector<std::string> keys = {"tech_x", "tech_y"};
        arcfg::PickResult p = arcfg::PickBest(keys, cfg);
        Check(keys[(size_t)p.index] == "tech_x" && p.weight == 100,
              "端到端：未列出科技走 @default=100");
    }

    // 保存成"全禁用"版本 → 热重载 → 停止研究
    f.SetAuto("@mode = take\n@default = 0\ntech_a = 0\n", 2222);
    r = w.Poll(&cfg, lg, "weights.txt");
    Check(r == arcfg::PollResult::Reloaded, "端到端：改档重载", arcfg::PollResultName(r));
    {
        std::vector<std::string> keys = {"tech_a", "tech_b"};
        arcfg::PickResult p = arcfg::PickBest(keys, cfg);
        Check(p.status == arcfg::PickStatus::Stop,
              "端到端：@default=0 且显式 0 → 全部禁选 → 停止研究");
    }

    // 删档 → 清空 → 回到 observe 默认（不再接管）
    f.Remove();
    r = w.Poll(&cfg, lg, "weights.txt");
    Check(r == arcfg::PollResult::Cleared, "端到端：删档 → 清空", arcfg::PollResultName(r));
    Check(cfg.mode == arcfg::Mode::Observe && cfg.defaultWeight == 100 &&
          cfg.weights.empty(), "端到端：删档后回到 observe 默认",
          arcfg::Describe(cfg));
    DumpCapturedLog();
}

// =====================================================================
// 额外工具：把真实配置文件喂给同一套解析器，检查有没有无效行
// （用于验证 config_template.txt / 用户实际配置）
static int ValidateFile(const std::string& path) {
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) {
        std::fprintf(stderr, "cannot open: %s\n", path.c_str());
        return 2;
    }
    std::string text;
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) text.append(buf, n);
    std::fclose(f);

    arcfg::Config cfg;
    arcfg::Logger lg = MakeLogger();
    ClearLog();
    arcfg::ParseStats st = arcfg::ParseConfigText(text, &cfg, lg, path.c_str());

    Emit("=== validate: " + path + " ===");
    Emit("  " + arcfg::Describe(cfg));
    Emit(arcfg::Fmt("  lines=%d comment=%d blank=%d entries=%d directives=%d invalid=%d",
                    st.lines, st.comment, st.blank, st.entries, st.directives, st.invalid));
    for (size_t i = 0; i < g_logLines.size(); ++i) Emit("    " + g_logLines[i]);
    if (st.invalid != 0) {
        Emit(arcfg::Fmt("  结论: FAILED (%d invalid line(s))", st.invalid));
        return 1;
    }
    Emit("  结论: OK (no invalid lines)");
    return 0;
}

// =====================================================================
// 8) dryrun 接线：@mode -> 是否改写返回地址
// =====================================================================
// 背景：这个决策曾经内联在 Init() 里、依赖真实文件 IO，
// 导致「代码写了但从来没被配置赋值」的缺陷无法被发现。
// 现在抽成纯函数 ShouldPatchReturnAddress()，这里把它钉死。
static void TestDryRunWiring() {
    Section("8) dryrun 接线：@mode -> 是否改写返回地址");

    Check(arcfg::ShouldPatchReturnAddress(arcfg::Mode::DryRun) == 0,
          "dryrun -> 0（不改写返回地址）");
    Check(arcfg::ShouldPatchReturnAddress(arcfg::Mode::Observe) == 1,
          "observe -> 1（正常改写）");
    Check(arcfg::ShouldPatchReturnAddress(arcfg::Mode::Take) == 1,
          "take -> 1（正常改写）");

    {
        arcfg::Config c;
        arcfg::Logger lg = MakeLogger();
        ClearLog();
        arcfg::ParseConfigText("@mode = dryrun\n", &c, lg, "t");
        Check(c.mode == arcfg::Mode::DryRun, "解析 @mode = dryrun 得到 DryRun");
        Check(arcfg::ShouldPatchReturnAddress(c.mode) == 0,
              "dryrun 配置 -> g_ar2DoPatch 应为 0（dryrun 真的生效）");
    }
    {
        arcfg::Config c;
        arcfg::Logger lg = MakeLogger();
        ClearLog();
        arcfg::ParseConfigText("@mode = observe\n", &c, lg, "t");
        Check(arcfg::ShouldPatchReturnAddress(c.mode) == 1, "observe 配置 -> 1");
    }
    {
        arcfg::Config c;
        arcfg::Logger lg = MakeLogger();
        ClearLog();
        arcfg::ParseConfigText("@mode = take\n", &c, lg, "t");
        Check(arcfg::ShouldPatchReturnAddress(c.mode) == 1, "take 配置 -> 1");
    }
    {
        arcfg::Config c;
        arcfg::Logger lg = MakeLogger();
        ClearLog();
        arcfg::ParseConfigText("# no mode directive\n", &c, lg, "t");
        Check(c.mode == arcfg::Mode::Observe, "缺省 mode 是 Observe");
        Check(arcfg::ShouldPatchReturnAddress(c.mode) == 1, "缺省 -> 1（不会误入 dryrun）");
    }
    {
        arcfg::Config c;
        arcfg::Logger lg = MakeLogger();
        ClearLog();
        arcfg::ParseConfigText("@MODE = DRYRUN\n", &c, lg, "t");
        Check(c.mode == arcfg::Mode::DryRun, "@MODE = DRYRUN 也识别");
        Check(arcfg::ShouldPatchReturnAddress(c.mode) == 0, "大写 dryrun -> 0");
    }
    {
        arcfg::Config c;
        arcfg::Logger lg = MakeLogger();
        ClearLog();
        arcfg::ParseConfigText("@mode = dryrunx\n", &c, lg, "t");
        Check(c.mode == arcfg::Mode::Observe,
              "非法 mode 值 -> 回落到 Observe（不是 dryrun）");
        Check(arcfg::ShouldPatchReturnAddress(c.mode) == 1,
              "非法值 -> 1，不会误关改写");
    }
    Check(std::string(arcfg::ModeName(arcfg::Mode::DryRun)) == "dryrun",
          "ModeName(DryRun) == dryrun");
    Check(std::string(arcfg::ModeName(arcfg::Mode::Take)) == "take",
          "ModeName(Take) == take");
}

int main(int argc, char** argv) {
    std::string logPath;
    std::string validatePath;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--log" && i + 1 < argc) {
            logPath = argv[++i];
        } else if (a == "--validate" && i + 1 < argc) {
            validatePath = argv[++i];
        } else if (a == "-h" || a == "--help") {
            std::printf("usage: %s [--log FILE] [--validate CONFIG_FILE]\n", argv[0]);
            return 0;
        }
    }
    if (!logPath.empty()) {
        g_out = std::fopen(logPath.c_str(), "w");
        if (!g_out) {
            std::fprintf(stderr, "cannot open log file: %s\n", logPath.c_str());
            return 2;
        }
    }

    // --validate 模式：只校验一份真实配置文件，不跑测试套件
    if (!validatePath.empty()) {
        int rc = ValidateFile(validatePath);
        if (g_out) { std::fclose(g_out); g_out = nullptr; }
        return rc;
    }

    Emit("==============================================");
    Emit("auto_research 配置层离线自测（ar_config.h）");
    Emit("规范：>0 权重 | 0 禁选 | <0 不选（全负时取数值最大）");
    Emit("      soft / ban 已删除：非数字一律无效行");
    Emit("==============================================");

    TestParseInt();
    TestLines();
    TestDirectives();
    TestPickSemantics();
    TestParseConfigText();
    TestWatcher();
    TestEndToEnd();
    TestDryRunWiring();

    Emit("");
    Emit("==============================================");
    Emit(arcfg::Fmt("结果: %d passed, %d failed, %d total", g_pass, g_fail,
                    g_pass + g_fail));
    Emit(g_fail == 0 ? "结论: ALL PASS" : "结论: FAILED");
    Emit("==============================================");

    if (g_out) {
        std::fclose(g_out);
        g_out = nullptr;
    }
    return g_fail == 0 ? 0 : 1;
}
