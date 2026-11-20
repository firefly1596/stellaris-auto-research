// ar_config.h —— 自动科研配置文件：解析 + 权重语义 + 热重载监听
//
// 设计原则：纯逻辑。不 include windows.h，不碰游戏内存，不依赖 hook。
// 因此可以被 DLL（auto_research.cpp）和控制台自测程序（config_selftest.cpp）
// 同时包含，测试就是跑同一份代码，不存在"测的和用的不一样"。
//
// ============ 配置规范（纯数字，用户定义，唯一规范） ============
//   tech_xxx = > 0     正常权重，候选里数值最大者胜出
//   tech_xxx = 0       禁选，绝不选（哪怕其他候选全被排除）
//   tech_xxx = < 0     不选；只有当没有任何 > 0 的候选时，
//                      才在 < 0 的候选里取数值最小者（= 绝对值最大）
//   全部候选都不可选（全 0 / 空候选）→ 停止研究（不选）
//
//   指令：
//     @mode    = observe | take       （默认 observe）
//     @default = N                   未在文件里列出的科技的权重（默认 100）
//
//   soft / ban 等字符串写法已彻底删除：非十进制整数的值一律视为无效行，
//   记日志后忽略，绝不猜测映射成某个数字。
//
//   文件不存在 / 读不到 → 整份配置重置为内置默认（observe / default=100 / 无条目）
//
// ============ 热重载 ============
//   Watcher 用 (是否存在, 写时间戳, 文件大小) 三元组判断是否需要重载：
//     - 时间戳没变且大小没变 → NoChange（不重载）
//     - 时间戳变了 / 大小变了 → Reloaded
//     - 文件从"存在"变"不存在" → Cleared（清空配置）
//     - 文件从"不存在"重新出现 → 一定重载（哪怕时间戳和旧的一样）
//   这样"文件被删"和"时间戳没变"是两类不同状态，不会互相混淆。
#pragma once
#ifndef AR_CONFIG_H
#define AR_CONFIG_H

#include <cctype>
#include <cerrno>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <unordered_map>
#include <vector>

namespace arcfg {

// 内置默认权重：未写 @default 时，未列出科技的权重
constexpr long long kBuiltinDefaultWeight = 100;

// Observe = 只读记录（主 hook 观察游戏选择）
// DryRun  = hookA 只观察、【不改写返回地址】（验证 patch 安装是否安全的中间档）
// Take    = 接管（尚未实装）
enum class Mode { Observe = 0, DryRun = 1, Take = 2 };

inline const char* ModeName(Mode m) {
    switch (m) {
        case Mode::Observe: return "observe";
        case Mode::DryRun:  return "dryrun";
        case Mode::Take:    return "take";
    }
    return "?";
}

struct Config {
    // 只有文件里显式写出的 key；没列出的走 defaultWeight
    std::unordered_map<std::string, long long> weights;
    long long defaultWeight = kBuiltinDefaultWeight;
    Mode mode = Mode::Observe;
};

// 内置默认配置 = "清空配置"的结果
inline Config Defaults() { return Config(); }

// ---------------- 日志 ----------------
// 用函数指针 + void* 上下文，避免把 <functional> 拖进来，也方便 DLL 里
// 直接转发到自己的 Log()。
enum class Severity { Info = 0, Warn = 1, Error = 2 };

using LogFn = void (*)(void* ctx, int severity, const char* msg);

struct Logger {
    LogFn fn = nullptr;
    void* ctx = nullptr;
    void emit(int sev, const std::string& m) const {
        if (fn) fn(ctx, sev, m.c_str());
    }
    void info(const std::string& m) const { emit((int)Severity::Info, m); }
    void warn(const std::string& m) const { emit((int)Severity::Warn, m); }
    void error(const std::string& m) const { emit((int)Severity::Error, m); }
};

// ---------------- 小工具 ----------------
inline std::string Trim(const std::string& s) {
    size_t b = 0, e = s.size();
    while (b < e && std::isspace((unsigned char)s[b])) ++b;
    while (e > b && std::isspace((unsigned char)s[e - 1])) --e;
    return s.substr(b, e - b);
}

inline std::string Lower(std::string s) {
    for (size_t i = 0; i < s.size(); ++i)
        s[i] = (char)std::tolower((unsigned char)s[i]);
    return s;
}

inline std::string Fmt(const char* fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n < 0) return std::string();
    if ((size_t)n < sizeof(buf)) return std::string(buf, (size_t)n);
    return std::string(buf);  // 被截断，够日志用
}

// 严格十进制整数解析。
// 接受: "0" "-5" "+7" "100000"
// 拒绝: "" "1.5" "12abc" "0x10" "1 000" "soft" "ban" "9999999999999999999999"
inline bool ParseInt(const std::string& s, long long* out) {
    if (s.empty()) return false;
    // 内部不许有空白（strtoll 会自己跳过前导空白，这里先掐掉这种宽容）
    if (s.find_first_of(" \t\r\n\v\f") != std::string::npos) return false;
    const char* p = s.c_str();
    errno = 0;
    char* end = nullptr;
    long long v = std::strtoll(p, &end, 10);
    if (end == p) return false;       // 一个数字都没读到
    if (*end != '\0') return false;   // 后面还有垃圾
    if (errno == ERANGE) return false;
    if (out) *out = v;
    return true;
}

// ---------------- 单行解析 ----------------
enum class LineKind { Blank, Comment, Entry, Directive, Invalid };

struct LineResult {
    LineKind kind = LineKind::Blank;
    std::string key;    // Entry: 科技 key 原样（大小写敏感）/ Directive: 小写指令名，如 "@mode"
    std::string value;  // 原样（已 trim、已去注释）
    long long number = 0;   // Entry 权重 / @default 数值
    Mode mode = Mode::Observe;  // @mode
    std::string error;      // kind == Invalid 时的原因
};

// 解析一行（不含行尾 \n；调用方负责去掉 \r）→ 纯函数，无副作用
inline LineResult ParseLine(const std::string& raw) {
    LineResult r;
    size_t hash = raw.find('#');
    std::string head = (hash == std::string::npos) ? raw : raw.substr(0, hash);
    std::string body = Trim(head);
    if (body.empty()) {
        r.kind = (hash != std::string::npos) ? LineKind::Comment : LineKind::Blank;
        return r;
    }

    size_t eq = body.find('=');
    if (eq == std::string::npos) {
        r.kind = LineKind::Invalid;
        r.error = "no '=' separator";
        return r;
    }
    std::string name = Trim(body.substr(0, eq));
    std::string val = Trim(body.substr(eq + 1));
    if (name.empty()) {
        r.kind = LineKind::Invalid;
        r.error = "empty key before '='";
        return r;
    }
    if (val.empty()) {
        r.kind = LineKind::Invalid;
        r.error = Fmt("empty value for '%s'", name.c_str());
        return r;
    }
    r.value = val;

    if (name[0] == '@') {
        std::string dn = Lower(name);
        if (dn == "@mode") {
            std::string v = Lower(val);
            if (v == "take") {
                r.kind = LineKind::Directive;
                r.key = dn;
                r.mode = Mode::Take;
            } else if (v == "dryrun") {
                r.kind = LineKind::Directive;
                r.key = dn;
                r.mode = Mode::DryRun;
            } else if (v == "observe") {
                r.kind = LineKind::Directive;
                r.key = dn;
                r.mode = Mode::Observe;
            } else {
                r.kind = LineKind::Invalid;
                r.error = Fmt("invalid @mode value '%s' (expected observe|dryrun|take)", val.c_str());
            }
            return r;
        }
        if (dn == "@default") {
            long long v = 0;
            if (!ParseInt(val, &v)) {
                r.kind = LineKind::Invalid;
                r.error = Fmt("invalid @default value '%s' (decimal integer required)", val.c_str());
            } else {
                r.kind = LineKind::Directive;
                r.key = dn;
                r.number = v;
            }
            return r;
        }
        r.kind = LineKind::Invalid;
        r.error = Fmt("unknown directive '%s'", name.c_str());
        return r;
    }

    // 科技 key：不许含空白
    if (name.find_first_of(" \t\r\n\v\f") != std::string::npos) {
        r.kind = LineKind::Invalid;
        r.error = Fmt("invalid key '%s' (whitespace inside)", name.c_str());
        return r;
    }
    long long v = 0;
    if (!ParseInt(val, &v)) {
        // 关键点：soft / ban 等非数字值不再有特殊含义，统一按无效行处理
        r.kind = LineKind::Invalid;
        r.error = Fmt("invalid value '%s' for '%s' (decimal integer required; "
                      "string forms such as soft/ban are no longer supported)",
                      val.c_str(), name.c_str());
        return r;
    }
    r.kind = LineKind::Entry;
    r.key = name;
    r.number = v;
    return r;
}

// 应用一条已校验通过的行。Invalid 行返回 false 并给出原因（调用方负责记日志）。
inline bool ApplyLine(const LineResult& lr, Config* cfg, std::string* err) {
    switch (lr.kind) {
        case LineKind::Blank:
        case LineKind::Comment:
            return true;
        case LineKind::Directive:
            if (lr.key == "@mode") {
                cfg->mode = lr.mode;
            } else if (lr.key == "@default") {
                cfg->defaultWeight = lr.number;
            } else {
                if (err) *err = Fmt("unknown directive '%s'", lr.key.c_str());
                return false;
            }
            return true;
        case LineKind::Entry:
            cfg->weights[lr.key] = lr.number;   // 重复 key：后出现者覆盖前者
            return true;
        case LineKind::Invalid:
            if (err) *err = lr.error;
            return false;
    }
    if (err) *err = "unknown line kind";
    return false;
}

// ---------------- 整份文件解析 ----------------
struct ParseStats {
    int lines = 0;
    int blank = 0;
    int comment = 0;
    int entries = 0;
    int directives = 0;
    int invalid = 0;
};

// 解析整份文本。永远从 Defaults() 开始 → 出错的配置不会残留上一份的条目。
inline ParseStats ParseConfigText(const std::string& text, Config* out,
                                  const Logger& log,
                                  const char* sourceName = "config") {
    ParseStats st;
    if (!out) return st;
    *out = Defaults();

    std::string body = text;
    // UTF-16（含 BOM）无法按行解析：明确报错，不要静默产出垃圾
    if (body.size() >= 2) {
        unsigned char b0 = (unsigned char)body[0];
        unsigned char b1 = (unsigned char)body[1];
        if ((b0 == 0xFF && b1 == 0xFE) || (b0 == 0xFE && b1 == 0xFF)) {
            st.lines = 1;
            st.invalid = 1;
            log.error(Fmt("%s: UTF-16 encoding detected (BOM %02X %02X); "
                          "save the file as UTF-8. No entries loaded.",
                          sourceName, b0, b1));
            return st;
        }
    }
    // UTF-8 BOM：跳过（记事本 / VS Code 保存常带）
    if (body.size() >= 3 && (unsigned char)body[0] == 0xEF &&
        (unsigned char)body[1] == 0xBB && (unsigned char)body[2] == 0xBF) {
        body.erase(0, 3);
    }

    // 空文件算 1 个空行；否则按 '\n' 切分，末尾的 '\n' 不再多算一行
    if (body.empty()) {
        st.lines = 1;
        st.blank = 1;
        return st;
    }

    size_t pos = 0;
    int lineNo = 0;
    while (pos < body.size()) {
        size_t nl = body.find('\n', pos);
        std::string line = body.substr(pos, (nl == std::string::npos) ? std::string::npos
                                                                      : nl - pos);
        if (!line.empty() && line[line.size() - 1] == '\r') line.erase(line.size() - 1);
        ++lineNo;
        ++st.lines;

        LineResult lr = ParseLine(line);
        std::string why;
        switch (lr.kind) {
            case LineKind::Blank:
                ++st.blank;
                break;
            case LineKind::Comment:
                ++st.comment;
                break;
            case LineKind::Directive:
                if (!ApplyLine(lr, out, &why)) {
                    ++st.invalid;
                    log.warn(Fmt("%s: line %d ignored: %s", sourceName, lineNo, why.c_str()));
                } else {
                    ++st.directives;
                }
                break;
            case LineKind::Entry: {
                bool dup = out->weights.find(lr.key) != out->weights.end();
                if (!ApplyLine(lr, out, &why)) {
                    ++st.invalid;
                    log.warn(Fmt("%s: line %d ignored: %s", sourceName, lineNo, why.c_str()));
                } else {
                    ++st.entries;
                    if (dup) {
                        log.warn(Fmt("%s: line %d: duplicate key '%s', later value wins",
                                     sourceName, lineNo, lr.key.c_str()));
                    }
                }
                break;
            }
            case LineKind::Invalid:
                ++st.invalid;
                log.warn(Fmt("%s: line %d ignored: %s", sourceName, lineNo,
                             lr.error.c_str()));
                break;
        }
        if (nl == std::string::npos) break;
        pos = nl + 1;
    }
    return st;
}

// ---------------- 权重语义 ----------------
inline bool HasExplicitWeight(const Config& c, const std::string& key) {
    return c.weights.find(key) != c.weights.end();
}

inline long long EffectiveWeight(const Config& c, const std::string& key) {
    std::unordered_map<std::string, long long>::const_iterator it = c.weights.find(key);
    return (it == c.weights.end()) ? c.defaultWeight : it->second;
}

enum class PickStatus { Stop, Picked };
enum class PickTier { None, Positive, NegativeFallback };

struct PickResult {
    PickStatus status = PickStatus::Stop;
    PickTier tier = PickTier::None;
    int index = -1;        // keys 里的下标；Stop 时为 -1
    long long weight = 0;  // 选中者的权重
};

inline const char* TierName(PickTier t) {
    switch (t) {
        case PickTier::Positive: return "positive";
        case PickTier::NegativeFallback: return "negative-fallback";
        case PickTier::None: return "none";
    }
    return "none";
}

// 纯语义决策：给定候选 key 列表 + 配置 → 选谁。
//   - 只在 > 0 的候选里挑最大者（并列时取列表里靠前的）
//   - 0 永远不选
//   - 没有 > 0 的候选时，从 < 0 的候选里挑【数值最大】者（最接近 0 的优先）
//     例：候选 [-1, -1000] → 选 -1（旧语义是 -1000，2026-11-18 已修正）
//   - 都没有 → Stop（停止研究）
inline PickResult PickBest(const std::vector<std::string>& keys, const Config& cfg) {
    PickResult r;
    int bestPos = -1;
    long long bestPosW = 0;
    int bestNeg = -1;
    long long bestNegW = 0;

    for (size_t i = 0; i < keys.size(); ++i) {
        long long w = EffectiveWeight(cfg, keys[i]);
        if (w > 0) {
            if (bestPos < 0 || w > bestPosW) {
                bestPos = (int)i;
                bestPosW = w;
            }
        } else if (w < 0) {
            if (bestNeg < 0 || w > bestNegW) {   // ★ 取数值最大（最接近 0）
                bestNeg = (int)i;
                bestNegW = w;
            }
        }
        // w == 0：禁选，直接跳过
    }

    if (bestPos >= 0) {
        r.status = PickStatus::Picked;
        r.tier = PickTier::Positive;
        r.index = bestPos;
        r.weight = bestPosW;
        return r;
    }
    if (bestNeg >= 0) {
        r.status = PickStatus::Picked;
        r.tier = PickTier::NegativeFallback;
        r.index = bestNeg;
        r.weight = bestNegW;
        return r;
    }
    r.status = PickStatus::Stop;
    r.tier = PickTier::None;
    r.index = -1;
    r.weight = 0;
    return r;
}

// ============ hookA 是否改写返回地址 ============
// 这个决策必须可离线验证 —— 之前它内联在 Init() 里，
// 依赖真实文件 IO，导致「代码写了但没接线」的缺陷无法被发现。
//
// 语义：
//   dryrun  -> 0（只 patch 入口，不改写返回地址：单独验证 patch 本身是否安全）
//   observe -> 1（正常改写，能记录 hookA 的完整参数）
//   take    -> 1（正常改写；take 的改写逻辑在上层，与此开关无关）
inline uint8_t ShouldPatchReturnAddress(Mode m) {
    return (m == Mode::DryRun) ? 0 : 1;
}

inline std::string Describe(const Config& c) {
    return Fmt("mode=%s default=%lld entries=%zu", ModeName(c.mode),
               c.defaultWeight, c.weights.size());
}

// ---------------- 热重载 ----------------
// 文件快照。writeTime 用 Windows FILETIME（100ns 自 1601），测试里可填任意单调值。
struct Snapshot {
    bool exists = false;
    uint64_t writeTime = 0;
    uint64_t size = 0;
    bool SameAs(const Snapshot& o) const {
        return exists == o.exists && writeTime == o.writeTime && size == o.size;
    }
};

// 文件读取抽象：真实实现（Win32）在 DLL 里，测试里用内存假文件。
class IFileSource {
public:
    enum Status { Ok = 0, Missing = 1, Unreadable = 2 };
    virtual ~IFileSource() {}
    // Ok: 填 snap + content；Missing / Unreadable: 只关心返回值
    virtual int Read(Snapshot* snap, std::string* content) = 0;
};

enum class PollResult {
    NoChange = 0,   // 没变化，配置保持原样
    Reloaded = 1,   // 重新加载
    Cleared = 2,    // 文件不存在 → 配置已清空（内置默认）
    ReadFailed = 3  // 文件存在但读不到 → 配置已清空（内置默认）
};

inline const char* PollResultName(PollResult r) {
    switch (r) {
        case PollResult::NoChange: return "no-change";
        case PollResult::Reloaded: return "reloaded";
        case PollResult::Cleared: return "cleared";
        case PollResult::ReadFailed: return "read-failed";
    }
    return "?";
}

class Watcher {
public:
    explicit Watcher(IFileSource* src = nullptr) : src_(src) {}
    void setSource(IFileSource* src) { src_ = src; }

    // 轮询一次：需要时才重载。线程安全由调用方保证。
    PollResult Poll(Config* out, const Logger& log, const char* sourceName = "config") {
        if (!out) return PollResult::NoChange;
        Snapshot snap;
        std::string content;
        int st = src_ ? src_->Read(&snap, &content) : (int)IFileSource::Unreadable;

        if (st != (int)IFileSource::Ok) {
            bool wasPresent = loaded_ && last_.exists;
            if (wasPresent || !loaded_) {
                *out = Defaults();
                stats_ = ParseStats();
                loaded_ = true;
                last_ = Snapshot();   // 记住"不在场"：下次出现一定重载
                if (st == (int)IFileSource::Missing)
                    log.info(Fmt("%s: file not found -> config cleared "
                                 "(mode=observe, default=%lld, no entries)",
                                 sourceName, kBuiltinDefaultWeight));
                else
                    log.warn(Fmt("%s: file unreadable -> config cleared "
                                 "(mode=observe, default=%lld, no entries)",
                                 sourceName, kBuiltinDefaultWeight));
                return (st == (int)IFileSource::Missing) ? PollResult::Cleared
                                                         : PollResult::ReadFailed;
            }
            return PollResult::NoChange;
        }

        // 文件在场：时间戳 + 大小都没变才跳过；首次加载或从"消失"恢复也一定会进这里
        if (loaded_ && last_.exists && last_.SameAs(snap)) return PollResult::NoChange;

        stats_ = ParseConfigText(content, out, log, sourceName);
        last_ = snap;
        loaded_ = true;
        return PollResult::Reloaded;
    }

    const Snapshot& LastSnapshot() const { return last_; }
    const ParseStats& LastStats() const { return stats_; }
    bool Loaded() const { return loaded_; }
    // 忘掉状态（下次 Poll 一定重载）
    void Reset() { last_ = Snapshot(); loaded_ = false; stats_ = ParseStats(); }

private:
    IFileSource* src_ = nullptr;
    Snapshot last_;
    ParseStats stats_;
    bool loaded_ = false;
};

}  // namespace arcfg

#endif  // AR_CONFIG_H
