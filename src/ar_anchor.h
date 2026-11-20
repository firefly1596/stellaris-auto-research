// ar_anchor.h —— 锚点解析：不靠硬编码 RVA，而是从二进制内容里"认"出目标函数
//
// 为什么要有它：
//   硬编码 RVA 只在唯一一个构建上成立。用户装了 patch、换了游戏版本，
//   RVA 就指向别的函数 —— 轻则失效，重则崩游戏。锚点解析改成
//   "找特征 → 反查函数 → 多重互证"，同一套代码能跨版本工作。
//
// ================== 实测确认的事实（4.5.2 build 9776） ==================
//   1. 指令长度解码器（ar_lde.h）在 5 个已知函数上都"正好解到 .pdata 终点"，
//      说明 rip 相对引用反查是可靠的。
//   2. 编译器引用的是【完整字符串的起始地址】，不是子串：
//        "technology_status.cpp" 实际完整串是
//          "C:\mnt\gsg\stellaris\augustus\augustus\source\technology_status.cpp"
//      拿子串 RVA 去反查永远 0 命中 —— 这是本次实测踩到的最大坑。
//   3. hook A (0x81A900) 有两条**唯一**字符串锚点，各自只命中它一个函数：
//        "MESSAGE_TECHNOLOGY_RESEARCH_FINISH"     → 1 func
//        "TECHNOLOGY_ORDER_FINISH_MESSAGE_TYPE"   → 1 func
//      两者互证，可靠性很高。
//   4. 主 hook (0x425550) **没有任何字符串引用**（只有 vtable/.data 引用），
//      所以它无法用字符串锚点定位。但它可以被**调用链**定位：
//        0x81A900 直接 call 0x425550（调用点 0x81ADD5）
//      于是：锚点解析出 0x81A900 → 在该函数里找形如
//      "call <某个 .pdata 函数起点>" 且目标满足附加特征的调用 → 得到 0x425550。
//
// ================== 解析策略（按优先级） ==================
//   A. 字符串锚点 + 唯一性投票           → 能定 0x81A900
//   B. 调用链推导（从 A 的结果出发）      → 能定 0x425550
//   C. SHA256/版本精确匹配（兜底）        → 老路，保证在自己的版本上一定能用
//
//   任何一步不成立 → 该目标标记为 unresolved，绝不猜。
//   上层据此决定是"降级为 observe"还是"整份拒绝"（见 ar_gate.h 的分档逻辑）。
#pragma once
#ifndef AR_ANCHOR_H
#define AR_ANCHOR_H

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
#include <utility>

#include "ar_lde.h"

namespace aranchor {

// 锚点解析使用的映像接口。比 argate::IImage 多两个能力：
//   枚举 .pdata 函数、按段名搜字符串。
class IAnchorImage {
public:
    virtual ~IAnchorImage() {}
    virtual uint64_t Size() const = 0;
    // 该 RVA 所在段是否可执行
    virtual bool IsExecutable(uint32_t rva) const = 0;
    // 读字节（失败返回 false）
    virtual bool ReadBytes(uint32_t rva, void* dst, size_t n) const = 0;
    // 枚举 .pdata：函数 (start, end)
    virtual void EnumFunctions(std::vector<std::pair<uint32_t, uint32_t> >* out) const = 0;
    // 在指定段里找【完整的、NUL 结尾的】字符串，返回其起始 RVA。
    // 注意：必须匹配整条字符串，不能用子串（见文件头第 2 条）。
    virtual void FindStrings(const char* sectionName, const char* needle,
                             std::vector<uint32_t>* out) const = 0;
    // 段名（用于日志）
    virtual std::string Describe() const = 0;
};

// ---------------- 解析结果 ----------------
enum class How {
    None = 0,        // 没解析出来
    StringAnchor = 1,// 字符串锚点唯一定位
    CallChain = 2,   // 从已解析函数经调用链推导
    HashFallback = 3,// SHA256/版本精确匹配（老路兜底）
};

inline const char* HowName(How h) {
    switch (h) {
        case How::None: return "none";
        case How::StringAnchor: return "string-anchor";
        case How::CallChain: return "call-chain";
        case How::HashFallback: return "hash-fallback";
    }
    return "?";
}

struct Resolved {
    uint32_t rva = 0;
    How how = How::None;
    std::string evidence;      // 人类可读的"凭什么认为是它"
    uint32_t voteCount = 0;    // 有几个独立锚点指向它
    bool ok() const { return how != How::None && rva != 0; }
};

// ---------------- 单个锚点 ----------------
struct AnchorSpec {
    const char* text;        // 完整字符串（必须以 NUL 结尾出现在 .rdata 里）
    const char* section;     // 通常 ".rdata"
    const char* why;         // 日志说明
};

// 用一组字符串锚点定位函数：
//   每个锚点 → 搜字符串 RVA → 反查哪些函数 rip-引用它 → 投票
//   唯一最高票且票数 >= minVotes 才算成功
struct VoteResult {
    uint32_t rva = 0;
    uint32_t votes = 0;
    std::vector<std::pair<uint32_t, uint32_t> > all;   // (funcRva, refs) 全部命中，日志用
    std::string detail;
    bool ok() const { return rva != 0 && votes > 0; }
};

inline VoteResult ResolveByStrings(const IAnchorImage& img,
                                   const AnchorSpec* specs, size_t nSpecs,
                                   size_t maxFuncLen = 60000,
                                   uint32_t minVotes = 1) {
    VoteResult vr;
    std::vector<std::pair<uint32_t, uint32_t> > funcs;
    img.EnumFunctions(&funcs);
    if (funcs.empty()) {
        vr.detail = "no .pdata entries";
        return vr;
    }

    // 每个锚点独立投一票
    std::vector<std::pair<uint32_t, uint32_t> > tally;   // (funcRva, votes)
    std::string detail;
    for (size_t i = 0; i < nSpecs; ++i) {
        std::vector<uint32_t> strRvas;
        img.FindStrings(specs[i].section ? specs[i].section : ".rdata",
                        specs[i].text, &strRvas);
        if (strRvas.empty()) {
            detail += std::string("  [skip] \"") + specs[i].text + "\" : string not found\n";
            continue;
        }
        uint32_t strRva = strRvas[0];
        uint32_t foundFunc = 0;
        uint32_t foundRefs = 0;
        int funcsHit = 0;
        for (size_t k = 0; k < funcs.size(); ++k) {
            uint32_t start = funcs[k].first, end = funcs[k].second;
            uint32_t len = end - start;
            if (len == 0 || len > maxFuncLen) continue;
            // 分块读（避免一次性分配过大的栈缓冲）
            std::vector<uint8_t> code(len);
            if (!img.ReadBytes(start, code.data(), len)) continue;
            uint32_t site = 0;
            uint32_t n = arlde::CountRipRefs(code.data(), len, start, strRva, &site);
            if (n > 0) {
                ++funcsHit;
                // 记录"票"：每个锚点只给它命中的第一个函数投一票；
                // 若命中多个函数，说明锚点不唯一，降低可信度（不投票）
                if (funcsHit == 1) {
                    foundFunc = start;
                    foundRefs = n;
                }
            }
        }
        char buf[256];
        snprintf(buf, sizeof(buf), "  \"%s\" @0x%X -> %d func(s)%s\n",
                 specs[i].text, strRva, funcsHit,
                 funcsHit == 1 ? " (unique)" : (funcsHit == 0 ? "" : " (ambiguous, no vote)"));
        detail += buf;
        if (funcsHit == 1) {
            bool merged = false;
            for (size_t t = 0; t < tally.size(); ++t)
                if (tally[t].first == foundFunc) { tally[t].second++; merged = true; break; }
            if (!merged) tally.push_back(std::make_pair(foundFunc, (uint32_t)1));
            vr.all.push_back(std::make_pair(foundFunc, foundRefs));
        }
    }

    if (tally.empty()) {
        vr.detail = detail + "  no anchor produced a unique function\n";
        return vr;
    }
    // 取票数最高者
    std::sort(tally.begin(), tally.end(),
              [](const std::pair<uint32_t, uint32_t>& a,
                 const std::pair<uint32_t, uint32_t>& b) {
                  return a.second > b.second;
              });
    if (tally.size() > 1 && tally[0].second == tally[1].second) {
        char buf[160];
        snprintf(buf, sizeof(buf),
                 "  ambiguous: 0x%X and 0x%X both got %u vote(s) -- refusing to guess\n",
                 tally[0].first, tally[1].first, tally[0].second);
        vr.detail = detail + buf;
        return vr;   // 不猜
    }
    vr.rva = tally[0].first;
    vr.votes = tally[0].second;
    vr.detail = detail;
    if (vr.votes < minVotes) {
        char buf[160];
        snprintf(buf, sizeof(buf), "  only %u vote(s), need %u\n", vr.votes, minVotes);
        vr.detail += buf;
        vr.rva = 0;
        vr.votes = 0;
    }
    return vr;
}

// ---------------- 调用链推导 ----------------
// 在 parentRva 指向的函数体里，找所有 `call rel32`，其目标必须是 .pdata 里
// 某个函数的起点。返回去重后的 (calleeRva, callSiteRva) 列表。
struct CallEdge {
    uint32_t callee;
    uint32_t site;
};

inline std::vector<CallEdge> DirectCallsFrom(const IAnchorImage& img, uint32_t parentRva,
                                             size_t maxFuncLen = 60000) {
    std::vector<CallEdge> edges;
    std::vector<std::pair<uint32_t, uint32_t> > funcs;
    img.EnumFunctions(&funcs);

    uint32_t len = 0;
    for (size_t i = 0; i < funcs.size(); ++i)
        if (funcs[i].first == parentRva) { len = funcs[i].second - funcs[i].first; break; }
    if (len == 0 || len > maxFuncLen) return edges;

    std::vector<uint8_t> code(len);
    if (!img.ReadBytes(parentRva, code.data(), len)) return edges;

    // 函数起点集合，用于校验 call 目标确实是函数入口
    std::vector<uint32_t> starts;
    starts.reserve(funcs.size());
    for (size_t i = 0; i < funcs.size(); ++i) starts.push_back(funcs[i].first);
    std::sort(starts.begin(), starts.end());

    size_t off = 0;
    size_t guard = 0;
    while (off < len && guard++ < 200000) {
        arlde::Insn in = arlde::Decode(code.data() + off, len - off);
        if (!in.ok || in.length == 0) break;
        if (!in.twoByte && in.opcode == 0xE8 && off + 5 <= len) {
            int32_t rel = 0;
            memcpy(&rel, code.data() + off + 1, 4);
            int64_t next = (int64_t)parentRva + (int64_t)off + 5;
            int64_t tgt = next + (int64_t)rel;
            // 不依赖 Size()：真实的身份校验是"目标必须是 .pdata 函数入口"
            // （下面的 binary_search）。Size() 只是上界，若实现方没填，
            // 用它当唯一判据会让整个调用链静默返回空 —— 那是最难查的失败。
            uint64_t upper = img.Size();
            if (upper == 0) upper = 0xFFFFFFFFull;
            if (tgt > 0 && (uint64_t)tgt < upper) {
                uint32_t t = (uint32_t)tgt;
                if (std::binary_search(starts.begin(), starts.end(), t)) {
                    bool dup = false;
                    for (size_t i = 0; i < edges.size(); ++i)
                        if (edges[i].callee == t) { dup = true; break; }
                    if (!dup) {
                        CallEdge e;
                        e.callee = t;
                        e.site = (uint32_t)(parentRva + off);
                        edges.push_back(e);
                    }
                }
            }
        }
        off += in.length;
    }
    return edges;
}

// ---------------- 稀有 callee 指纹 ----------------
// 主 hook 的一个很强行为特征：它自己会调用「选择算法」和「取玩家国家」。
// 这两个 callee 的稀有度差很多：
//   SEL (选择算法)   全 exe 只有  8 个函数调用  -> 强证据
//   GETC(取玩家国家) 全 exe 有 1545 个函数调用  -> 只能当辅证
// 所以判据是"同时出现 + 次数吻合"，而不是"出现过"。
struct CallSignature {
    std::vector<std::pair<uint32_t, uint32_t> > expected;  // (calleeRva, exactCount)
    std::string detail;
    bool ok = false;
};

// 统计某个函数对若干 callee 的调用次数
inline std::vector<uint32_t> CountCallsTo(const IAnchorImage& img, uint32_t funcRva,
                                          const std::vector<uint32_t>& callees,
                                          size_t maxFuncLen = 60000) {
    std::vector<uint32_t> counts(callees.size(), 0);
    std::vector<std::pair<uint32_t, uint32_t> > funcs;
    img.EnumFunctions(&funcs);
    uint32_t len = 0;
    for (size_t i = 0; i < funcs.size(); ++i)
        if (funcs[i].first == funcRva) { len = funcs[i].second - funcs[i].first; break; }
    if (len == 0 || len > maxFuncLen) return counts;
    std::vector<uint8_t> code(len);
    if (!img.ReadBytes(funcRva, code.data(), len)) return counts;

    size_t off = 0, guard = 0;
    while (off < len && guard++ < 200000) {
        arlde::Insn in = arlde::Decode(code.data() + off, len - off);
        if (!in.ok || in.length == 0) break;
        if (!in.twoByte && in.opcode == 0xE8 && off + 5 <= len) {
            int32_t rel = 0;
            memcpy(&rel, code.data() + off + 1, 4);
            int64_t next = (int64_t)funcRva + (int64_t)off + 5;
            int64_t tgt = next + (int64_t)rel;
            for (size_t c = 0; c < callees.size(); ++c)
                if (tgt == (int64_t)callees[c]) counts[c]++;
        }
        off += in.length;
    }
    return counts;
}

// 校验一个候选函数是否满足"稀有 callee 组合"指纹
inline CallSignature VerifyCallSignature(const IAnchorImage& img, uint32_t funcRva,
                                         const std::vector<uint32_t>& callees,
                                         const std::vector<uint32_t>& wantCounts) {
    CallSignature sig;
    std::vector<uint32_t> got = CountCallsTo(img, funcRva, callees);
    bool all = true;
    char buf[320];
    std::string d;
    for (size_t i = 0; i < callees.size(); ++i) {
        snprintf(buf, sizeof(buf), "callee 0x%X calls=%u (want %u)%s\n",
                 callees[i], got[i], wantCounts[i],
                 got[i] == wantCounts[i] ? "" : "  <-- MISMATCH");
        d += buf;
        if (got[i] != wantCounts[i]) all = false;
    }
    sig.ok = all;
    sig.detail = d;
    return sig;
}

// ---------------- 主入口 ----------------
// 按 A → B → C 的顺序解析全部目标。
struct TargetPlan {
    const char* name;
    Resolved resolved;
    // 解析失败的原因（写日志用，必须具体）
    std::string failure;
};

struct ResolveReport {
    std::vector<TargetPlan> targets;
    std::string log;              // 全程可读日志
    bool allResolved = false;
    size_t resolvedCount = 0;

    const TargetPlan* Find(const char* name) const {
        for (size_t i = 0; i < targets.size(); ++i)
            if (strcmp(targets[i].name, name) == 0) return &targets[i];
        return nullptr;
    }
};

// 主 hook 候选的特征：它是 hookA 的直接被调者之一，且函数长度落在合理区间。
// 这里用"从 hookA 调用链里取指定名字的边"的方式，由调用方指定每个目标的策略。

// 解析 hook A（纯字符串锚点，两条互证）
inline ResolveReport ResolveHookA(const IAnchorImage& img, const AnchorSpec* specs,
                                  size_t nSpecs) {
    ResolveReport rep;
    TargetPlan tp;
    tp.name = "hookA";
    VoteResult vr = ResolveByStrings(img, specs, nSpecs, 60000, 2);
    rep.log += "== resolve hookA (string anchors, need >=2 votes) ==\n";
    rep.log += vr.detail;
    if (vr.ok()) {
        tp.resolved.rva = vr.rva;
        tp.resolved.how = How::StringAnchor;
        tp.resolved.voteCount = vr.votes;
        char buf[192];
        snprintf(buf, sizeof(buf), "%u independent string anchor(s) agree on 0x%X",
                 vr.votes, vr.rva);
        tp.resolved.evidence = buf;
        ++rep.resolvedCount;
    } else {
        tp.failure = "string anchors did not converge on a unique function";
        rep.log += "  FAILED: " + tp.failure + "\n";
    }
    rep.targets.push_back(tp);
    return rep;
}

}  // namespace aranchor

#endif  // AR_ANCHOR_H
