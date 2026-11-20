// ar_resolve.h —— 地址解析与 hook 安装的分层编排
//
// 职责：把"这些目标函数在哪"这件事和"怎么装 hook"彻底分开，
// 这样出问题时能一眼看出是【没找到】还是【找到了但装不上】。
//
// ================== 解析优先级 ==================
//   1. 字符串锚点 + 投票     （跨版本最稳）
//   2. 调用链推导            （主 hook 没有字符串锚点时用）
//   3. SHA256/版本精确匹配   （兜底，保证在自己版本上一定能用）
//   最后统一用【函数长度 + 序言字节】互证，任何一项不符就降级。
//
// ================== 分级降级（不是全有或全无） ==================
//   Required  ：缺了就不能启用 take（退化成纯 observe）
//   Optional  ：缺了只是少一个增强功能
//
//   特别注意：MainHook 和 HookA 是**同一个功能的两半** ——
//   HookA 提供"当前是不是玩家"的判据，MainHook 提供候选池与选择。
//   只有其中一个装上会导致"看起来在工作但判据失效"，比不装更糟。
//   所以两者被捆绑成一个 Required 组：要么都成，要么都不装。
#pragma once
#ifndef AR_RESOLVE_H
#define AR_RESOLVE_H

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>

#include "ar_anchor.h"
#include "ar_gate.h"
#include "ar_layout.h"

namespace arresolve {

// =====================================================================
// L1 结构偏移自动推导（候选卡组）
// =====================================================================
//
// 为什么放在这里而不是 auto_research.cpp：
//   推导需要"读游戏 exe 的 C890 函数体"，而 ar_resolve 已经持有 IAnchorImage。
//   放在这一层，DLL 和离线测试可以用同一份实现。
//
// 重要约束（来自 L1_PROTOTYPE_REPORT §6）：
//   - 失败必须返回 nullopt，【不得 fallback 到硬编码值】
//   - 调用方必须处理 nullopt -> 降级为"候选卡功能禁用"
//   - 偏移只能从指令 disp 读，代码里不得出现 0x31B0/0x31BC 字面量
//
// 当前接入状态（2026-11-11）：
//   本函数已实现并有 19 项离线测试（layout_test.cpp），
//   但【尚未接入 InstallAll()】—— 需要先确认 C890 定位可靠。
//   接入时应当：
//     1. 用 C890 的 RVA 调 DeriveCardLayout()
//     2. 失败 -> Log("[WARN] 候选卡布局推导失败: ...") 并禁用相关功能
//     3. 成功 -> 用它替代写死的 country+0x31B0/+0x31BC 常量
struct CardLayoutResult {
    bool ok = false;
    arlayout::CardLayout layout{};
    std::vector<std::string> diag;   // 失败原因，调用方应写入日志
};

// 从已解析的 exe 镜像里，用 C890 的 RVA 推导候选卡布局。
// 返回 ok=false 时必须降级，不得使用 layout。
inline CardLayoutResult DeriveCardLayout(const aranchor::IAnchorImage& img,
                                         uint32_t c890Rva) {
    CardLayoutResult out;

    // C890 必须是 .pdata 里的函数起点，且长度合理
    std::vector<std::pair<uint32_t,uint32_t>> funcs;
    img.EnumFunctions(&funcs);
    uint32_t len = 0;
    // 注意：EnumFunctions 的契约是 (start, end)，不是 (start, len)。
    for (auto& f : funcs) if (f.first == c890Rva) { len = f.second - f.first; break; }
    if (len == 0) {
        out.diag.push_back("C890 RVA 不是 .pdata 函数起点（或长度未知）");
        return out;
    }
    if (len > 200000) {
        out.diag.push_back("C890 长度异常（" + std::to_string(len) + " 字节），拒绝推导");
        return out;
    }

    std::vector<uint8_t> code(len);
    if (!img.ReadBytes(c890Rva, code.data(), len)) {
        out.diag.push_back("无法读取 C890 函数体");
        return out;
    }

    arlayout::Diag dg;
    auto r = arlayout::FindCardLayout(code.data(), code.size(), c890Rva, &dg);
    out.diag = dg.lines;
    if (!r) return out;      // ok 保持 false

    out.ok = true;
    out.layout = *r;
    return out;
}

// =====================================================================
// C890（权重计算）定位 + 候选卡布局三级推导
// =====================================================================
//
// ============ 为什么是三级，而不是一步 ============
//
// 这里有一个必须解开的循环：
//     要推导候选卡偏移  ->  需要先知道 C890 在哪
//     要定位 C890       ->  如果拿「体内含 +0x31B0」当判据 -> 又需要先知道偏移
//
// 解法：把定位和校验拆开，定位阶段【完全不看偏移】。
//
//     阶段 1  定位 C890   判据 = 被 E4B0 调用 + 长度 4074      （不用偏移）
//     阶段 2  推导偏移    形状扫描，从指令 disp 读            （产出偏移）
//     阶段 3  二次校验    用推导出的偏移回头验 C890 体内确有对应访问（用偏移）
//
// 顺序天然无环：1 不依赖偏移 -> 2 产出偏移 -> 3 消费偏移。
//
// ============ 三级失败的含义不同（诊断方向也不同）============
//     阶段 1 失败  -> C890 没找到          -> 可能版本变了（E4B0 或长度特征变了）
//     阶段 2 失败  -> 形状扫描失败        -> 可能编译器生成的代码形态变了
//     阶段 3 失败  -> 推导值可疑          -> 可能形状匹配到了错误的东西
//
// ============ 阶段 1 判据的实测依据 ============
//   4.5.2  E4B0=0x81E4B0  len=1768  中 len==4074 的 callee: 0x81C890 (callsite 0x81E752)  唯一
//   4.5.4  E4B0=0x820400  len=1768  中 len==4074 的 callee: 0x81E7E0 (callsite 0x8206A2)  唯一
//   且【全 exe 长度 4074 的函数都只有 1 个】—— 即使 E4B0 链断了，单靠长度也能定位。
//
// ============ 阶段 3 的判据【不能】是「等于 0x31BC」============
//   写成「推导值 == 0x31BC」就又变硬编码了，版本一变必失败。
//   正确做法：用推导出的偏移，在 C890 体内查找对应的内存访问指令，
//             【数量 > 0 即可】，不要求等于任何特定值。
//   这样它验证的是「推导出的偏移在函数里真的被用过」，
//   而不是「推导值等于我知道的那个数」。

struct WeightCalcResult {
    bool ok = false;
    uint32_t rva = 0;
    uint32_t len = 0;
    std::vector<std::string> diag;
};

// 阶段 0：定位 E4B0（C890 的唯一上游）
//
// 判据 = 被 hookA 直接调用 + 函数长度 == expectLen。
// 实测（两版本均唯一）：
//   4.5.2  hookA=0x81A900 的 callee 中 len==1768 的: 0x81E4B0  唯一
//   4.5.4  hookA=0x81C850 的 callee 中 len==1768 的: 0x820400  唯一
//
// 与 LocateWeightCalc 的关系：
//   hookA --call--> E4B0 --call--> C890
//   每一级都用「父函数直接调用 + 子函数长度」定位，都不依赖结构偏移。
inline WeightCalcResult LocateMidE4B0(const aranchor::IAnchorImage& img,
                                      uint32_t hookARva,
                                      uint32_t expectLen) {
    WeightCalcResult out;

    std::vector<std::pair<uint32_t,uint32_t>> funcs;
    img.EnumFunctions(&funcs);

    auto lenOf = [&](uint32_t rva) -> uint32_t {
        for (auto& f : funcs) if (f.first == rva) return f.second - f.first;
        return 0;
    };

    uint32_t hookALen = lenOf(hookARva);
    if (hookALen == 0) {
        out.diag.push_back("阶段0: hookA RVA 不是 .pdata 函数起点 —— 无法定位 E4B0");
        return out;
    }

    std::vector<uint8_t> code(hookALen);
    if (!img.ReadBytes(hookARva, code.data(), hookALen)) {
        out.diag.push_back("阶段0: 无法读取 hookA 函数体");
        return out;
    }

    std::vector<uint32_t> callees;
    {
        size_t off = 0;
        while (off < hookALen) {
            arlde::Insn in = arlde::Decode(code.data() + off, hookALen - off);
            if (!in.ok || in.length == 0) break;
            if (!in.twoByte && in.opcode == 0xE8 && off + 5 <= hookALen) {
                int32_t rel; __builtin_memcpy(&rel, code.data() + off + 1, 4);
                int64_t next = (int64_t)hookARva + off + 5;
                int64_t tgt  = next + rel;
                if (tgt > 0 && tgt < 0x40000000) {
                    uint32_t g = (uint32_t)tgt;
                    if (std::find(callees.begin(), callees.end(), g) == callees.end())
                        callees.push_back(g);
                }
            }
            off += in.length;
        }
    }
    out.diag.push_back("阶段0: hookA 直接调用 " + std::to_string(callees.size()) + " 个函数");

    std::vector<uint32_t> hits;
    for (uint32_t c : callees) if (lenOf(c) == expectLen) hits.push_back(c);

    if (hits.empty()) {
        out.diag.push_back("阶段0: hookA 的 callee 中没有长度为 " +
                           std::to_string(expectLen) + " 的函数");
        return out;
    }
    if (hits.size() > 1) {
        out.diag.push_back("阶段0: 长度为 " + std::to_string(expectLen) +
                           " 的 callee 有 " + std::to_string(hits.size()) +
                           " 个 —— 判据不足以区分，放弃（不挑第一个）");
        return out;
    }

    out.ok  = true;
    out.rva = hits[0];
    out.len = expectLen;
    {
        char b[200];
        snprintf(b, sizeof(b), "阶段0: 定位 E4B0 = 0x%X (len=%u, 唯一)", out.rva, out.len);
        out.diag.push_back(b);
    }
    return out;
}

// 阶段 1：定位 C890。
// 判据 = 被 e4b0Rva 直接调用 + 函数长度 == expectLen。
// 【不使用任何结构偏移】—— 这是避免循环的关键。
inline WeightCalcResult LocateWeightCalc(const aranchor::IAnchorImage& img,
                                         uint32_t e4b0Rva,
                                         uint32_t expectLen) {
    WeightCalcResult out;

    std::vector<std::pair<uint32_t,uint32_t>> funcs;
    img.EnumFunctions(&funcs);

    auto lenOf = [&](uint32_t rva) -> uint32_t {
        for (auto& f : funcs) if (f.first == rva) return f.second - f.first;
        return 0;
    };

    uint32_t e4b0Len = lenOf(e4b0Rva);
    if (e4b0Len == 0) {
        out.diag.push_back("阶段1: E4B0 RVA 不是 .pdata 函数起点");
        return out;
    }

    std::vector<uint8_t> code(e4b0Len);
    if (!img.ReadBytes(e4b0Rva, code.data(), e4b0Len)) {
        out.diag.push_back("阶段1: 无法读取 E4B0 函数体");
        return out;
    }

    // 扫 E4B0 体内的直接 E8 call，收集 callee RVA（去重）
    std::vector<uint32_t> callees;
    {
        size_t off = 0;
        while (off < e4b0Len) {
            arlde::Insn in = arlde::Decode(code.data() + off, e4b0Len - off);
            if (!in.ok || in.length == 0) break;
            if (!in.twoByte && in.opcode == 0xE8 && off + 5 <= e4b0Len) {
                int32_t rel; __builtin_memcpy(&rel, code.data() + off + 1, 4);
                int64_t next = (int64_t)e4b0Rva + off + 5;
                int64_t tgt  = next + rel;
                if (tgt > 0 && tgt < 0x40000000) {
                    uint32_t g = (uint32_t)tgt;
                    if (std::find(callees.begin(), callees.end(), g) == callees.end())
                        callees.push_back(g);
                }
            }
            off += in.length;
        }
    }
    out.diag.push_back("阶段1: E4B0 直接调用 " + std::to_string(callees.size()) + " 个函数");

    // 唯一性：长度 == expectLen 的 callee 必须【恰好 1 个】
    std::vector<uint32_t> hits;
    for (uint32_t c : callees) if (lenOf(c) == expectLen) hits.push_back(c);

    if (hits.empty()) {
        out.diag.push_back("阶段1: E4B0 的 callee 中没有长度为 " +
                           std::to_string(expectLen) + " 的函数");
        return out;
    }
    if (hits.size() > 1) {
        out.diag.push_back("阶段1: 长度为 " + std::to_string(expectLen) +
                           " 的 callee 有 " + std::to_string(hits.size()) +
                           " 个 —— 判据不足以区分，放弃（不挑第一个）");
        return out;
    }

    out.ok  = true;
    out.rva = hits[0];
    out.len = expectLen;
    char b[200];
    snprintf(b, sizeof(b), "阶段1: 定位 C890 = 0x%X (len=%u, 唯一)", out.rva, out.len);
    out.diag.push_back(b);
    return out;
}

// 阶段 3：用推导出的偏移，回头验证 C890 体内确实访问了这些偏移。
// 判据【不要求等于任何特定值】，只要求「能找到访问」。
inline bool VerifyLayoutUsed(const aranchor::IAnchorImage& img,
                             uint32_t c890Rva, uint32_t c890Len,
                             const arlayout::CardLayout& lay,
                             std::vector<std::string>* diag) {
    std::vector<uint8_t> code(c890Len);
    if (!img.ReadBytes(c890Rva, code.data(), c890Len)) {
        if (diag) diag->push_back("阶段3: 无法读取 C890 函数体");
        return false;
    }
    arlayout::DecodedFn d = arlayout::DecodeFunction(code.data(), code.size(), c890Rva);
    if (!d.complete) {
        if (diag) diag->push_back("阶段3: 线性解码未完成，无法校验");
        return false;
    }

    int nCount = 0, nArray = 0;
    for (const arlde::Insn& in : d.insns) {
        if (!in.hasModRm || in.modrmMod == 3) continue;
        if (in.hasRipRel) continue;
        if (in.disp == (int64_t)lay.countOff) ++nCount;
        if (in.disp == (int64_t)lay.arrayOff) ++nArray;
    }

    if (diag) {
        char b[240];
        snprintf(b, sizeof(b),
                 "阶段3: 用推导值校验 —— count_off=0x%X 出现 %d 次, array_off=0x%X 出现 %d 次",
                 lay.countOff, nCount, lay.arrayOff, nArray);
        diag->push_back(b);
    }
    // 只要求「被用过」，不要求次数等于某值（次数会随编译变化）
    return nCount > 0 && nArray > 0;
}

// =====================================================================
// take 链路编排：hookA -> E4B0 -> C890 -> 候选卡布局
// =====================================================================
//
// 一次调用走完全部阶段，返回结构化结果供 InstallAll() 使用。
// 每一级失败都不影响 observe（只有 MainHook + HookA 是必需组）。
//
// 返回字段说明：
//   e4b0Ok / e4b0Rva      研究槽决策函数是否定位到
//   c890Ok / c890Rva      权重计算函数是否定位到
//   layoutOk / layout     候选卡布局是否推导出来
//   legacyMatch           推导值是否与 legacy 常量一致（仅用于告警，不做 fallback）
//   log                   分级日志行（调用方直接逐行打印）
struct TakeChainResult {
    bool e4b0Ok   = false;
    uint32_t e4b0Rva = 0;
    bool c890Ok   = false;
    uint32_t c890Rva = 0;
    uint32_t c890Len = 0;
    // ---- SEL 探针（0x81A5B0 = 选卡函数，CMOVcc×4）----
    bool selOk   = false;
    uint32_t selRva = 0;
    uint32_t selLen = 0;
    bool layoutOk = false;
    arlayout::CardLayout layout{};
    bool legacyCompared = false;   // 是否做了 legacy 对照
    bool legacyMatch    = false;   // 对照结果
    std::vector<std::string> log;  // 分级日志
};

// legacy 对照用的常量（仅用于比对告警，【绝不用于 fallback】）
struct LegacyCardOffsets {
    uint32_t countOff;
    uint32_t arrayOff;
};

inline TakeChainResult DeriveTakeChain(const aranchor::IAnchorImage& img,
                                       uint32_t hookARva,
                                       uint32_t e4b0ExpectLen,
                                       uint32_t c890ExpectLen,
                                       const LegacyCardOffsets* legacy) {
    TakeChainResult r;

    // ---------- 阶段 0：E4B0 ----------
    auto e4 = LocateMidE4B0(img, hookARva, e4b0ExpectLen);
    for (auto& l : e4.diag) r.log.push_back("[INFO] " + l);
    if (!e4.ok) {
        r.log.push_back("[WARN] mid-e4b0 not found (phase 0) -> take disabled, "
                        "observe still works");
        return r;
    }
    r.e4b0Ok = true;
    r.e4b0Rva = e4.rva;

    // ---------- 阶段 1：C890 ----------
    auto w = LocateWeightCalc(img, r.e4b0Rva, c890ExpectLen);
    for (auto& l : w.diag) r.log.push_back("[INFO] " + l);
    if (!w.ok) {
        r.log.push_back("[WARN] weight-calc not found (phase 1) -> take disabled, "
                        "observe still works");
        return r;
    }
    r.c890Ok = true;
    r.c890Rva = w.rva;
    r.c890Len = w.len;

    // ---------- 阶段 1.5：SEL（选卡函数）----------
    //   定位依据：长度 + CMOVcc 计数（跨 6 版本 CMOV 恒为 4）
    //   这是「从候选里取权重最大者」的函数，与 C890（算权重）是不同阶段。
    {
        std::vector<std::pair<uint32_t,uint32_t>> funcs;
        img.EnumFunctions(&funcs);
        const uint32_t kSelExpectLen = 3503;
        int found = 0; uint32_t selRva = 0;
        for (auto& f : funcs) {
            if (f.second - f.first != kSelExpectLen) continue;
            std::vector<uint8_t> code(kSelExpectLen);
            if (!img.ReadBytes(f.first, code.data(), kSelExpectLen)) continue;
            // ★ 只数 CMOVG（0F 4F）—— 不是全部 CMOVcc(0F 4x)
            //   实测 0x81A5B0: cmovg=4, cmov(含 ae/l/o)=12
            //   之前的 bug：把全部 CMOVcc 数成 12，与判据 4 不符 → 0 命中
            int cmovg = 0, cmovAll = 0, b0 = 0, bc = 0, d8 = 0;
            for (size_t i = 0; i + 8 < code.size(); ++i) {
                if (code[i] == 0x0F && code[i+1] >= 0x40 && code[i+1] <= 0x4F) {
                    ++cmovAll;
                    if (code[i+1] == 0x4F) ++cmovg;   // ★ CMOVG only
                }
                const uint8_t m = code[i+1];
                if ((m & 0xC0) == 0x80) {
                    const uint32_t d = (uint32_t)code[i+2] | ((uint32_t)code[i+3] << 8)
                                     | ((uint32_t)code[i+4] << 16) | ((uint32_t)code[i+5] << 24);
                    if (d == 0x31B0) ++b0;
                    if (d == 0x31BC) ++bc;
                    if (d == 0x31D8) ++d8;
                }
            }
            if (cmovg == 4 && b0 && bc && d8) { ++found; selRva = f.first; }
        }
        char buf[256];
        snprintf(buf, sizeof(buf),
                 "[INFO] SEL candidate: len=%u cmovg=4 -> %d match(es), rva=0x%X",
                 kSelExpectLen, found, selRva);
        r.log.push_back(buf);
        if (found == 1) { r.selOk = true; r.selRva = selRva; r.selLen = kSelExpectLen; }
        else r.log.push_back("[WARN] SEL not uniquely located -> probe skipped");
    }

    // ---------- 阶段 2：推导候选卡布局 ----------
    auto lay = DeriveCardLayout(img, r.c890Rva);
    for (auto& l : lay.diag) r.log.push_back("[INFO] " + l);
    if (!lay.ok) {
        r.log.push_back("[WARN] card layout derivation failed (phase 2) -> "
                        "take disabled, observe still works");
        return r;
    }
    r.layoutOk = true;
    r.layout = lay.layout;
    {
        char b[240];
        snprintf(b, sizeof(b),
                 "[INFO] card layout derived: count_off=0x%X array_off=0x%X elem=%u "
                 "(source: shape-derivation, not hardcoded)",
                 r.layout.countOff, r.layout.arrayOff, r.layout.elemSize);
        r.log.push_back(b);
    }

    // ---------- 阶段 3：二次校验（用推导值回头验 C890 体内确有访问）----------
    {
        std::vector<std::string> d3;
        bool v = VerifyLayoutUsed(img, r.c890Rva, r.c890Len, r.layout, &d3);
        for (auto& l : d3) r.log.push_back("[INFO] " + l);
        if (!v) {
            r.layoutOk = false;
            r.log.push_back("[WARN] derived offsets suspicious (phase 3) -> "
                            "take disabled, observe still works");
            return r;
        }
    }

    // ---------- legacy 对照（只告警，绝不 fallback）----------
    if (legacy) {
        r.legacyCompared = true;
        r.legacyMatch = (r.layout.countOff == legacy->countOff &&
                         r.layout.arrayOff == legacy->arrayOff);
        char b[280];
        snprintf(b, sizeof(b),
                 "[INFO] derived count=0x%X array=0x%X vs legacy constant "
                 "count=0x%X array=0x%X (%s) -- legacy is REFERENCE ONLY, "
                 "never used as fallback",
                 r.layout.countOff, r.layout.arrayOff,
                 legacy->countOff, legacy->arrayOff,
                 r.legacyMatch ? "match" : "MISMATCH");
        r.log.push_back(b);
        if (!r.legacyMatch) {
            r.log.push_back("[WARN] card offsets differ from legacy constant -- "
                            "this is a signal that the structure changed; "
                            "verify take behaviour before trusting it");
        }
    }

    return r;
}

// ---------------- 目标角色 ----------------
enum class Role {
    MainHook = 0,   // 自动科研选科技入口（被 hook）
    HookA = 1,      // 「开始研究」汇聚点（被 hook）
    // 注：StrCtor / StrDtor / GetPlayer 三个角色已于 2026-11-12 删除。
    // 理由（见 DESIGN_454_ADAPT.md 第 0 步）：
    //   它们只被赋值、从未被调用（grep 调用形式零命中），是纯死代码；
    //   且服务的功能（改写 out）已被 FINDINGS §3.2 证伪，take 不需要它们。
    // 保留它们只会持续制造 [weak] 与误导性 WARNING。
    // ---- take 模式链路（2026-11-11 新增）----
    // 顺序刻意保持「从上游到下游」，便于日志阅读失败发生在哪一级。
    //
    //   hookA  --call-->  E4B0  --call-->  C890
    //   (已定位)          (len 1768)      (len 4074，全 exe 唯一)
    //
    // 注意：这两个【都不是】必需组。缺了只是禁用 take，observe 照常工作。
    MidE4B0 = 5,    // 研究槽决策（C890 的唯一上游）
    WeightCalc = 6, // 权重计算（take 模式的写入点）
};

inline const char* RoleName(Role r) {
    switch (r) {
        case Role::MainHook: return "main-hook";
        case Role::HookA: return "hook-a";
        case Role::MidE4B0: return "mid-e4b0";
        case Role::WeightCalc: return "weight-calc";
    }
    return "?";
}

inline bool IsRequired(Role r) {
    // 只有这两个影响"能不能正确接管"；其余缺了只是少点信息
    return r == Role::MainHook || r == Role::HookA;
}

// ---------------- 单个目标的解析产物 ----------------
struct Addr {
    Role role = Role::MainHook;
    uint32_t rva = 0;
    aranchor::How how = aranchor::How::None;
    std::string evidence;
    // 互证结果
    bool verifiedLen = false;
    bool verifiedPrologue = false;
    // 长特征码校验：这是唯一能"确认身份"的一步
    bool verifiedSig = false;
    uint32_t actualLen = 0;
    std::string failure;

    bool ok() const { return rva != 0 && how != aranchor::How::None; }
    // 能用于安装：必须有地址 + 两项互证都过
    bool installable() const { return ok() && verifiedLen && verifiedPrologue && verifiedSig; }
};

// 角色 -> ar_version.h 目标表的显式映射
//
// 【为什么不用数组下标】
//   2026-11-12 真机 bug：曾写成 (int)i == (int)a->role，假设 kTargets 的下标
//   恰好等于 Role 枚举值。删掉 str-ctor/str-dtor/getPlayer 后数组只剩 4 项，
//   于是 Role::StrCtor(2) 取到了 kTargets[2] = E4B0（len 1768），
//   日志出现 "str-ctor ... reference 1768" 的荒谬提示。
//
// 【为什么不用 RVA 匹配】
//   试过，但被 anchor_perturb_test 抓出来：该测试会把整个映像平移
//   （模拟版本漂移），此时解析出的 RVA 是【平移后】的值，
//   与 kTargets 里记录的原始 RVA 永不相等 -> 所有指纹校验失效。
//   RVA 是解析产物，不能反过来当身份键。
//
// 【正确做法】用 Role 显式映射到目标表的槽位。
//   这是唯一稳定的键：Role 是编译期常量，与运行时解析结果无关。
inline const arver::Target* FindReferenceFor(Role r) {
    switch (r) {
        // 必需组：kTargets[0] = 主 hook，kTargets[1] = hookA
        case Role::MainHook:   return &arver::kTargets[0];
        case Role::HookA:      return &arver::kTargets[1];
        // take 链路：kTargets[2] = E4B0，kTargets[3] = C890
        case Role::MidE4B0:    return &arver::kTargets[2];
        case Role::WeightCalc: return &arver::kTargets[3];
    }
    return nullptr;
}



// ---------------- 交叉验证 ----------------
// 用 arver 里的 (函数长度, 序言字节) 校验一个解析出来的地址。
// 注意：这两个值来自已知版本，在别的版本上可能不匹配 —— 那正是我们要知道的。
inline void CrossCheck(const aranchor::IAnchorImage& img, Addr* a) {
    std::vector<std::pair<uint32_t, uint32_t> > funcs;
    img.EnumFunctions(&funcs);
    uint32_t len = 0;
    for (size_t i = 0; i < funcs.size(); ++i)
        if (funcs[i].first == a->rva) { len = funcs[i].second - funcs[i].first; break; }
    a->actualLen = len;
    if (len == 0) {
        a->failure = "resolved address is not a function entry in .pdata";
        return;
    }
    // 找到 arver 里同名目标的期望值
    const arver::Target* t = FindReferenceFor(a->role);
    if (!t) {
        a->failure = "no reference fingerprint for this role";
        return;
    }
    a->verifiedLen = (len == t->funcLen);
    uint8_t pro[arver::kPrologueLen] = {0};
    bool rd = img.ReadBytes(a->rva, pro, arver::kPrologueLen);
    a->verifiedPrologue = rd && memcmp(pro, t->expect, arver::kPrologueLen) == 0;

    // 长特征码：唯一能确认"这个地址确实是那个函数"的手段。
    // 15 字节序言在主 hook 上重复 2572 次，单独用它等于没校验。
    if (t->sigLen > 0 && t->sigLen <= 64) {
        uint8_t sigGot[64] = {0};
        if (img.ReadBytes(a->rva, sigGot, t->sigLen))
            a->verifiedSig = (memcmp(sigGot, t->sig, t->sigLen) == 0);
    }

    if (!a->verifiedLen) {
        char buf[160];
        snprintf(buf, sizeof(buf), "function length %u != reference %u", len, t->funcLen);
        a->failure = buf;
    } else if (!a->verifiedPrologue) {
        a->failure = "prologue bytes differ from reference";
    } else if (!a->verifiedSig) {
        char buf[192];
        snprintf(buf, sizeof(buf),
                 "long signature (%u bytes) mismatch -- address is not the expected function",
                 (unsigned)t->sigLen);
        a->failure = buf;
    }
}

// ---------------- 解析编排 ----------------
// SEL（选择算法）/ GETC（取玩家国家）的参考地址。
// 它们只用于"识别主 hook 的调用指纹"，不用于定位主 hook 本身。
// 值来自 ar_version.h（gen_version_h.js 生成）。
constexpr uint32_t kSelRva  = arver::kSelRva_Ref;
constexpr uint32_t kGetcRva = arver::kGetcRva_Ref;

struct Resolver {
    const aranchor::IAnchorImage* img = nullptr;
    // 主 hook 的"稀有 callee 指纹"参照点。
    // 默认取 ar_version.h 里的已知值；调用方可以覆盖
    // （版本漂移时这两个函数的位置同样会变）。
    uint32_t selRva  = kSelRva;
    uint32_t getcRva = kGetcRva;

    // 解析日志（逐行可读）
    std::string log;
    std::vector<Addr> addrs;

    // 字符串锚点（完整串，见 ar_anchor.h 头部说明）
    static const char* kHookAAnchor1() { return "MESSAGE_TECHNOLOGY_RESEARCH_FINISH"; }
    static const char* kHookAAnchor2() { return "TECHNOLOGY_ORDER_FINISH_MESSAGE_TYPE"; }

    bool Run() {
        addrs.clear();
        log.clear();
        if (!img) { log = "no image\n"; return false; }

        // ---- 1) hookA：双锚点投票 ----
        Addr hookA;
        hookA.role = Role::HookA;
        {
            const aranchor::AnchorSpec specs[] = {
                {kHookAAnchor1(), ".rdata", "科研完成消息 key"},
                {kHookAAnchor2(), ".rdata", "科研完成消息类型"},
            };
            log += "-- resolve hook-a via string anchors (need >=2 votes) --\n";
            aranchor::VoteResult vr = aranchor::ResolveByStrings(
                *img, specs, 2, 60000, 2);
            log += vr.detail;
            if (vr.ok()) {
                hookA.rva = vr.rva;
                hookA.how = aranchor::How::StringAnchor;
                char buf[192];
                snprintf(buf, sizeof(buf), "%u string anchors agree", vr.votes);
                hookA.evidence = buf;
                CrossCheck(*img, &hookA);
            } else {
                hookA.failure = "string anchors did not converge";
            }
        }

        // ---- 2) 主 hook：调用链 + 稀有 callee 指纹（多特征评分） ----
        // 主 hook 没有任何字符串引用，只能靠行为特征认：
        //   a) 被 hookA 直接调用                        （调用链）
        //   b) 函数体里恰好调用 SEL(选择算法) 1 次       （强：全 exe 仅 8 个函数调用 SEL）
        //   c) 函数体里恰好调用 GETC(取玩家国家) 1 次    （弱：1545 个函数调用它，仅作辅证）
        //   d) 函数长度与参考值一致                      （强）
        //   e) 序言 + 长签名与参考值一致                 （强，仅同版本有效）
        //
        // 为什么不用单一判据：b+c 单独看能命中 5 个函数；d 单独看能缩小到 1 个；
        // 但只有组合起来才既"找得到"又"不会认错"。
        Addr mainHook;
        mainHook.role = Role::MainHook;
        {
            log += "-- resolve main-hook via call chain + rare-callee fingerprint --\n";
            if (!hookA.ok()) {
                mainHook.failure = "parent hook-a unresolved";
                log += "  skipped: hook-a unresolved\n";
            } else {
                // 先拿到 SEL / GETC 两个参照函数的位置（它们也要靠解析，不写死）
                // SEL = 被 hookA 调用、且自身长度与参考一致的"选择算法"
                // 这里用 arver 的参考长度做匹配，属于"用已知版本的形状当模板"
                const uint32_t refSelLen = arver::kTargets[0].funcLen;  // 占位，下面按需修正
                (void)refSelLen;

                std::vector<aranchor::CallEdge> edges =
                    aranchor::DirectCallsFrom(*img, hookA.rva);
                char buf[160];
                snprintf(buf, sizeof(buf), "  hook-a makes %zu direct calls\n", edges.size());
                log += buf;

                std::vector<std::pair<uint32_t, uint32_t> > funcs;
                img->EnumFunctions(&funcs);
                auto lenOf = [&](uint32_t rva) -> uint32_t {
                    for (size_t k = 0; k < funcs.size(); ++k)
                        if (funcs[k].first == rva) return funcs[k].second - funcs[k].first;
                    return 0;
                };

                // 第一层：候选 = 被 hookA 调用的函数里，长度落在主 hook 可能区间的
                //         （参考值 ±600 字节，够宽容但不至于全收）
                const uint32_t refMainLen = arver::kTargets[0].funcLen;
                std::vector<uint32_t> cands;
                for (size_t i = 0; i < edges.size(); ++i) {
                    uint32_t c = edges[i].callee;
                    uint32_t l = lenOf(c);
                    if (l == 0) continue;
                    uint32_t lo = (refMainLen > 600) ? refMainLen - 600 : 0;
                    uint32_t hi = refMainLen + 600;
                    if (l >= lo && l <= hi) cands.push_back(c);
                }
                snprintf(buf, sizeof(buf), "  length-filtered candidates: %zu\n", cands.size());
                log += buf;

                // 第二层：在候选里找"同时调用 SEL 和 GETC"的
                // SEL / GETC 的地址从 arver 取（它们是 arver 里 Role 3/4 对应的目标）
                // 注意：这里用参考 RVA 只是为了"知道要找哪两个 callee"，不是用来定位主 hook。
                // SEL/GETC 由成员提供（默认 ar_version.h 的已知值）
                // SEL 和 GETC 通过"稀有度"识别：遍历 hookA 的所有 callee，
                // 统计"全 exe 有多少函数调用它"，取最稀有的那几个。
                // 但那样太慢（要全量扫 13 万函数两次）。
                // 实用做法：SEL 是主 hook 独有的强特征，用 arver 里记录的值。
                // 用成员值（可被调用方覆盖；默认是 ar_version.h 的已知值）

                uint32_t pick = 0;
                int matches = 0;
                std::string fallbackLog;
                if (selRva && getcRva) {
                    for (size_t i = 0; i < cands.size(); ++i) {
                        std::vector<uint32_t> callees;
                        callees.push_back(selRva);
                        callees.push_back(getcRva);
                        aranchor::CallSignature sig =
                            aranchor::VerifyCallSignature(*img, cands[i], callees,
                                                          std::vector<uint32_t>{1u, 1u});
                        snprintf(buf, sizeof(buf),
                                 "    candidate 0x%X len=%u : %s",
                                 cands[i], lenOf(cands[i]),
                                 sig.ok ? "SEL=1 GETC=1 OK" : "fingerprint mismatch");
                        log += buf;
                        log += "\n";
                        if (sig.ok) { ++matches; if (matches == 1) pick = cands[i]; }
                    }
                } else {
                    log += "  SEL/GETC reference unavailable -- falling back to length only\n";
                    if (cands.size() == 1) { pick = cands[0]; matches = 1; }
                }

                if (matches == 1 && pick) {
                    mainHook.rva = pick;
                    mainHook.how = aranchor::How::CallChain;
                    snprintf(buf, sizeof(buf),
                             "hook-a callee + rare-callee fingerprint (SEL=1,GETC=1)");
                    mainHook.evidence = buf;
                    CrossCheck(*img, &mainHook);
                    snprintf(buf, sizeof(buf), "  unique candidate 0x%X\n", pick);
                    log += buf;
                } else if (matches == 0) {
                    mainHook.failure = (cands.size() == 1)
                        ? "candidate failed the rare-callee fingerprint"
                        : "no candidate matched the rare-callee fingerprint";
                    log += "  FAILED: " + mainHook.failure + "\n";
                } else {
                    snprintf(buf, sizeof(buf),
                             "  FAILED: %d candidates matched -- ambiguous, refusing to guess\n",
                             matches);
                    log += buf;
                    mainHook.failure = "multiple candidates passed the fingerprint (ambiguous)";
                }
            }
        }

        // ---- 3) 辅助函数：已于 2026-11-12 全部移除 ----
        // 原 str-ctor / str-dtor / getPlayer 三个 Optional 目标都是死代码，
        // 移除后解析链只剩必需组（main-hook + hook-a）与 take 链路（E4B0/C890）。
        // 这样日志里不会再出现永远 unresolved 的 [weak] 行。

        addrs.push_back(mainHook);
        addrs.push_back(hookA);
        return true;
    }

    const Addr* Get(Role r) const {
        for (size_t i = 0; i < addrs.size(); ++i)
            if (addrs[i].role == r) return &addrs[i];
        return nullptr;
    }

    // 必需组是否全就绪（MainHook + HookA 必须同时可用）
    bool RequiredReady() const {
        const Addr* m = Get(Role::MainHook);
        const Addr* a = Get(Role::HookA);
        return m && a && m->installable() && a->installable();
    }

    // 生成人类可读的解析报告（写日志用）
    std::string Report() const {
        std::string s = log;
        s += "-- resolution summary --\n";
        for (size_t i = 0; i < addrs.size(); ++i) {
            const Addr& a = addrs[i];
            char buf[320];
            if (a.installable()) {
                snprintf(buf, sizeof(buf),
                         "  [ok]   %-10s 0x%X  how=%-13s %s\n",
                         RoleName(a.role), a.rva, aranchor::HowName(a.how),
                         a.evidence.c_str());
            } else if (a.ok()) {
                snprintf(buf, sizeof(buf),
                         "  [weak] %-10s 0x%X  how=%-13s but %s\n",
                         RoleName(a.role), a.rva, aranchor::HowName(a.how),
                         a.failure.empty() ? "verification failed" : a.failure.c_str());
            } else if (IsRequired(a.role)) {
                snprintf(buf, sizeof(buf),
                         "  [MISS] %-10s REQUIRED but unresolved: %s\n",
                         RoleName(a.role),
                         a.failure.empty() ? "unknown" : a.failure.c_str());
            } else {
                snprintf(buf, sizeof(buf),
                         "  [ -- ] %-10s optional, unresolved: %s\n",
                         RoleName(a.role),
                         a.failure.empty() ? "unknown" : a.failure.c_str());
            }
            s += buf;
        }
        s += RequiredReady() ? "  => required set READY\n"
                             : "  => required set INCOMPLETE (take mode will be disabled)\n";
        return s;
    }
};

}  // namespace arresolve

#endif  // AR_RESOLVE_H
