// ar_gate.h —— 版本闸门：决定"这份 DLL 敢不敢在这个游戏进程里装 hook"
//
// 为什么要单独一个头文件：
//   发布到 GitHub 后，用户版本不对 / 装了别的 mod / 官方打了 patch，
//   硬编码的 RVA 就会指向错误的函数。轻则功能失效，重则崩游戏。
//   闸门的职责就是：**不确定就一个 hook 都不装**。宁可功能失效，
//   绝不让别人的游戏崩。
//
// 设计要点（与 captain 商定）：
//   1. 全量检查后才统一安装 —— 禁止半挂
//   2. 检查分三层，任何一层不过就整份拒绝：
//        a) 版本锚：SHA256 精确匹配 → Trusted
//                  SHA256 不符但内嵌 buildId 匹配 → Unverified（仍放行，但日志标注）
//                  都不匹配 → 拒绝
//        b) 地址合法性：目标 RVA 必须落在映像范围内、且是可读可执行段
//        c) 函数指纹：.pdata 认为它是函数入口 + 函数长度符合 + 序言字节符合
//   3. 序言字节【单独不足以证明身份】—— 实测 0x425550 的 15 字节序言在
//      .text 里重复 1000 次。所以序言只作为"没被别的 mod 改过"的健全性检查，
//      真正的身份由 (RVA 是函数入口 + 函数长度) 锚定，版本由 SHA256/buildId 锚定。
//
// 这个头文件不依赖 windows.h：内存访问通过一个抽象接口注入，
// 因此可以在控制台程序里用"假映像"完整测试所有拒绝路径。
#pragma once
#ifndef AR_GATE_H
#define AR_GATE_H

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <vector>

#include "ar_version.h"

namespace argate {

// ---------------- 状态 ----------------
// 导出给网页/脚本查询用，顺序有意义：数值越大越"接近可用"
enum class State : int {
    NotChecked     = 0,   // 还没跑过检查（DLL 刚加载）
    VersionRejected = 1,  // 版本锚对不上 → 完全不装
    AddressRejected = 2,  // 地址不在合法段/不可执行 → 完全不装
    FingerprintRejected = 3,  // 函数指纹对不上（版本对但代码被改过？） → 完全不装
    InstallFailed  = 4,   // 检查全过但写入失败，已回滚 → 不装
    Unverified     = 5,   // 装了，但版本锚不是精确 SHA256（buildId 匹配）
    FullyInstalled = 6,   // 装了，SHA256 精确匹配
};

inline const char* StateName(State s) {
    switch (s) {
        case State::NotChecked:          return "not-checked";
        case State::VersionRejected:     return "version-rejected";
        case State::AddressRejected:     return "address-rejected";
        case State::FingerprintRejected: return "fingerprint-rejected";
        case State::InstallFailed:       return "install-failed";
        case State::Unverified:          return "unverified";
        case State::FullyInstalled:      return "fully-installed";
    }
    return "?";
}

// 是否真的装上了（只有这两个状态算"可用"）
inline bool IsUsable(State s) {
    return s == State::Unverified || s == State::FullyInstalled;
}

// 版本锚的判定结果（与"装没装上"分开，便于日志区分排查方向）
enum class Anchor {
    None = 0,        // 两项都不匹配
    BuildIdOnly = 1, // SHA256 不符，但内嵌 buildId 匹配（可能是合法 patch）
    Sha256Exact = 2, // 完全匹配
};

inline const char* AnchorName(Anchor a) {
    switch (a) {
        case Anchor::None:        return "none";
        case Anchor::BuildIdOnly: return "build-id-only";
        case Anchor::Sha256Exact: return "sha256-exact";
    }
    return "?";
}

// ---------------- 映像抽象 ----------------
// 让闸门逻辑与真实进程解耦：测试里给假映像，DLL 里给真进程。
class IImage {
public:
    virtual ~IImage() {}
    // 模块文件名（写日志用）
    virtual const char* Name() const = 0;
    // 映像基址（= PE ImageBase，运行时实际加载地址）
    virtual uint64_t Base() const = 0;
    // 映像大小（PE SizeOfImage）
    virtual uint64_t Size() const = 0;
    // 该 RVA 是否落在可执行且可读的段里
    virtual bool IsExecutable(uint32_t rva) const = 0;
    // 读取虚拟地址处的字节；返回 false 表示不可读
    virtual bool ReadBytes(uint32_t rva, void* dst, size_t n) const = 0;
    // 该 RVA 是否为函数入口；是则输出函数长度（来自 .pdata）
    virtual bool IsFunctionStart(uint32_t rva, uint32_t* funcLen) const = 0;
    // 计算整份文件 SHA256（小写十六进制）；失败返回空串
    virtual std::string Sha256() const = 0;
    // 在映像里找内嵌版本串（形如 "Cygnus v4.5.2  32709cf... (Oct  1 2026 ...)"）
    // 返回完整的 buildId（32 位十六进制），找不到返回空串
    virtual std::string EmbeddedBuildId() const = 0;
};

// ---------------- 单项检查结果 ----------------
struct TargetCheck {
    uint32_t rva = 0;
    const char* fnName = "";
    bool addressOk = false;
    bool pdataOk = false;
    bool prologueOk = false;
    // 长特征码校验（唯一的身份确认手段）
    bool sigOk = false;
    uint32_t sigLen = 0;
    bool required = true;   // Diagnostic 目标为 false：失败不阻止安装
    uint32_t actualFuncLen = 0;
    uint32_t expectFuncLen = 0;
    uint32_t actualPrologueDup = 0;
    uint8_t actualPrologue[arver::kPrologueLen] = {0};
    std::string detail;   // 人类可读的失败原因

    bool Ok() const { return addressOk && pdataOk && prologueOk && sigOk; }
};

struct Report {
    Anchor anchor = Anchor::None;
    State state = State::NotChecked;
    std::string imageName;
    std::string actualSha256;
    std::string actualBuildId;
    std::vector<TargetCheck> targets;
    std::vector<std::string> errors;   // 每条都是一个可直接写进日志的句子

    // 供日志使用：把整个报告压成多行
    std::string Summary() const {
        std::string s;
        s += "state=";
        s += StateName(state);
        s += " anchor=";
        s += AnchorName(anchor);
        s += " image=";
        s += imageName;
        s += "\n";
        s += "  expected sha256: ";
        s += arver::kSupportedSha256;
        s += "\n";
        s += "  actual   sha256: ";
        s += actualSha256.empty() ? "<unavailable>" : actualSha256;
        s += "\n";
        s += "  expected build : ";
        s += arver::kSupportedBuildId;
        s += " (";
        s += arver::kSupportedVersionTag;
        s += ")\n";
        s += "  actual   build : ";
        s += actualBuildId.empty() ? "<not found>" : actualBuildId;
        s += "\n";
        for (size_t i = 0; i < targets.size(); ++i) {
            const TargetCheck& t = targets[i];
            s += "  ";
            s += (t.Ok() ? "[ok]   " : "[FAIL] ");
            s += t.fnName;
            s += " rva=0x";
            s += Hex(t.rva);
            if (!t.Ok()) {
                s += "  -> ";
                s += t.detail;
            }
            s += "\n";
        }
        for (size_t i = 0; i < errors.size(); ++i) {
            s += "  ! ";
            s += errors[i];
            s += "\n";
        }
        return s;
    }

    static std::string Hex(uint64_t v) {
        static const char* d = "0123456789ABCDEF";
        char buf[17];
        buf[16] = 0;
        for (int i = 15; i >= 0; --i) {
            buf[i] = d[v & 0xF];
            v >>= 4;
        }
        return std::string(buf + (v ? 0 : 0));
    }

    static std::string HexBytes(const uint8_t* p, size_t n) {
        static const char* d = "0123456789ABCDEF";
        std::string s;
        s.reserve(n * 3);
        for (size_t i = 0; i < n; ++i) {
            if (i) s += ' ';
            s += d[p[i] >> 4];
            s += d[p[i] & 0xF];
        }
        return s;
    }
};

// 把十六进制串转小写（SHA256 比较时统一用）
inline std::string ToLower(const std::string& s) {
    std::string r = s;
    for (size_t i = 0; i < r.size(); ++i) {
        char c = r[i];
        if (c >= 'A' && c <= 'F') r[i] = (char)(c - 'A' + 'a');
    }
    return r;
}

// ---------------- 闸门主体 ----------------
// 只做检查，不做任何内存改写 —— 安装由调用方在拿到 Ok() 的结果后执行。
// 这样"检查"和"安装"能分开测，也让回滚逻辑只出现在安装侧。
inline Report Inspect(const IImage& img) {
    Report rep;
    rep.imageName = img.Name() ? img.Name() : "<unknown>";

    // ---- a) 版本锚 ----
    rep.actualSha256 = ToLower(img.Sha256());
    rep.actualBuildId = ToLower(img.EmbeddedBuildId());

    const std::string wantSha = ToLower(arver::kSupportedSha256);
    const std::string wantBuild = ToLower(arver::kSupportedBuildId);

    if (!rep.actualSha256.empty() && rep.actualSha256 == wantSha) {
        rep.anchor = Anchor::Sha256Exact;
    } else if (!rep.actualBuildId.empty() && rep.actualBuildId == wantBuild) {
        rep.anchor = Anchor::BuildIdOnly;
    } else {
        rep.anchor = Anchor::None;
        rep.state = State::VersionRejected;
        if (rep.actualSha256.empty()) {
            rep.errors.push_back("VERSION: cannot hash the game executable (file locked or unreadable).");
        } else if (rep.actualSha256 != wantSha) {
            rep.errors.push_back(
                "VERSION: sha256 mismatch -- this DLL was built for " +
                std::string(arver::kSupportedVersionTag) + " (build " +
                std::string(arver::kSupportedBuildId) + ").");
            rep.errors.push_back(
                "VERSION: your game reports buildId='" +
                (rep.actualBuildId.empty() ? "<not found>" : rep.actualBuildId) +
                "'. Refusing to install ANY hook (your game will NOT be modified).");
        } else {
            rep.errors.push_back("VERSION: build id mismatch.");
        }
        // 版本就不过，后续检查没有意义 —— 直接返回，日志更干净
        return rep;
    }

    // ---- b)+c) 逐个目标检查 ----
    bool anyFail = false;
    for (size_t i = 0; i < arver::kTargetCount; ++i) {
        const arver::Target& want = arver::kTargets[i];
        TargetCheck tc;
        tc.rva = want.rva;
        tc.fnName = want.fnName;
        tc.expectFuncLen = want.funcLen;
        tc.required = (want.kind != arver::TargetKind::Diagnostic);
        // Diagnostic 目标只用于只读诊断：校验失败只记日志，不影响安装决策
        const bool isRequired = tc.required;

        // b) 地址在可执行段内
        if (want.rva >= img.Size() || !img.IsExecutable(want.rva)) {
            tc.detail = "address is not inside an executable section of the game image";
            rep.targets.push_back(tc);
            if (isRequired) anyFail = true;
            continue;
        }
        tc.addressOk = true;

        // c1) .pdata 认为它是函数入口，且长度吻合
        uint32_t actualLen = 0;
        if (!img.IsFunctionStart(want.rva, &actualLen)) {
            tc.detail = "not a function entry point according to .pdata "
                        "(RVA drifted -- wrong game build?)";
            rep.targets.push_back(tc);
            if (isRequired) anyFail = true;
            continue;
        }
        tc.actualFuncLen = actualLen;
        if (actualLen != want.funcLen) {
            char buf[192];
            snprintf(buf, sizeof(buf),
                     "function length is %u bytes, expected %u "
                     "(wrong game build, or another mod patched this function)",
                     actualLen, want.funcLen);
            tc.detail = buf;
            rep.targets.push_back(tc);
            if (isRequired) anyFail = true;
            continue;
        }
        tc.pdataOk = true;

        // c2) 序言字节吻合（防别的 mod 已经改过这段）
        uint8_t got[arver::kPrologueLen] = {0};
        if (!img.ReadBytes(want.rva, got, arver::kPrologueLen)) {
            tc.detail = "cannot read function prologue from game memory";
            rep.targets.push_back(tc);
            if (isRequired) anyFail = true;
            continue;
        }
        memcpy(tc.actualPrologue, got, arver::kPrologueLen);
        if (memcmp(got, want.expect, arver::kPrologueLen) != 0) {
            tc.detail = "prologue bytes differ -- expected [" +
                        Report::HexBytes(want.expect, arver::kPrologueLen) +
                        "] got [" + Report::HexBytes(got, arver::kPrologueLen) + "]";
            rep.targets.push_back(tc);
            if (isRequired) anyFail = true;
            continue;
        }
        tc.prologueOk = true;

        // c3) 长特征码校验 —— 这是唯一能"确认身份"的一步。
        //     15 字节序言在 .text 里重复上千次，只能证明"地址处长得像"；
        //     长签名（24..56B，取到唯一所需长度）才能证明"就是它"。
        //     注意签名只做【校验】不做【定位】：版本漂移后 .text 会重排，
        //     拿长签名去全盘搜必然失效，但用来确认"解出来的地址对不对"很可靠。
        tc.sigLen = want.sigLen;
        if (want.sigLen == 0 || want.sigLen > 64) {
            tc.detail = "no long signature available for this target";
            rep.targets.push_back(tc);
            if (isRequired) anyFail = true;
            continue;
        }
        {
            uint8_t sigGot[64] = {0};
            if (!img.ReadBytes(want.rva, sigGot, want.sigLen)) {
                tc.detail = "cannot read signature bytes from game memory";
                rep.targets.push_back(tc);
                if (isRequired) anyFail = true;
                continue;
            }
            if (memcmp(sigGot, want.sig, want.sigLen) != 0) {
                tc.detail = "long signature mismatch (" + std::to_string(want.sigLen) +
                            " bytes) -- the code at this address is NOT the function this "
                            "DLL was built against";
                rep.targets.push_back(tc);
                if (isRequired) anyFail = true;
                continue;
            }
            tc.sigOk = true;
        }
        rep.targets.push_back(tc);
    }

    // 统计诊断目标失败数（它们不影响安装，但要记日志）
    size_t diagFailed = 0;
    for (size_t i = 0; i < rep.targets.size(); ++i)
        if (!rep.targets[i].required && !rep.targets[i].Ok()) ++diagFailed;

    if (anyFail) {
        // 区分两种失败：地址/pdata 不符 = 版本漂移；仅序言不符 = 被别人改过
        bool structuralFail = false;
        bool requiredFailed = false;
        for (size_t i = 0; i < rep.targets.size(); ++i) {
            const TargetCheck& t2 = rep.targets[i];
            if (t2.Ok()) continue;
            if (!t2.required) continue;          // 诊断目标失败不计入
            requiredFailed = true;
            if (!t2.addressOk || !t2.pdataOk) structuralFail = true;
        }
        if (!requiredFailed) {
            // 只有诊断目标失败 -> 安装照常，但记一条日志
            rep.state = (rep.anchor == Anchor::Sha256Exact) ? State::FullyInstalled
                                                            : State::Unverified;
            rep.errors.push_back("NOTE: one or more DIAGNOSTIC targets failed verification. "
                                 "This does NOT affect hook installation (they are read-only).");
            return rep;
        }
        rep.state = structuralFail ? State::AddressRejected
                                   : State::FingerprintRejected;
        rep.errors.push_back(
            structuralFail
                ? "FINGERPRINT: one or more target addresses do not match this game build. "
                  "Refusing to install ANY hook."
                : "FINGERPRINT: the target functions look like a different build, or another "
                  "mod has already patched them. Refusing to install ANY hook.");
        return rep;
    }

    rep.state = (rep.anchor == Anchor::Sha256Exact) ? State::FullyInstalled
                                                    : State::Unverified;
    if (diagFailed > 0) {
        char b[192];
        snprintf(b, sizeof(b),
                 "NOTE: %zu DIAGNOSTIC target(s) failed verification. This does NOT affect "
                 "hook installation (they are read-only, used for take-mode probing).",
                 diagFailed);
        rep.errors.push_back(b);
    }
    if (rep.anchor == Anchor::BuildIdOnly) {
        rep.errors.push_back(
            "NOTE: sha256 differs from the known-good build, but the embedded build id matches. "
            "Proceeding as UNVERIFIED -- if the game misbehaves, delete the DLL and report it.");
    }
    return rep;
}

// =====================================================================
// 安装计划：把"要改哪几个字节、原始值是什么"算出来，便于原子化安装 + 回滚
// =====================================================================
struct Patch {
    uint32_t rva;
    const char* fnName;
    uint8_t  original[arver::kPatchLen];   // 原始 15 字节（回滚用）
    uint8_t  patched[arver::kPatchLen];    // 要写入的 15 字节
};

// 生成"写 jmp 到 target 地址"的 15 字节补丁
//   48 B8 <imm64> FF E0 90 90 90   = mov rax, imm64 ; jmp rax ; nop*3
inline void MakeAbsJmp(uint8_t out[arver::kPatchLen], uint64_t dest) {
    out[0] = 0x48;
    out[1] = 0xB8;
    memcpy(out + 2, &dest, 8);
    out[10] = 0xFF;
    out[11] = 0xE0;
    out[12] = 0x90;
    out[13] = 0x90;
    out[14] = 0x90;
}

// 从检查通过的 Report 生成补丁计划（只含 kind==Hook 的目标）
//   hookAddr: 每个 hook 目标要跳到的宿主函数地址（由调用方给出）
inline std::vector<Patch> BuildPlan(const Report& rep, const IImage& /*img*/,
                                    const uint64_t* hookAddrs, size_t hookAddrCount) {
    std::vector<Patch> plan;
    if (!IsUsable(rep.state)) return plan;
    size_t hi = 0;
    for (size_t i = 0; i < arver::kTargetCount; ++i) {
        const arver::Target& want = arver::kTargets[i];
        if (want.kind != arver::TargetKind::Hook) continue;
        if (hi >= hookAddrCount) break;
        // 找对应检查结果
        const TargetCheck* tc = nullptr;
        for (size_t k = 0; k < rep.targets.size(); ++k)
            if (rep.targets[k].rva == want.rva) { tc = &rep.targets[k]; break; }
        if (!tc || !tc->Ok()) { ++hi; continue; }

        Patch p;
        p.rva = want.rva;
        p.fnName = want.fnName;
        memcpy(p.original, tc->actualPrologue, arver::kPatchLen);
        MakeAbsJmp(p.patched, hookAddrs[hi]);
        plan.push_back(p);
        ++hi;
    }
    return plan;
}

}  // namespace argate

#endif  // AR_GATE_H

// =====================================================================
// 解析结果闸门：把 ar_resolve 的解析产物纳入同一条"能不能装"的判定链
// =====================================================================
//
// 为什么单独一段而不是复用 Inspect()：
//   Inspect() 是"按 ar_version.h 里写死的 RVA 去看"，只对**已知构建**有意义。
//   锚点解析是"从二进制内容里认出函数"，它可能在一个**未知构建**上也成功。
//   这两件事的可信度不同，必须分开表达，否则日志会误导排查方向。
//
// 判定规则：
//   - 解析出的地址 + 与参考指纹(函数长度/序言)完全一致  → 可装（strong）
//   - 解析出的地址 + 指纹不一致                        → **不可装**
//     理由：hook 会改写序言、还依赖调用约定/栈布局。指纹对不上就说明
//     这个构建的函数体变了，改写它是拿用户的游戏冒险。正确做法是
//     用 gen_version_h.js 为这个新版本重新生成指纹，重新编译。
//   - 解析不出来，但 SHA256 精确匹配已知构建            → 可装（hash 兜底）
//   - 都不成立                                        → 拒绝
namespace argate {

enum class ResolveVerdict {
    None = 0,
    AnchorVerified = 1,   // 锚点解析 + 指纹互证都过
    AnchorUnverified = 2, // 锚点解析成功但指纹不符（已知构建之外）
    HashFallback = 3,     // 锚点失败，靠 SHA256 精确匹配定位
    Failed = 4,
};

inline const char* ResolveVerdictName(ResolveVerdict v) {
    switch (v) {
        case ResolveVerdict::None: return "none";
        case ResolveVerdict::AnchorVerified: return "anchor-verified";
        case ResolveVerdict::AnchorUnverified: return "anchor-unverified";
        case ResolveVerdict::HashFallback: return "hash-fallback";
        case ResolveVerdict::Failed: return "failed";
    }
    return "?";
}

inline bool VerdictInstallable(ResolveVerdict v) {
    return v == ResolveVerdict::AnchorVerified || v == ResolveVerdict::HashFallback;
}

}  // namespace argate
