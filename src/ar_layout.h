// ar_layout.h —— L1 结构偏移自动推导（候选卡组）
//
// ================== 为什么需要它 ==================
// 之前 country+0x31B0 / +0x31BC / +0x31D8 是**写死**的常量。
// 游戏一升级（4.5.2 -> 4.5.4），这些偏移变了就全废。
//
// 本文件的目标：从 C890（权重计算函数）的**指令字节**里把偏移读出来，
// 代码里【不出现任何 0x31B0/0x31BC 字面量】。
//
// ================== 强制的四项验收标准 ==================
//   1. 双版本正确读出且值相同
//   2. 对抗测试：把 disp 改掉后必须读出【改后的新值】
//      —— 这是区分「真推导」与「伪装查表」的唯一可靠手段
//   3. 唯一解：消歧后只剩 1 个候选；多解返回 nullopt，不挑第一个
//   4. 失败明确：找不到 -> nullopt，不猜
//
// 未通过 1/2 -> 推导器不可信，禁止合入
// 未通过 3/4 -> 当前版本不可用，运行时 nullopt 降级
//
// ================== 形状 ==================
//   ① MOV r32, [base + dc]      读 32 位 count
//   ② TEST r32, r32             判空守卫
//   ③ Jcc <skip>                条件跳转
//   ④ MOV r64, [base + da]      读 64 位 array（同一 base）
//   ⑤ [arr + idx*4]             元素 4 字节
//   ⑥ 消歧 A：首次访问 array 元素是 CMP（比较语义），不是纯 MOV
//   ⑦ 消歧 B：count 在函数内使用频次最高者胜出
//
// 实测：单用 A 剩 2 个，加 B 才收敛到 1 个，缺一不可。
#pragma once
#ifndef AR_LAYOUT_H
#define AR_LAYOUT_H

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <optional>
#include <algorithm>

#include "ar_lde.h"

namespace arlayout {

// ---------------- 候选卡布局 ----------------
struct CardLayout {
    uint32_t countOff = 0;   // country + countOff -> int32 count
    uint32_t arrayOff = 0;   // country + arrayOff -> ptr to int32[]
    uint32_t elemSize = 0;   // 元素字节数
};

// ---------------- 诊断信息 ----------------
// 失败时调用方要把这些打进日志，否则"为什么没推出来"无从排查。
struct Diag {
    std::vector<std::string> lines;
    int rawCandidates = 0;       // 形状初筛后的候选数
    int afterCompare = 0;        // 消歧 A（比较语义）之后
    int afterFrequency = 0;      // 消歧 B（使用频次）之后
    void add(const std::string& s) { lines.push_back(s); }
};

// ---------------- 解码结果 ----------------
struct DecodedFn {
    uint32_t rva = 0;
    std::vector<arlde::Insn> insns;
    std::vector<size_t> offs;    // 每条指令在函数体内的字节偏移
    bool complete = false;       // 是否完整解码到函数末尾
};

// 从函数体线性解码。fail-closed：任何一条解不了就整体放弃。
inline DecodedFn DecodeFunction(const uint8_t* code, size_t len, uint32_t rva) {
    DecodedFn d;
    d.rva = rva;
    size_t off = 0;
    while (off < len) {
        arlde::Insn in = arlde::Decode(code + off, len - off);
        if (!in.ok || in.length == 0 || off + in.length > len) {
            d.complete = false;
            return d;   // 解不了就不给半截结果
        }
        d.insns.push_back(in);
        d.offs.push_back(off);
        off += in.length;
    }
    d.complete = (off == len);
    return d;
}

// ---------------- 指令语义小工具 ----------------
// 取指令的 ModRM 基址寄存器编号（含 REX.B 扩展），mod==3 时返回 false
inline bool MemBase(const arlde::Insn& in, int* base) {
    if (!in.hasModRm || in.modrmMod == 3) return false;
    int b = in.modrmRm;
    if (in.hasSib) b = in.sibBase;
    if (in.rex & 0x01) b |= 8;          // REX.B
    *base = b;
    return true;
}

// 该指令是否「写 rsp/rbp 基址」（栈帧，不是对象）
inline bool IsStackBase(const arlde::Insn& in) {
    int b = 0;
    if (!MemBase(in, &b)) return false;
    return b == 4 || b == 5;            // rsp=4 / rbp=5（x64 编码）
}

// 目的寄存器编号（含 REX.R）
inline int DestReg(const arlde::Insn& in) {
    int r = in.modrmReg;
    if (in.rex & 0x04) r |= 8;          // REX.R
    return r;
}

// 该 MOV load 是否 64 位（REX.W）
inline bool Is64BitLoad(const arlde::Insn& in) { return (in.rex & 0x08) != 0; }

// ---------------- ① 找 count 候选 ----------------
// MOV r32, [base + disp]，disp != 0，base 不是栈
struct CountCand {
    size_t insnIdx = 0;
    int    base    = 0;
    uint32_t disp  = 0;
    int    dstReg  = 0;
};

inline std::vector<CountCand> FindCountLoads(const DecodedFn& d) {
    std::vector<CountCand> out;
    for (size_t i = 0; i < d.insns.size(); ++i) {
        const arlde::Insn& in = d.insns[i];
        if (!in.isMovLoad) continue;
        if (Is64BitLoad(in)) continue;          // 要的是 32 位 load
        if (IsStackBase(in)) continue;
        if (in.disp <= 0) continue;             // 偏移必须为正
        int base = 0;
        if (!MemBase(in, &base)) continue;
        CountCand c;
        c.insnIdx = i;
        c.base = base;
        c.disp = (uint32_t)in.disp;
        c.dstReg = DestReg(in);
        out.push_back(c);
    }
    return out;
}

// ---------------- ②③ 判空守卫 + 条件跳转 ----------------
// 在 count load 之后 1..3 条内找 TEST/CMP 自身，再紧跟 Jcc
inline bool HasGuardAndBranch(const DecodedFn& d, size_t countIdx, size_t* branchIdx) {
    size_t limit = std::min(countIdx + 4, d.insns.size());
    for (size_t i = countIdx + 1; i < limit; ++i) {
        const arlde::Insn& in = d.insns[i];
        bool isTest = (!in.twoByte && (in.opcode == 0x85 ||
                                       in.opcode == 0x84));    // TEST r/m, r
        bool isCmpImm = (!in.twoByte && in.opcode == 0x83 &&
                         in.hasModRm && in.modrmMod == 3 &&
                         in.modrmReg == 7);                        // CMP r32, imm8
        if (!isTest && !isCmpImm) continue;
        // 紧跟条件跳转
        if (i + 1 < d.insns.size()) {
            const arlde::Insn& j = d.insns[i + 1];
            bool jcc1 = (!j.twoByte && j.opcode >= 0x70 && j.opcode <= 0x7F);
            bool jcc2 = (j.twoByte && j.escapeOp >= 0x80 && j.escapeOp <= 0x8F);
            if (jcc1 || jcc2) { *branchIdx = i + 1; return true; }
        }
    }
    return false;
}

// ---------------- ④ 找 array load ----------------
// 分支之后 1..16 条内，MOV r64, [同一 base + disp]，disp != dc
struct ArrayCand {
    size_t   insnIdx = 0;
    uint32_t disp    = 0;
    int      dstReg  = 0;
};

inline bool FindArrayLoad(const DecodedFn& d, size_t branchIdx, int base,
                          uint32_t dc, ArrayCand* out) {
    size_t limit = std::min(branchIdx + 17, d.insns.size());
    for (size_t i = branchIdx + 1; i < limit; ++i) {
        const arlde::Insn& in = d.insns[i];
        if (!in.isMovLoad) continue;
        if (!Is64BitLoad(in)) continue;          // 要 64 位指针 load
        int b = 0;
        if (!MemBase(in, &b) || b != base) continue;
        if (in.disp <= 0) continue;
        uint32_t da = (uint32_t)in.disp;
        if (da == dc) continue;
        out->insnIdx = i;
        out->disp = da;
        out->dstReg = DestReg(in);
        return true;
    }
    return false;
}

// ---------------- ⑤ 元素步长 ----------------
// array 载入寄存器 R 之后，找 [R + idx*scale] 形式的访问，返回 1<<scale
// 也接受 [R + idx] （scale=0 -> 元素 1 字节），但本形状期待 4
inline bool FindElemSize(const DecodedFn& d, size_t arrayIdx, int arrReg, uint32_t* elem,
                         size_t* firstAccessIdx) {
    size_t limit = std::min(arrayIdx + 25, d.insns.size());
    for (size_t i = arrayIdx + 1; i < limit; ++i) {
        const arlde::Insn& in = d.insns[i];
        if (!in.hasModRm || in.modrmMod == 3) continue;
        if (!in.hasSib) {
            // 无 SIB：可能是 [R + disp]
            int b = in.modrmRm | ((in.rex & 0x01) ? 8 : 0);
            if (b != arrReg) continue;
            *elem = 1;
            *firstAccessIdx = i;
            return true;
        }
        int b = in.sibBase | ((in.rex & 0x01) ? 8 : 0);
        int idx = in.sibIndex | ((in.rex & 0x02) ? 8 : 0);
        if (b != arrReg) continue;
        if (idx == 4) continue;                 // 无 index
        *elem = (uint32_t)1 << in.sibScale;
        *firstAccessIdx = i;
        return true;
    }
    return false;
}

// ---------------- ⑥ 消歧 A：首次访问是比较语义 ----------------
// 原型报告的单用 A 剩 2 个，说明这条能排除「纯 MOV 读取」的平行数组。
inline bool FirstAccessIsCompare(const DecodedFn& d, size_t idx) {
    const arlde::Insn& in = d.insns[idx];
    if (in.twoByte) return false;
    // CMP r/m, r     0x39 / 0x3B      CMP r/m, imm  0x80/0x81/0x83 (/7)
    if (in.opcode == 0x39 || in.opcode == 0x3B) return true;
    if ((in.opcode == 0x80 || in.opcode == 0x81 || in.opcode == 0x83) &&
        in.hasModRm && in.modrmReg == 7) return true;
    return false;
}

// ---------------- ⑦ 消歧 B：count 使用频次 ----------------
// 统计某个 disp 在整个函数里作为内存操作数偏移出现的次数
inline int CountDispUsage(const DecodedFn& d, uint32_t disp) {
    int n = 0;
    for (const arlde::Insn& in : d.insns) {
        if (!in.hasModRm || in.modrmMod == 3) continue;
        if (in.hasRipRel) continue;
        if (in.disp == (int64_t)disp) ++n;
    }
    return n;
}

// ---------------- 主入口 ----------------
// 成功返回布局；失败返回 nullopt 并把原因写进 diag。
inline std::optional<CardLayout> FindCardLayout(const uint8_t* code, size_t len,
                                                uint32_t rva, Diag* diag) {
    if (!code || len == 0) {
        if (diag) diag->add("函数体为空");
        return std::nullopt;
    }

    DecodedFn d = DecodeFunction(code, len, rva);
    if (!d.complete) {
        if (diag) {
            diag->add("线性解码未能完整走到函数末尾 —— 解码器可能失步，"
                      "为避免误判直接放弃（fail-closed）");
        }
        return std::nullopt;
    }
    if (diag) diag->add("线性解码完成：" + std::to_string(d.insns.size()) + " 条指令");

    // ---- 形状初筛 ----
    struct RawCand { uint32_t dc, da, elem; size_t cmpIdx; int freq; };
    std::vector<RawCand> raws;

    std::vector<CountCand> counts = FindCountLoads(d);
    if (diag) diag->add("① 32位 count load 候选：" + std::to_string(counts.size()));

    for (const CountCand& cc : counts) {
        size_t branchIdx = 0;
        if (!HasGuardAndBranch(d, cc.insnIdx, &branchIdx)) continue;
        ArrayCand ac;
        if (!FindArrayLoad(d, branchIdx, cc.base, cc.disp, &ac)) continue;
        uint32_t elem = 0;
        size_t accessIdx = 0;
        if (!FindElemSize(d, ac.insnIdx, ac.dstReg, &elem, &accessIdx)) continue;

        RawCand rc;
        rc.dc = cc.disp; rc.da = ac.disp; rc.elem = elem;
        rc.cmpIdx = accessIdx;
        rc.freq = 0;
        raws.push_back(rc);
    }
    if (diag) diag->rawCandidates = (int)raws.size();

    if (raws.empty()) {
        if (diag) diag->add("①~⑤ 完整形状未匹配到任何候选");
        return std::nullopt;
    }
    if (diag) {
        diag->add("①~⑤ 完整形状候选 " + std::to_string(raws.size()) + " 个：");
        for (const RawCand& r : raws) {
            char b[160];
            snprintf(b, sizeof(b), "    count=0x%X array=0x%X elem=%u",
                     r.dc, r.da, r.elem);
            diag->add(b);
        }
    }

    // ---- 消歧 A：首次访问是比较语义 ----
    std::vector<RawCand> afterA;
    for (const RawCand& r : raws) {
        if (FirstAccessIsCompare(d, r.cmpIdx)) afterA.push_back(r);
        else if (diag) {
            char b[160];
            snprintf(b, sizeof(b), "  排除 count=0x%X array=0x%X：首次访问非比较语义",
                     r.dc, r.da);
            diag->add(b);
        }
    }
    if (diag) diag->afterCompare = (int)afterA.size();
    if (afterA.empty()) {
        if (diag) diag->add("消歧A（比较语义）后无候选");
        return std::nullopt;
    }

    // ---- 消歧 B：count 使用频次 ----
    int maxFreq = 0;
    for (RawCand& r : afterA) {
        r.freq = CountDispUsage(d, r.dc);
        if (r.freq > maxFreq) maxFreq = r.freq;
    }
    std::vector<RawCand> afterB;
    for (const RawCand& r : afterA) {
        if (r.freq == maxFreq) afterB.push_back(r);
        else if (diag) {
            char b[160];
            snprintf(b, sizeof(b), "  排除 count=0x%X array=0x%X：使用频次 %d < 最高 %d",
                     r.dc, r.da, r.freq, maxFreq);
            diag->add(b);
        }
    }
    if (diag) diag->afterFrequency = (int)afterB.size();

    // ---- 标准 3：唯一解才接受 ----
    if (afterB.size() != 1) {
        if (diag) {
            diag->add("消歧B 后仍有 " + std::to_string(afterB.size()) +
                      " 个候选 —— 判据不足以区分，按要求返回 nullopt（不猜）");
        }
        return std::nullopt;
    }

    CardLayout out;
    out.countOff = afterB[0].dc;
    out.arrayOff = afterB[0].da;
    out.elemSize = afterB[0].elem;
    if (diag) {
        char b[200];
        snprintf(b, sizeof(b), "=> 唯一解：count=0x%X array=0x%X elem=%u",
                 out.countOff, out.arrayOff, out.elemSize);
        diag->add(b);
    }
    return out;
}

}  // namespace arlayout

#endif  // AR_LAYOUT_H
