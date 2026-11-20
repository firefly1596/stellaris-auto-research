// ar_lde.h —— 极简 x86-64 指令长度解码器（只为"找 rip 相对引用"服务）
//
// 为什么需要它：
//   锚点解析的思路是"某条指令的 rip 相对位移正好指向目标字符串"。
//   如果直接在字节流里搜 `48 8D 05 xx xx xx xx`，会把数据段里的假指令、
//   指令内部的立即数误当成引用。要可靠，必须先**逐条对齐指令边界**，
//   再在每条指令上取 rip 相对位移。
//
// 覆盖范围：足够走完编译器生成的正常代码（REX / 常用前缀 / 单双字节 opcode /
// ModRM+SIB+disp / 立即数）。故意【不】做语义解码，只算长度 + 取 disp。
// 遇到解不了的字节返回 ok=false，上层会把这个候选函数整体放弃 ——
// 宁可漏掉一个锚点，也不能给出错误的地址。
#pragma once
#ifndef AR_LDE_H
#define AR_LDE_H

#include <cstdint>
#include <cstddef>

namespace arlde {

struct Insn {
    size_t  length = 0;      // 整条指令字节数
    bool    ok = false;      // 是否成功解码
    bool    hasRipRel = false;
    int64_t disp = 0;        // ModRM 的 disp32 原值（有符号）
    uint8_t rex = 0;
    bool    twoByte = false; // 0F xx
    uint8_t opcode = 0;
    uint8_t escapeOp = 0;    // twoByte 时的第二个字节

    // ---- 语义字段（L1 结构推导需要，2026-11-11 新增）----
    // 这些字段只是把解码时已经算过的 mod/rm/reg/sib 保存下来，
    // 不改变解码逻辑本身，对长度计算零影响。
    bool    hasModRm = false;
    uint8_t modrmReg = 0;    // ModRM.reg（操作码扩展 / 目标寄存器）
    uint8_t modrmRm  = 0;    // ModRM.rm（基址寄存器，mod!=3 时）
    uint8_t modrmMod = 0;    // ModRM.mod（3 = 寄存器直接寻址，非内存）
    bool    hasSib = false;
    uint8_t sibScale = 0;    // SIB.scale 原始值 0..3（步长 = 1 << scale）
    uint8_t sibIndex = 0;    // SIB.index（4 = 无 index）
    uint8_t sibBase  = 0;    // SIB.base
    // 该指令是否「从内存读入寄存器」（MOV r, [..] 语义）
    // 只对 opcode 8B / 8A 置 true，其余保守为 false。
    bool    isMovLoad = false;
};

inline bool IsLegacyPrefix(uint8_t b) {
    switch (b) {
        case 0x66: case 0x67: case 0xF0: case 0xF2: case 0xF3:
        case 0x2E: case 0x36: case 0x3E: case 0x26: case 0x64: case 0x65:
            return true;
        default:
            return false;
    }
}

// 单字节 opcode 里 0F 表之外、带 ModRM 的项判定
inline bool HasModRm_1Byte(uint8_t op) {
    if (op < 0x40) return (op & 7) <= 3;              // ALU 族
    if (op >= 0x80 && op <= 0x8F) return true;        // group1 / mov / lea / pop
    if (op >= 0xD0 && op <= 0xD3) return true;        // shift
    if (op >= 0xD8 && op <= 0xDF) return true;        // x87
    if (op >= 0xFE) return true;                      // group4/5
    switch (op) {
        case 0x62: case 0x63:                         // bound / movsxd
        case 0x69: case 0x6B:                         // imul
        case 0xC0: case 0xC1:                         // shift imm
        case 0xC4: case 0xC5:                         // vex (rare in legacy code)
        case 0xC6: case 0xC7:                         // mov imm
        case 0xF6: case 0xF7:                         // group3
            return true;
        default:
            return false;
    }
}

// 0F 表里【没有】ModRM 的项（其余默认都有）
inline bool HasModRm_2ByteNoModRm(uint8_t op2) {
    switch (op2) {
        case 0x05: case 0x06: case 0x07: case 0x08: case 0x09: case 0x0B:
        case 0x0E:
        case 0x30: case 0x31: case 0x32: case 0x33: case 0x34: case 0x35:
        case 0x36: case 0x37:
        case 0x77:
        case 0xA0: case 0xA1: case 0xA2:
        case 0xA8: case 0xA9: case 0xAA:
        case 0xC8: case 0xC9: case 0xCA: case 0xCB: case 0xCC: case 0xCD:
        case 0xCE: case 0xCF:
            return true;
        default:
            break;
    }
    if (op2 >= 0x80 && op2 <= 0x8F) return true;      // Jcc rel32
    return false;
}

// 解码一条指令。code/codeLen 为所在缓冲区，maxLen 限制不越过函数边界。
inline Insn Decode(const uint8_t* code, size_t maxLen) {
    Insn in;
    if (!code || maxLen == 0) return in;

    size_t i = 0;
    bool opsize16 = false;

    // 前缀
    while (i < maxLen && IsLegacyPrefix(code[i])) {
        if (code[i] == 0x66) opsize16 = true;
        ++i;
        if (i > 14) return in;   // 前缀过多，非法
    }
    // REX
    if (i < maxLen && (code[i] & 0xF0) == 0x40) {
        in.rex = code[i];
        ++i;
    }
    if (i >= maxLen) return in;

    uint8_t op = code[i++];
    bool twoByte = false;
    uint8_t op2 = 0;
    if (op == 0x0F) {
        if (i >= maxLen) return in;
        twoByte = true;
        op2 = code[i++];
    }
    in.twoByte = twoByte;
    in.opcode = op;
    in.escapeOp = op2;

    bool hasModRm = twoByte ? !HasModRm_2ByteNoModRm(op2) : HasModRm_1Byte(op);
    uint8_t modrm = 0;
    int mod = 0, rm = 0;

    if (hasModRm) {
        if (i >= maxLen) return in;
        modrm = code[i++];
        mod = (modrm >> 6) & 3;
        rm = modrm & 7;
        // 保存语义字段（L1 推导用）
        in.hasModRm = true;
        in.modrmMod = (uint8_t)mod;
        in.modrmReg = (uint8_t)((modrm >> 3) & 7);
        in.modrmRm  = (uint8_t)rm;

        if (mod != 3 && rm == 4) {          // SIB
            if (i >= maxLen) return in;
            uint8_t sib = code[i++];
            in.hasSib = true;
            in.sibScale = (uint8_t)((sib >> 6) & 3);
            in.sibIndex = (uint8_t)((sib >> 3) & 7);
            in.sibBase  = (uint8_t)(sib & 7);
            if (mod == 0 && ((sib >> 3) & 7) == 5) {
                i += 4;                      // SIB 带 disp32
                if (i > maxLen) return in;
            }
        }
        if (mod == 0 && rm == 5) {           // RIP 相对
            if (i + 4 > maxLen) return in;
            int32_t d;
            __builtin_memcpy(&d, code + i, 4);
            in.hasRipRel = true;
            in.disp = d;
            i += 4;
        } else if (mod == 1) {
            // disp8：也保存下来（L1 推导需要真实偏移值）
            if (i + 1 > maxLen) return in;
            int8_t d8;
            __builtin_memcpy(&d8, code + i, 1);
            in.disp = d8;
            i += 1;
            if (i > maxLen) return in;
        } else if (mod == 2) {
            // disp32：保存下来。原实现只跳过 4 字节（只算长度），
            // 但 L1 结构推导必须读到真实偏移 —— 2026-11-11 修复。
            if (i + 4 > maxLen) return in;
            int32_t d32;
            __builtin_memcpy(&d32, code + i, 4);
            in.disp = d32;
            i += 4;
            if (i > maxLen) return in;
        }
    }

    // 立即数
    size_t imm = 0;
    if (!twoByte) {
        if (op < 0x40 && ((op & 7) == 4)) imm = 1;
        else if (op < 0x40 && ((op & 7) == 5)) imm = opsize16 ? 2 : 4;
        else {
            switch (op) {
                case 0x68: imm = opsize16 ? 2 : 4; break;
                case 0x69: imm = opsize16 ? 2 : 4; break;
                case 0x6A: imm = 1; break;
                case 0x6B: imm = 1; break;
                case 0x80: case 0x83: case 0xC0: case 0xC1: case 0xC6:
                    imm = 1; break;
                case 0x81: case 0xC7: imm = opsize16 ? 2 : 4; break;
                case 0xA8: imm = 1; break;
                case 0xA9: imm = opsize16 ? 2 : 4; break;
                case 0xB0: case 0xB1: case 0xB2: case 0xB3:
                case 0xB4: case 0xB5: case 0xB6: case 0xB7:
                    imm = 1; break;
                case 0xB8: case 0xB9: case 0xBA: case 0xBB:
                case 0xBC: case 0xBD: case 0xBE: case 0xBF:
                    // REX.W 时是 movabs r64, imm64
                    imm = (in.rex & 0x08) ? 8 : (opsize16 ? 2 : 4);
                    break;
                case 0xC2: imm = 2; break;
                case 0xCA: imm = 2; break;
                case 0xCD: imm = 1; break;
                case 0xE4: case 0xE5: case 0xE6: case 0xE7: imm = 1; break;
                case 0xE8: case 0xE9: imm = 4; break;
                case 0xEB: imm = 1; break;
                case 0xF6: imm = ((modrm >> 3) & 7) <= 1 ? 1 : 0; break;
                case 0xF7: imm = ((modrm >> 3) & 7) <= 1 ? (opsize16 ? 2 : 4) : 0; break;
                default: break;
            }
            if (op >= 0x70 && op <= 0x7F) imm = 1;       // Jcc rel8
            if (op >= 0xE0 && op <= 0xE3) imm = 1;       // loop/jcxz rel8
            if (op == 0xC8) imm = 3;                     // enter
        }
    } else {
        if (op2 >= 0x80 && op2 <= 0x8F) imm = 4;         // Jcc rel32
    }

    i += imm;
    if (i > maxLen) return in;

    in.length = i;
    in.ok = true;

    // ---- 语义标记：MOV r, [mem] ----
    // 8B /r  = MOV r32/r64, r/m  （方向由 ModRM.reg 作目标）
    // 8A /r  = MOV r8,  r/m
    // 仅当操作数是内存（mod != 3）时才算 load。
    // 同时记录目的寄存器位宽：REX.W -> 64 位，否则 32 位。
    if (!twoByte && in.hasModRm && in.modrmMod != 3 &&
        (in.opcode == 0x8B || in.opcode == 0x8A)) {
        in.isMovLoad = true;
    }
    return in;
}

// 从函数起点开始逐条走，找引用 targetRva 的 rip 相对指令
// 返回引用次数（0 表示没找到）；outFirstSite 给出第一条的 RVA
inline uint32_t CountRipRefs(const uint8_t* code, size_t codeLen, uint32_t funcRva,
                             uint32_t targetRva, uint32_t* outFirstSite = nullptr) {
    uint32_t hits = 0;
    size_t off = 0;
    size_t guard = 0;
    while (off < codeLen && guard++ < 200000) {
        Insn in = Decode(code + off, codeLen - off);
        if (!in.ok || in.length == 0) break;   // 解码失败 → 放弃整个函数
        if (in.hasRipRel) {
            // rip = 下一条指令的 RVA
            int64_t next = (int64_t)funcRva + (int64_t)off + (int64_t)in.length;
            int64_t target = next + in.disp;
            if (target == (int64_t)targetRva) {
                if (hits == 0 && outFirstSite)
                    *outFirstSite = (uint32_t)(funcRva + off);
                ++hits;
            }
        }
        off += in.length;
    }
    return hits;
}

}  // namespace arlde

#endif  // AR_LDE_H
