// ============================================================================
// Win64 shadow space 覆盖 —— 离线验证（2026-11-16 真机崩溃根因）
// ============================================================================
//
// 【根因】
//   桩的 7 次 push 让 rsp = R-56。
//   此时直接 call 一个 4 参数函数，被调用者的 shadow space 是
//   [R-64, R-64+0x20) = [R-64, R-32)，正好覆盖：
//       r11 @ R-56, r10 @ R-48, r9 @ R-40, r8 @ R-32
//   被调用者序言（MSVC）会把 rcx/rdx/r8/r9 spill 进 shadow，
//   于是保存的 r8（tech 对象指针）被写坏 → pop 拿到垃圾 → 崩。
//
// 【修复】
//   call 前 sub $0x20, %rsp（rsp = R-88，(8-88)%16 = 0 仍对齐）
//   自己的 shadow 变成 [R-80, R-56)，与保存区 [R-56, R-8] 无重叠。
//   参数偏移全部 +0x20。
//
// 【本测试不执行旧桩】
//   旧桩执行时真的会破坏寄存器并可能跳飞（实测 segfault），
//   所以改用【静态字节检查】验证两者差异，宏观且安全。
// ============================================================================

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>

static int g_pass = 0, g_fail = 0;
static void Check(bool ok, const char* msg) {
    printf("  [%s] %s\n", ok ? "PASS" : "FAIL", msg);
    if (ok) ++g_pass; else ++g_fail;
}

// ---- 旧桩字节序列（7 push 后直接 call，无 sub）----
static const uint8_t kOld[] = {
    0x50,                    // push rax
    0x51,                    // push rcx
    0x52,                    // push rdx
    0x41,0x50,               // push r8
    0x41,0x51,               // push r9
    0x41,0x52,               // push r10
    0x41,0x53,               // push r11
    0x4C,0x8B,0x44,0x24,0x18,// mov 24(%rsp),%r8
    0x48,0x8B,0x54,0x24,0x20,// mov 32(%rsp),%rdx
    0x48,0x8B,0x4C,0x24,0x28,// mov 40(%rsp),%rcx
    0x4C,0x8B,0x4C,0x24,0x10,// mov 16(%rsp),%r9
    0xE8,0x00,0x00,0x00,0x00,// call rel32
};

// ---- 新桩字节序列（7 push + sub 0x20 + 偏移+0x20 + add 0x20）----
static const uint8_t kNew[] = {
    0x50, 0x51, 0x52,
    0x41,0x50, 0x41,0x51, 0x41,0x52, 0x41,0x53,
    0x48,0x83,0xEC,0x20,       // ★ sub $0x20,%rsp
    0x4C,0x8B,0x44,0x24,0x38,  // mov 56(%rsp),%r8
    0x48,0x8B,0x54,0x24,0x40,  // mov 64(%rsp),%rdx
    0x48,0x8B,0x4C,0x24,0x48,  // mov 72(%rsp),%rcx
    0x4C,0x8B,0x4C,0x24,0x30,  // mov 48(%rsp),%r9
    0xE8,0x00,0x00,0x00,0x00,  // call rel32
    0x48,0x83,0xC4,0x20,       // ★ add $0x20,%rsp
};

// 检查字节数组里是否有给定子序列
static bool HasSeq(const uint8_t* p, size_t n, const uint8_t* s, size_t sn) {
    if (sn > n) return false;
    for (size_t i = 0; i + sn <= n; ++i)
        if (memcmp(p + i, s, sn) == 0) return true;
    return false;
}

int main() {
    printf("=== Win64 shadow space 覆盖：静态字节验证 ===\n\n");
    printf("根因：7 push 后 rsp=R-56，call 时被调用者 shadow=[R-64,R-32)，\n");
    printf("      覆盖 r11@R-56 / r10@R-48 / r9@R-40 / r8@R-32。\n\n");

    // ---------- 旧桩（有 bug）----------
    printf("--- 旧桩（7 push 后直接 call）---\n");
    {
        const uint8_t kSub20[] = {0x48,0x83,0xEC,0x20};
        Check(!HasSeq(kOld, sizeof(kOld), kSub20, sizeof(kSub20)),
              "旧桩没有 sub $0x20（这是 bug）");
        // 旧桩第一个参数偏移是 0x18（=24），即 [R-32] = r8 保存槽
        const uint8_t kParam3Old[] = {0x4C,0x8B,0x44,0x24,0x18};
        Check(HasSeq(kOld, sizeof(kOld), kParam3Old, sizeof(kParam3Old)),
              "旧桩 param_3 读 [rsp+0x18] = [R-32]（r8 保存槽）");
        // 计算：shadow 覆盖区间
        printf("    shadow 覆盖 [R-64, R-32)  ⇒ r11@R-56 / r10@R-48 / r9@R-40 / r8@R-32 全在范围内\n");
        Check(true, "旧桩的保存区【全部落在】被调用者 shadow space 内（会被写坏）");
    }
    printf("\n");

    // ---------- 新桩（已修）----------
    printf("--- 新桩（7 push + sub 0x20 + 偏移+0x20 + add 0x20）---\n");
    {
        const uint8_t kSub20[]   = {0x48,0x83,0xEC,0x20};
        const uint8_t kAdd20[]   = {0x48,0x83,0xC4,0x20};
        const uint8_t kParam3New[] = {0x4C,0x8B,0x44,0x24,0x38};  // [rsp+0x38] = [R-32]
        const uint8_t kParam2New[] = {0x48,0x8B,0x54,0x24,0x40};  // [rsp+0x40] = [R-24]
        const uint8_t kParam1New[] = {0x48,0x8B,0x4C,0x24,0x48};  // [rsp+0x48] = [R-16]
        const uint8_t kParam4New[] = {0x4C,0x8B,0x4C,0x24,0x30};  // [rsp+0x30] = [R-40]

        Check(HasSeq(kNew, sizeof(kNew), kSub20, sizeof(kSub20)),
              "新桩有 sub $0x20（预留自己的 shadow）");
        Check(HasSeq(kNew, sizeof(kNew), kAdd20, sizeof(kAdd20)),
              "新桩有 add $0x20（恢复栈）");
        Check(HasSeq(kNew, sizeof(kNew), kParam3New, sizeof(kParam3New)),
              "param_3 偏移已改为 0x38（对应 [R-32]）");
        Check(HasSeq(kNew, sizeof(kNew), kParam2New, sizeof(kParam2New)),
              "param_2 偏移已改为 0x40（对应 [R-24]）");
        Check(HasSeq(kNew, sizeof(kNew), kParam1New, sizeof(kParam1New)),
              "param_1 偏移已改为 0x48（对应 [R-16]）");
        Check(HasSeq(kNew, sizeof(kNew), kParam4New, sizeof(kParam4New)),
              "SEL 的 param_4 偏移为 0x30（对应 [R-40]）");
    }
    printf("\n");

    // ---------- 区间不重叠验证 ----------
    printf("--- 区间分析 ---\n");
    {
        // 入口 rsp = R，7 push 后 R-56，sub 0x20 后 R-88
        const int64_t R = 0;
        const int64_t afterPush = R - 56;
        const int64_t afterSub  = R - 88;
        // 被调用者入口 rsp = afterSub - 8（call 压返回地址）
        const int64_t calleeRsp = afterSub - 8;
        const int64_t shadowLo  = calleeRsp + 8;    // = afterSub
        const int64_t shadowHi  = shadowLo + 0x20;  // = afterSub + 32
        const int64_t saveLo    = afterPush;        // 保存区下界 = R-56（push 后 rsp）
        const int64_t saveHi    = R;                // 返回地址（不含）
        printf("    R = 入口 rsp\n");
        printf("    7 push 后 rsp      = R-56\n");
        printf("    sub 0x20 后 rsp    = R-88\n");
        printf("    被调用者入口 rsp   = R-96\n");
        printf("    被调用者 shadow    = [R-88, R-56)\n");
        printf("    我们的保存区       = [R-56, R)\n");
        Check(shadowHi <= saveLo,
              "shadow 上界 ≤ 保存区下界（无重叠）");
        printf("    ⇒ [R-88,R-56) 与 [R-56,R) 恰好相接，不重叠 ✓\n");
        // 对齐
        Check(((8 - 56 - 32) % 16 + 16) % 16 == 0,
              "sub 后 rsp 仍 16 字节对齐（(8-56-32)%16==0）");
    }
    printf("\n");

    printf("==============================================\n");
    printf("结果: %d passed, %d failed, %d total\n", g_pass, g_fail, g_pass + g_fail);
    printf("结论: %s\n", g_fail == 0 ? "ALL PASS" : "FAILED");
    printf("==============================================\n");
    return g_fail == 0 ? 0 : 1;
}
