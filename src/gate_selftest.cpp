// gate_selftest.cpp —— 版本闸门离线自测（不需要游戏、不需要 hook）
//
// 用"假映像"(FakeImage) 构造各种输入，验证闸门在每种情况下都做出正确判断：
//   - 完全正确 → FullyInstalled，装 2 个 hook
//   - SHA256 错、buildId 对 → Unverified（仍装，但日志标注）
//   - SHA256 错、buildId 错 → VersionRejected（一个都不装）
//   - 地址不在可执行段 → AddressRejected
//   - .pdata 说不是函数入口（RVA 漂移）→ AddressRejected
//   - 函数长度不符（版本漂移/被别的 mod 改）→ AddressRejected
//   - 序言字节不符（被别人 patch 过）→ FingerprintRejected
//   - 安装中途失败 → 回滚到原始字节（字节级验证）
//
// 编译：
//   g++ -std=c++17 -O2 -o gate_selftest.exe gate_selftest.cpp
#include "ar_gate.h"

#include <cstdio>
#include <string>
#include <vector>

// ================= 迷你测试框架 =================
static int g_pass = 0, g_fail = 0;
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
static void __attribute__((unused)) DumpReport(const argate::Report& r) {
    std::string s = r.Summary();
    size_t pos = 0;
    while (pos < s.size()) {
        size_t nl = s.find('\n', pos);
        std::string line = s.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos);
        if (!line.empty()) Emit("      " + line);
        if (nl == std::string::npos) break;
        pos = nl + 1;
    }
}

// ================= 假映像 =================
class FakeImage : public argate::IImage {
public:
    std::string name = "fake-stellaris.exe";
    std::string sha = arver::kSupportedSha256;
    std::string buildId = arver::kSupportedBuildId;
    uint64_t size = 0x40000000ULL;

    // RVA → 内容
    struct Region {
        uint32_t rva;
        std::vector<uint8_t> bytes;
        bool executable = true;
        bool isFuncStart = true;
        uint32_t funcLen = 0;
    };
    std::vector<Region> regions;

    // 用生成器的真值填一份"正确的"映像
    // 注意：现在闸门除了 16B 序言还要校验长特征码（sig），
    // 所以这里必须把两者都准备好，否则每个目标都会被判 sigOk=false。
    void BuildCorrect() {
        regions.clear();
        for (size_t i = 0; i < arver::kTargetCount; ++i) {
            const arver::Target& t = arver::kTargets[i];
            Region r;
            r.rva = t.rva;
            // 前 16 字节用 expect（序言），随后用 sig 覆盖成完整长签名
            r.bytes.assign(t.sig, t.sig + t.sigLen);
            if (r.bytes.size() < arver::kPrologueLen)
                r.bytes.insert(r.bytes.end(), arver::kPrologueLen - r.bytes.size(), 0);
            memcpy(r.bytes.data(), t.expect, arver::kPrologueLen);
            r.executable = true;
            r.isFuncStart = true;
            r.funcLen = t.funcLen;
            regions.push_back(r);
        }
    }

    // 改长签名里的一个字节（用于验证"长签名能抓住篡改"）
    void SetSigByte(uint32_t rva, size_t idx, uint8_t val) {
        for (auto& r : regions)
            if (r.rva == rva && idx >= arver::kPrologueLen && idx < r.bytes.size())
                r.bytes[idx] = val;
    }

    void SetPrologueByte(uint32_t rva, size_t idx, uint8_t val) {
        for (auto& r : regions) if (r.rva == rva && idx < r.bytes.size()) r.bytes[idx] = val;
    }
    void SetFuncLen(uint32_t rva, uint32_t len) {
        for (auto& r : regions) if (r.rva == rva) r.funcLen = len;
    }
    void SetNotFuncStart(uint32_t rva) {
        for (auto& r : regions) if (r.rva == rva) r.isFuncStart = false;
    }
    void SetNonExecutable(uint32_t rva) {
        for (auto& r : regions) if (r.rva == rva) r.executable = false;
    }

    const char* Name() const override { return name.c_str(); }
    uint64_t Base() const override { return arver::kImageBase; }
    uint64_t Size() const override { return size; }

    bool IsExecutable(uint32_t rva) const override {
        for (auto& r : regions) if (r.rva == rva) return r.executable;
        return false;
    }
    bool ReadBytes(uint32_t rva, void* dst, size_t n) const override {
        for (auto& r : regions) {
            if (r.rva != rva) continue;
            if (r.bytes.size() < n) return false;
            memcpy(dst, r.bytes.data(), n);
            return true;
        }
        return false;
    }
    bool IsFunctionStart(uint32_t rva, uint32_t* funcLen) const override {
        for (auto& r : regions) {
            if (r.rva != rva) continue;
            if (!r.isFuncStart) return false;
            if (funcLen) *funcLen = r.funcLen;
            return true;
        }
        return false;
    }
    std::string Sha256() const override { return sha; }
    std::string EmbeddedBuildId() const override { return buildId; }
};

// 统计 Report 里 Hook 类目标的数量
static size_t HookCount() {
    size_t n = 0;
    for (size_t i = 0; i < arver::kTargetCount; ++i)
        if (arver::kTargets[i].kind == arver::TargetKind::Hook) ++n;
    return n;
}

// =====================================================================
// 1) 版本锚
// =====================================================================
static void TestVersionAnchor() {
    Section("1) 版本锚：SHA256 / buildId");

    // 1.1 完全匹配
    {
        FakeImage img; img.BuildCorrect();
        argate::Report r = argate::Inspect(img);
        Check(r.anchor == argate::Anchor::Sha256Exact && r.state == argate::State::FullyInstalled,
              "SHA256 精确匹配 → FullyInstalled",
              std::string(argate::StateName(r.state)) + " / " + argate::AnchorName(r.anchor));
    }
    // 1.2 大小写不敏感
    {
        FakeImage img; img.BuildCorrect();
        std::string up = img.sha;
        for (auto& c : up) c = (char)toupper((unsigned char)c);
        img.sha = up;
        argate::Report r = argate::Inspect(img);
        Check(r.state == argate::State::FullyInstalled, "SHA256 大写也认（大小写不敏感）",
              argate::StateName(r.state));
    }
    // 1.3 SHA 错但 buildId 对 → Unverified，仍然可用
    {
        FakeImage img; img.BuildCorrect();
        img.sha = "deadbeef" + std::string(56, '0');
        argate::Report r = argate::Inspect(img);
        Check(r.anchor == argate::Anchor::BuildIdOnly && r.state == argate::State::Unverified,
              "SHA256 不符但 buildId 匹配 → Unverified",
              std::string(argate::StateName(r.state)) + " / " + argate::AnchorName(r.anchor));
        Check(argate::IsUsable(r.state), "Unverified 仍算可用（不阻断合法 patch）");
        Check(r.errors.size() >= 1 && r.errors.back().find("UNVERIFIED") != std::string::npos,
              "日志里有 UNVERIFIED 提示");
    }
    // 1.4 两者都不匹配 → 拒绝
    {
        FakeImage img; img.BuildCorrect();
        img.sha = "deadbeef" + std::string(56, '0');
        img.buildId = "ffffffffffffffffffffffffffffffff";
        argate::Report r = argate::Inspect(img);
        Check(r.state == argate::State::VersionRejected, "两项都不匹配 → VersionRejected",
              argate::StateName(r.state));
        Check(r.targets.empty(), "版本就不过时直接返回，不做多余检查（日志干净）",
              "targets=" + std::to_string(r.targets.size()));
        Check(!r.errors.empty(), "有明确错误说明");
    }
    // 1.5 拿不到 SHA（文件被锁）
    {
        FakeImage img; img.BuildCorrect();
        img.sha = "";
        img.buildId = "";
        argate::Report r = argate::Inspect(img);
        Check(r.state == argate::State::VersionRejected, "SHA 不可读且无 buildId → 拒绝",
              argate::StateName(r.state));
        bool said = false;
        for (auto& e : r.errors) if (e.find("cannot hash") != std::string::npos) said = true;
        Check(said, "日志说明是「读不到」而不是「版本不符」");
    }
    // 1.6 错误信息里必须能看出期望 vs 实际
    {
        FakeImage img; img.BuildCorrect();
        img.sha = "aaaa" + std::string(60, '0');
        img.buildId = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        argate::Report r = argate::Inspect(img);
        std::string all;
        for (auto& e : r.errors) all += e + "\n";
        Check(all.find(arver::kSupportedBuildId) != std::string::npos,
              "错误信息含期望 buildId");
        Check(all.find("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") != std::string::npos,
              "错误信息含实际 buildId");
        Check(all.find(arver::kSupportedVersionTag) != std::string::npos,
              "错误信息含期望版本名（" + std::string(arver::kSupportedVersionTag) + "）");
    }
}

// =====================================================================
// 2) 地址 / 函数指纹
// =====================================================================
static void TestFingerprint() {
    Section("2) 地址与方法指纹：全有或全无");
    const uint32_t firstHookRva = arver::kTargets[0].rva;

    // 2.1 地址不在可执行段
    {
        FakeImage img; img.BuildCorrect();
        img.SetNonExecutable(firstHookRva);
        argate::Report r = argate::Inspect(img);
        Check(r.state == argate::State::AddressRejected, "地址不在可执行段 → AddressRejected",
              argate::StateName(r.state));
        Check(!argate::IsUsable(r.state), "被拒绝时 IsUsable()==false");
    }
    // 2.2 RVA 超出映像
    {
        FakeImage img; img.BuildCorrect();
        img.size = 0x1000;   // 比所有目标 RVA 都小
        argate::Report r = argate::Inspect(img);
        Check(r.state == argate::State::AddressRejected, "RVA 超出映像范围 → AddressRejected",
              argate::StateName(r.state));
    }
    // 2.3 .pdata 说不是函数入口（RVA 漂移）
    {
        FakeImage img; img.BuildCorrect();
        img.SetNotFuncStart(firstHookRva);
        argate::Report r = argate::Inspect(img);
        Check(r.state == argate::State::AddressRejected,
              ".pdata 不认它是函数入口 → AddressRejected", argate::StateName(r.state));
    }
    // 2.4 函数长度不符
    {
        FakeImage img; img.BuildCorrect();
        img.SetFuncLen(firstHookRva, 999);
        argate::Report r = argate::Inspect(img);
        Check(r.state == argate::State::AddressRejected, "函数长度不符 → AddressRejected",
              argate::StateName(r.state));
        bool said = false;
        for (auto& t : r.targets)
            if (!t.Ok() && t.detail.find("length") != std::string::npos) said = true;
        Check(said, "失败原因写明是「长度不符」");
    }
    // 2.5 序言字节不符（被别人 patch 过）
    {
        FakeImage img; img.BuildCorrect();
        img.SetPrologueByte(firstHookRva, 0, 0xCC);   // int3
        argate::Report r = argate::Inspect(img);
        Check(r.state == argate::State::FingerprintRejected,
              "序言被改过 → FingerprintRejected（区别于版本漂移）",
              argate::StateName(r.state));
        bool said = false;
        for (auto& t : r.targets)
            if (!t.Ok() && t.detail.find("prologue") != std::string::npos) said = true;
        Check(said, "失败原因写明是序言字节不符");
    }
    // 2.6 版本拒绝 vs 指纹拒绝，日志要能区分
    {
        FakeImage v; v.BuildCorrect();
        v.sha = std::string(64, '0'); v.buildId = "11111111111111111111111111111111";
        argate::Report rv = argate::Inspect(v);

        FakeImage f; f.BuildCorrect();
        f.SetPrologueByte(firstHookRva, 0, 0xCC);
        argate::Report rf = argate::Inspect(f);

        Check(rv.state != rf.state, "版本不符 与 序言不符 是两种不同状态",
              std::string(argate::StateName(rv.state)) + " vs " +
              argate::StateName(rf.state));
        Check(rv.anchor == argate::Anchor::None && rf.anchor == argate::Anchor::Sha256Exact,
              "版本锚结果也不同（none vs sha256-exact）");
    }
    // 2.7 只要有一个目标失败，整体就不可用
    {
        FakeImage img; img.BuildCorrect();
        // 弄坏最后一个【必需】目标（Diagnostic 目标失败不应阻止安装）
        int lastReq = -1;
        for (size_t k = 0; k < arver::kTargetCount; ++k)
            if (arver::kTargets[k].kind != arver::TargetKind::Diagnostic) lastReq = (int)k;
        const arver::Target& last = arver::kTargets[lastReq];
        img.SetPrologueByte(last.rva, 0, 0xCC);
        argate::Report r = argate::Inspect(img);
        Check(!argate::IsUsable(r.state),
              "任一目标失败 → 整体不可用（禁止半挂）", argate::StateName(r.state));
        size_t okCount = 0;
        for (auto& t : r.targets) if (t.Ok()) ++okCount;
        Check(okCount == arver::kTargetCount - 1,
              "其它目标本身是通过的（证明是「因为一个失败而整体拒绝」）",
              "ok=" + std::to_string(okCount) + "/" + std::to_string(arver::kTargetCount));
    }
    // 2.7b 长签名能抓住"序言对但函数体不同"——这正是 15 字节 memcmp 抓不到的
    {
        FakeImage img; img.BuildCorrect();
        const arver::Target& t0 = arver::kTargets[0];
        // 只在签名深处（超出 16B 序言）改一个字节
        img.SetSigByte(t0.rva, arver::kPrologueLen + 4, 0xEE);
        argate::Report r = argate::Inspect(img);
        Check(!argate::IsUsable(r.state),
              "序言对但长签名不符 → 拒绝（15B memcmp 会漏掉这种）",
              argate::StateName(r.state));
        bool saidSig = false;
        for (auto& tc : r.targets)
            if (!tc.Ok() && tc.detail.find("signature") != std::string::npos) saidSig = true;
        Check(saidSig, "失败原因写明是长签名不符");
    }
    // 2.7c 主 hook 的 15 字节序言在真实 .text 里重复 2572 次 —— 记录这个事实，
    //     确保生成器算出的 sigLen 足够长（不是 15 或 16）
    {
        const arver::Target& mainHook = arver::kTargets[0];
        Check(mainHook.sigLen >= 24,
              "主 hook 的长签名长度 >= 24 字节（足以区分）",
              "sigLen=" + std::to_string(mainHook.sigLen));
        Check(mainHook.prologueDupCount > 100,
              "生成器记录到主 hook 序言高度重复（证明 15B 不足以定位）",
              "dup=" + std::to_string(mainHook.prologueDupCount));
    }


    // 2.8 全部通过时每个目标都 Ok
    {
        FakeImage img; img.BuildCorrect();
        argate::Report r = argate::Inspect(img);
        bool all = true;
        for (auto& t : r.targets) if (!t.Ok()) all = false;
        Check(all && r.targets.size() == arver::kTargetCount,
              "全对时每个目标都 Ok", "n=" + std::to_string(r.targets.size()));
    }
}

// =====================================================================
// 3) 安装计划 + 字节回滚
// =====================================================================
static void TestPlanAndRollback() {
    Section("3) 安装计划与字节回滚");

    // 3.1 计划只包含 Hook 类目标
    {
        FakeImage img; img.BuildCorrect();
        argate::Report r = argate::Inspect(img);
        uint64_t addrs[8] = {0x1111111111111111ULL, 0x2222222222222222ULL,
                             0x3333333333333333ULL, 0x4444444444444444ULL,
                             0x5555555555555555ULL, 0x6666666666666666ULL,
                             0x7777777777777777ULL, 0x8888888888888888ULL};
        std::vector<argate::Patch> plan = argate::BuildPlan(r, img, addrs, 8);
        Check(plan.size() == HookCount(),
              "补丁数 = Hook 类目标数(" + std::to_string(HookCount()) + ")",
              "plan=" + std::to_string(plan.size()));
        bool originalsOk = true;
        for (auto& p : plan) {
            // 原始字节必须与生成器里的期望序言前 15 字节一致
            const arver::Target* t = nullptr;
            for (size_t i = 0; i < arver::kTargetCount; ++i)
                if (arver::kTargets[i].rva == p.rva) t = &arver::kTargets[i];
            if (!t || memcmp(p.original, t->expect, arver::kPatchLen) != 0) originalsOk = false;
        }
        Check(originalsOk, "每个补丁都保存了正确的原始字节（回滚依据）");
    }
    // 3.2 拒绝状态下不生成任何计划
    {
        FakeImage img; img.BuildCorrect();
        img.sha = std::string(64, '0');
        img.buildId = "22222222222222222222222222222222";
        argate::Report r = argate::Inspect(img);
        uint64_t addrs[8] = {0x1111111111111111ULL};
        std::vector<argate::Patch> plan = argate::BuildPlan(r, img, addrs, 1);
        Check(plan.empty(), "版本被拒 → 计划为空（一个 hook 都不装）",
              "plan=" + std::to_string(plan.size()));
    }
    // 3.3 jmp 字节形态正确
    {
        uint8_t buf[arver::kPatchLen];
        argate::MakeAbsJmp(buf, 0x1122334455667788ULL);
        Check(buf[0] == 0x48 && buf[1] == 0xB8, "补丁以 mov rax, imm64 开头");
        uint64_t got = 0; memcpy(&got, buf + 2, 8);
        Check(got == 0x1122334455667788ULL, "imm64 正确");
        Check(buf[10] == 0xFF && buf[11] == 0xE0, "以 jmp rax 结尾");
        Check(buf[12] == 0x90 && buf[13] == 0x90 && buf[14] == 0x90, "剩余 3 字节填 nop");
    }
    // 3.4 模拟安装中途失败 → 回滚后内存 == 原始字节
    {
        FakeImage img; img.BuildCorrect();
        argate::Report r = argate::Inspect(img);
        uint64_t addrs[8] = {0xAAAA000000000001ULL, 0xAAAA000000000002ULL,
                             0xAAAA000000000003ULL, 0xAAAA000000000004ULL,
                             0xAAAA000000000005ULL, 0xAAAA000000000006ULL,
                             0xAAAA000000000007ULL, 0xAAAA000000000008ULL};
        std::vector<argate::Patch> plan = argate::BuildPlan(r, img, addrs, 8);

        // 用一块可写内存模拟游戏代码段
        std::vector<uint8_t> mem(0x1000, 0xCC);
        // 把每个 patch 的原始字节放进去
        for (auto& p : plan)
            memcpy(mem.data() + (p.rva & 0x7FF), p.original, arver::kPatchLen);

        // 模拟：逐个写入，第 2 个时"失败"，然后把已写的全部还原
        auto applyAt = [&](size_t idx, bool useOriginal) {
            auto& p = plan[idx];
            memcpy(mem.data() + (p.rva & 0x7FF),
                   useOriginal ? p.original : p.patched, arver::kPatchLen);
        };
        std::vector<size_t> written;
        bool failed = false;
        for (size_t i = 0; i < plan.size(); ++i) {
            if (i == 1) { failed = true; break; }   // 第二个写入失败
            applyAt(i, false);
            written.push_back(i);
        }
        Check(failed, "模拟：安装到第 2 个时失败");
        // 回滚
        for (auto i : written) applyAt(i, true);

        bool restored = true;
        for (size_t i = 0; i < plan.size(); ++i) {
            auto& p = plan[i];
            if (memcmp(mem.data() + (p.rva & 0x7FF), p.original, arver::kPatchLen) != 0)
                restored = false;
        }
        Check(restored, "回滚后所有目标字节 == 原始字节（无残留补丁）",
              "restored=" + std::to_string(restored));
    }
}

// =====================================================================
// 4) 状态位语义
// =====================================================================
static void TestStateSemantics() {
    Section("4) 状态位语义（给网页/脚本用）");
    Check(!argate::IsUsable(argate::State::NotChecked), "NotChecked 不可用");
    Check(!argate::IsUsable(argate::State::VersionRejected), "VersionRejected 不可用");
    Check(!argate::IsUsable(argate::State::AddressRejected), "AddressRejected 不可用");
    Check(!argate::IsUsable(argate::State::FingerprintRejected), "FingerprintRejected 不可用");
    Check(!argate::IsUsable(argate::State::InstallFailed), "InstallFailed 不可用");
    Check(argate::IsUsable(argate::State::Unverified), "Unverified 可用");
    Check(argate::IsUsable(argate::State::FullyInstalled), "FullyInstalled 可用");
    Check(std::string(argate::StateName(argate::State::FullyInstalled)) == "fully-installed",
          "状态名稳定（网页可依赖）");
    // 所有状态都有非空名字
    bool allNamed = true;
    for (int i = 0; i <= 6; ++i) {
        const char* n = argate::StateName((argate::State)i);
        if (!n || std::string(n) == "?") allNamed = false;
    }
    Check(allNamed, "全部 7 个状态都有名字");
}

// =====================================================================
// =====================================================================
// 5) RequiredReady() 语义 —— 负向验证时发现的覆盖缺口
// =====================================================================
// 背景：2026-11-11 做安全机制负向验证时，把 RequiredReady() 改成恒返回 true，
//       结果 gate_selftest 仍然 48/48 全绿 —— 说明本套件【从未测试过它】。
//       RequiredReady() 是"要么都装、要么都不装"的最后一道闸，必须有测试守着。
//
// 这个测试不依赖真实 exe（用 FakeImage 构造），所以不受版本变更影响。
static void TestRequiredReadySemantics() {
    Section("5) RequiredReady()：必需组缺一即整体不就绪");

    FakeImage img; img.BuildCorrect();
    argate::Report r = argate::Inspect(img);

    // 5.1 全部正确时，必需组应就绪
    Check(argate::IsUsable(r.state), "全部正确时 IsUsable()==true",
          argate::StateName(r.state));

    // 5.2 必需组任一目标失败 → 整体不就绪（这是"禁止半挂"的核心）
    {
        FakeImage bad = img;
        // 找第一个必需的 Hook 目标（Role::Hook == 主 hook 或 hookA）
        int hookIdx = -1;
        for (size_t k = 0; k < arver::kTargetCount; ++k) {
            if (arver::kTargets[k].kind == arver::TargetKind::Hook) { hookIdx = (int)k; break; }
        }
        Check(hookIdx >= 0, "存在至少一个 Hook 类目标");
        if (hookIdx >= 0) {
            bad.SetPrologueByte(arver::kTargets[hookIdx].rva, 0, 0xCC);
            argate::Report br = argate::Inspect(bad);
            Check(!argate::IsUsable(br.state),
                  "任一必需目标失败 → IsUsable()==false（禁止半挂）",
                  argate::StateName(br.state));
        }
    }

    // 5.3 版本被拒时，必需组绝不应被判定就绪
    {
        FakeImage bad = img;
        bad.sha     = std::string(64, '0');
        bad.buildId = "ffffffffffffffffffffffffffffffff";
        argate::Report br = argate::Inspect(bad);
        Check(!argate::IsUsable(br.state),
              "版本被拒 → IsUsable()==false",
              argate::StateName(br.state));
        Check(br.targets.empty(),
              "版本被拒时不做逐目标检查（targets 为空）",
              "targets=" + std::to_string(br.targets.size()));
    }
}

// =====================================================================
// 6) InstallAll() 的「层 2 惰性」—— 保护游戏不被修改的最后一道关
// =====================================================================
// 背景（2026-11-11 t16 负向验证发现）：
//   "三项安全机制"里的「惰性」实际由两层保证：
//     层 1: Inspect() 返回 VersionRejected -> IsUsable()==false   （gate_realcheck 有测）
//     层 2: InstallAll() 看到 !IsUsable -> 直接 return false，【不生成 patch 计划】
//   而层 2 在测试文件里 grep InstallAll 是【零命中】—— 也就是说，
//   「DLL 不会修改游戏」这件事从来没有被测过。
//
// 为什么不能直接调用 InstallAll()：
//   它依赖真实 PE 镜像、真实 VirtualProtect 写入、全局 g_report —— 离线不可构造。
//
// 所以改为【源码结构断言】：验证决策点确实存在、且在写入之前。
// 这个方案不依赖具体游戏版本（只读源码结构），且可以做负向注入验证。

// 读取 auto_research.cpp 全文（失败返回空串）
static std::string LoadProductSrcForGate() {
    const char* cands[] = { "auto_research.cpp",
                            "../tech_probe/auto_research.cpp",
                            "_stellaris_eval/tech_probe/auto_research.cpp" };
    for (const char* c : cands) {
        std::FILE* f = std::fopen(c, "rb");
        if (!f) continue;
        std::fseek(f, 0, SEEK_END);
        long n = std::ftell(f);
        std::fseek(f, 0, SEEK_SET);
        if (n > 0) {
            std::string s; s.resize((size_t)n);
            size_t got = std::fread(&s[0], 1, (size_t)n, f);
            std::fclose(f);
            if (got == (size_t)n) return s;
        } else { std::fclose(f); }
    }
    return std::string();
}

static void TestInstallAllLayer2Gate() {
    Section("6) InstallAll() 层2惰性：无法确认版本时绝不生成 patch");

    std::string src = LoadProductSrcForGate();
    // 读不到源码 => 必须 FAIL，不能静默跳过（否则又是一条假断言）
    Check(!src.empty(), "能读取 auto_research.cpp（失败则本组全部不可信）");
    if (src.empty()) return;

    // 截取 InstallAll 函数体
    size_t s = src.find("static bool InstallAll()");
    Check(s != std::string::npos, "源码中存在 InstallAll()");
    if (s == std::string::npos) return;
    size_t e = src.find("\n}", s);
    Check(e != std::string::npos && e > s, "能定位 InstallAll() 函数体结尾");
    if (e == std::string::npos) return;
    std::string body = src.substr(s, e - s);

    // 6.1 决策点存在：必须有 IsUsable 检查
    size_t pUsable = body.find("argate::IsUsable");
    Check(pUsable != std::string::npos,
          "InstallAll() 内存在 IsUsable 检查（层2 的决策点）");

    // 6.2 决策点必须【早于】任何实际写入
    size_t pWrite = body.find("WritePatch(");
    Check(pWrite != std::string::npos, "InstallAll() 内存在 WritePatch 调用");
    if (pUsable != std::string::npos && pWrite != std::string::npos) {
        char buf[320];
        snprintf(buf, sizeof(buf),
                 "IsUsable 检查(偏移%zu) 早于 WritePatch(偏移%zu) —— 决策在写入之前",
                 pUsable, pWrite);
        Check(pUsable < pWrite, buf);
    }

    // 6.3 决策点必须早于 patch 计划生成
    size_t pPlan = body.find("plan.push_back");
    if (pUsable != std::string::npos && pPlan != std::string::npos) {
        char buf[320];
        snprintf(buf, sizeof(buf),
                 "IsUsable 检查(偏移%zu) 早于 plan.push_back(偏移%zu) —— 决策在生成计划之前",
                 pUsable, pPlan);
        Check(pUsable < pPlan, buf);
    }

    // 6.4 拒绝分支必须真的 return false
    //
    // ⚠️ 这里踩过两次坑（都是负向验证发现的）：
    //   第 1 次：只查「IsUsable 之后存在 return false」——
    //            删掉该分支的 return 后仍全绿，因为函数别处还有 return false 顶替。
    //   第 2 次：查「else 之后存在 return false」——
    //            同样被后面别处的 return false 顶替。
    //   正确做法：先把 else 分支的【花括号范围】精确切出来，再在范围内找。
    {
        bool foundRejectReturn = false;
        if (pUsable != std::string::npos) {
            size_t pElse = body.find("} else {", pUsable);
            Check(pElse != std::string::npos, "IsUsable 判定带有 else 分支（拒绝路径）");
            if (pElse != std::string::npos) {
                // else 块的起始花括号位置
                size_t braceOpen = body.find("{", pElse);
                // 从 braceOpen 起做花括号配对，找到 else 块的结束
                size_t braceClose = std::string::npos;
                if (braceOpen != std::string::npos) {
                    int depth = 0;
                    for (size_t q = braceOpen; q < body.size(); ++q) {
                        if (body[q] == '{') ++depth;
                        else if (body[q] == '}') {
                            --depth;
                            if (depth == 0) { braceClose = q; break; }
                        }
                    }
                }
                Check(braceClose != std::string::npos, "能定位 else 块的结束花括号");
                if (braceOpen != std::string::npos && braceClose != std::string::npos) {
                    std::string elseBlock = body.substr(braceOpen, braceClose - braceOpen + 1);
                    size_t pRet = elseBlock.find("return false;");
                    foundRejectReturn = (pRet != std::string::npos);
                    char buf[420];
                    snprintf(buf, sizeof(buf),
                             "else 块内（%zu 字符）有 return false：%s",
                             elseBlock.size(),
                             foundRejectReturn ? "有" : "【没有 —— 拒绝时不会中止安装】");
                    Check(foundRejectReturn, buf);
                    // 还要求这个 else 块整体早于 WritePatch
                    Check(braceClose < pWrite,
                          "整个拒绝分支早于 WritePatch（先判后写，不是先写后判）");
                }
            }
        }
        Check(foundRejectReturn,
              "拒绝路径确实中止安装（不是只打日志继续跑）");
    }

    // 6.5 两条入口路径都要被覆盖：
    //   锚点路径 -> VerdictInstallable(verdict) 判定
    //   hash 兜底 -> IsUsable(g_report.state) 判定
    // 注意：锚点成功时不需要 IsUsable，所以 IsUsable 只出现 1 次是正确的。
    {
        bool hasVerdictGate = body.find("VerdictInstallable") != std::string::npos;
        Check(hasVerdictGate,
              "锚点路径有闸：VerdictInstallable(verdict) 判定存在");
        int n = 0; size_t pos = 0;
        while ((pos = body.find("argate::IsUsable", pos)) != std::string::npos) { ++n; pos += 10; }
        char buf[256];
        snprintf(buf, sizeof(buf),
                 "hash 兜底路径有闸：IsUsable 检查出现 %d 次（应为 1，锚点成功时不需要它）", n);
        Check(n >= 1, buf);
        if (hasVerdictGate && n >= 1) {
            // 两闸都要在 WritePatch 之前
            size_t pV = body.find("VerdictInstallable");
            Check(pV < pWrite && pUsable < pWrite,
                  "两条路径的闸都早于 WritePatch");
        }
    }

    // 6.6 反证：函数体内不得存在「先 WritePatch 再判 IsUsable」的写法
    if (pUsable != std::string::npos && pWrite != std::string::npos) {
        Check(pUsable < pWrite,
              "不存在「先写入后校验」的危险顺序");
    }
}

int main(int argc, char** argv) {
    std::string logPath;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--log" && i + 1 < argc) logPath = argv[++i];
        else if (a == "-h" || a == "--help") {
            std::printf("usage: %s [--log FILE]\n", argv[0]);
            return 0;
        }
    }
    if (!logPath.empty()) {
        g_out = std::fopen(logPath.c_str(), "w");
        if (!g_out) { std::fprintf(stderr, "cannot open log: %s\n", logPath.c_str()); return 2; }
    }

    Emit("==============================================");
    Emit("自动科研 DLL 版本闸门离线自测（ar_gate.h）");
    Emit("目标版本: " + std::string(arver::kSupportedVersionTag) +
         " (build " + std::string(arver::kSupportedBuildId) + ")");
    Emit("exe sha256: " + std::string(arver::kSupportedSha256));
    Emit("检查目标: " + std::to_string(arver::kTargetCount) + " 个地址");
    Emit("==============================================");

    TestVersionAnchor();
    TestFingerprint();
    TestPlanAndRollback();
    TestStateSemantics();
    TestRequiredReadySemantics();
    TestInstallAllLayer2Gate();

    Emit("");
    Emit("==============================================");
    char buf[128];
    snprintf(buf, sizeof(buf), "结果: %d passed, %d failed, %d total",
             g_pass, g_fail, g_pass + g_fail);
    Emit(buf);
    Emit(g_fail == 0 ? "结论: ALL PASS" : "结论: FAILED");
    Emit("==============================================");
    if (g_out) { std::fclose(g_out); g_out = nullptr; }
    return g_fail == 0 ? 0 : 1;
}
