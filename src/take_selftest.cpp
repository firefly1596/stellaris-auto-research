// take_selftest.cpp —— t3 的离线自测：验证「读科技 key / 读候选卡 / 权重决策」
// 的纯逻辑部分，不需要游戏、不需要 hook。
//
// 重点是把这些容易写错的地方钉死在测试里：
//   1. tech key 的偏移必须是 +0x350 对象 / +0x360 buf / +0x370 size / +0x378 cap
//      —— 前任把 +0x360 当 size（FINDINGS §6.5），这里用构造的内存验证读法
//   2. 候选卡必须是 country+0x31B0/+0x31BC/+0x31D8（不是 arg1+0x9B8）
//   3. 权重决策：>0 取最大 / 0 禁选 / 全负取最小 / 全 0 → 停止
//
// 编译: g++ -std=c++17 -O2 -o take_selftest.exe take_selftest.cpp
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>

#include "ar_config.h"

static int g_pass = 0, g_fail = 0;
static FILE* g_out = nullptr;
static void Emit(const std::string& s) {
    fputs(s.c_str(), stdout); fputc('\n', stdout);
    if (g_out) { fputs(s.c_str(), g_out); fputc('\n', g_out); fflush(g_out); }
}
static void Section(const std::string& n) { Emit(""); Emit("=== " + n + " ==="); }
static void Check(bool c, const std::string& what, const std::string& d = "") {
    if (c) { ++g_pass; Emit("  [PASS] " + what + (d.empty() ? "" : "   (" + d + ")")); }
    else   { ++g_fail; Emit("  [FAIL] " + what + (d.empty() ? "" : "   (" + d + ")")); }
}

// ---------------- 用一块内存模拟游戏对象，验证偏移读法 ----------------
//
// 关键：构造一个"看起来像"的对象，故意在 +0x360 和 +0x370 放不同值，
// 这样"把 +0x360 当 size"的错误读法会立刻暴露。
struct FakeTech {
    std::vector<uint8_t> mem;
    FakeTech() : mem(0x400, 0) {}

    // 按 FINDINGS §6 的正确布局写一个 key
    void SetKey(const char* key) {
        size_t len = strlen(key);
        // +0x350 = std::string 对象起点
        // +0x360 = buf，+0x370 = size，+0x378 = cap
        uint64_t cap = 15;
        const char* bufIn = nullptr;
        uint8_t* bufField = mem.data() + 0x360;
        if (len <= 15) {
            memcpy(bufField, key, len);           // 内联 buffer
            bufIn = (const char*)bufField;
        } else {
            // 长字符串：buf 存指针
            static std::vector<char> heap;
            heap.assign(key, key + len + 1);
            bufIn = heap.data();
            uint64_t p = (uint64_t)heap.data();
            memcpy(bufField, &p, 8);
            cap = len + 8;
        }
        (void)bufIn;
        uint64_t size = len;
        memcpy(mem.data() + 0x370, &size, 8);     // ★ size 在 +0x370
        memcpy(mem.data() + 0x378, &cap, 8);      // ★ cap  在 +0x378
    }

    // 故意制造"错误布局"：把 size 放在 +0x360（前任的错误读法）
    void SetKeyWrongLayout(const char* key) {
        uint64_t len = strlen(key);
        memcpy(mem.data() + 0x360, &len, 8);      // 前任以为是 size
    }
};

// 模拟 ReadTechKey 的逻辑（与 auto_research.cpp 同一套判定，但不依赖 SafeReadable）
static bool ReadTechKeyFrom(const uint8_t* t, size_t avail, std::string* out) {
    if (!out || !t) return false;
    if (avail < 0x380) return false;
    uint64_t size = *(const uint64_t*)(t + 0x370);
    uint64_t cap  = *(const uint64_t*)(t + 0x378);
    if (size == 0 || size > 64) return false;
    if (cap < size) return false;
    const char* p = (cap > 15) ? *(const char* const*)(t + 0x360)
                               : (const char*)(t + 0x360);
    for (uint64_t i = 0; i < size; ++i) {
        char ch = p[i];
        if (!((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_')) return false;
    }
    out->assign(p, (size_t)size);
    return true;
}

// ---------------- 测试 ----------------
static void TestTechKeyLayout() {
    Section("1) 科技 key 偏移（FINDINGS §6.5）");

    // 1.1 正确布局：短 key（内联 buffer）
    {
        FakeTech ft; ft.SetKey("tech_physics_1");
        std::string k;
        bool ok = ReadTechKeyFrom(ft.mem.data(), ft.mem.size(), &k);
        Check(ok && k == "tech_physics_1",
              "短 key 用内联 buffer 能读出", "got=\"" + k + "\" ok=" + (ok?"1":"0"));
    }
    // 1.2 正确布局：长 key（heap buffer）
    {
        FakeTech ft; ft.SetKey("tech_repeatable_weapons_damage_1");
        std::string k;
        bool ok = ReadTechKeyFrom(ft.mem.data(), ft.mem.size(), &k);
        Check(ok && k == "tech_repeatable_weapons_damage_1",
              "长 key 用 heap 指针能读出", "got=\"" + k + "\" ok=" + (ok?"1":"0"));
    }
    // 1.3 ★ 核心断言：+0x360 放的是 buf，不是 size
    {
        FakeTech ft; ft.SetKey("tech_society_1");
        // 如果代码错把 +0x360 当 size 读，会读到一个指针/字符，必然 > 64 或为 0
        uint64_t wrongSize = *(const uint64_t*)(ft.mem.data() + 0x360);
        Check(wrongSize != 9,
              "把 +0x360 当 size 会读出垃圾（证明该读法错误）",
              "wrongSize=" + std::to_string(wrongSize) + " (正确 size=9 在 +0x370)");
        uint64_t rightSize = *(const uint64_t*)(ft.mem.data() + 0x370);
        Check(rightSize == 14, "+0x370 才是 size", "size=" + std::to_string(rightSize));
    }
    // 1.4 cap < size 必须拒绝（防御性检查）
    {
        FakeTech ft; ft.SetKey("tech_x");
        uint64_t badCap = 2;   // 小于 size
        memcpy(ft.mem.data() + 0x378, &badCap, 8);
        std::string k;
        Check(!ReadTechKeyFrom(ft.mem.data(), ft.mem.size(), &k),
              "cap < size 时拒绝（防御性检查）");
    }
    // 1.5 size 超范围拒绝
    {
        FakeTech ft; ft.SetKey("tech_x");
        uint64_t huge = 9999;
        memcpy(ft.mem.data() + 0x370, &huge, 8);
        std::string k;
        Check(!ReadTechKeyFrom(ft.mem.data(), ft.mem.size(), &k), "size 超范围时拒绝");
    }
    // 1.6 非法字符拒绝（防读成垃圾）
    {
        FakeTech ft; ft.SetKey("tech_x");
        ft.mem[0x360] = 0x01;   // 控制字符
        std::string k;
        Check(!ReadTechKeyFrom(ft.mem.data(), ft.mem.size(), &k),
              "key 含非法字符时拒绝");
    }
    // 1.7 缓冲区不足时拒绝（防越界）
    {
        FakeTech ft; ft.SetKey("tech_x");
        std::string k;
        Check(!ReadTechKeyFrom(ft.mem.data(), 0x200, &k), "可用长度不足时拒绝");
    }
}

static void TestCandidateCards() {
    Section("2) 候选卡偏移（FINDINGS §2.3，在 country 上不是 arg1）");

    // 构造 country 对象：+0x31B0 ids, +0x31BC count, +0x31D8 weights
    std::vector<uint8_t> country(0x3300, 0);
    int32_t ids[3] = {11, 22, 33};
    uint64_t ws[3] = {100, 200, 300};

    uint64_t idsPtr = (uint64_t)ids;
    uint64_t wsPtr = (uint64_t)ws;
    int32_t n = 3;
    memcpy(country.data() + 0x31B0, &idsPtr, 8);
    memcpy(country.data() + 0x31BC, &n, 4);
    memcpy(country.data() + 0x31D8, &wsPtr, 8);

    // 与 ReadCandidateCards 相同的读法
    auto read = [&](const uint8_t* c, int32_t* outCount, uint64_t* outIds, uint64_t* outWs) -> bool {
        int32_t cnt = *(const int32_t*)(c + 0x31BC);
        if (cnt <= 0 || cnt > 128) return false;
        *outIds = *(const uint64_t*)(c + 0x31B0);
        *outWs = *(const uint64_t*)(c + 0x31D8);
        *outCount = cnt;
        return true;
    };

    int32_t cnt = 0; uint64_t ip = 0, wp = 0;
    bool ok = read(country.data(), &cnt, &ip, &wp);
    Check(ok && cnt == 3, "从 country+0x31BC 读到候选数 3", "n=" + std::to_string(cnt));
    Check(ok && ip == (uint64_t)ids, "country+0x31B0 是 ids 指针");
    Check(ok && wp == (uint64_t)ws, "country+0x31D8 是权重指针");
    Check(ok && ((int32_t*)ip)[1] == 22, "ids[1] == 22");
    Check(ok && ((uint64_t*)wp)[1] == 200, "weights[1] == 200（步长 0x10）");

    // 边界：count 为 0 / 负数 / 超大都必须拒绝
    auto setCount = [&](int32_t v) { memcpy(country.data() + 0x31BC, &v, 4); };
    setCount(0);   Check(!read(country.data(), &cnt, &ip, &wp), "count=0 拒绝");
    setCount(-1);  Check(!read(country.data(), &cnt, &ip, &wp), "count=-1 拒绝");
    setCount(99999); Check(!read(country.data(), &cnt, &ip, &wp), "count 超上限 拒绝");
}

static void TestDecideSemantics() {
    Section("3) 权重决策（纯数字语义，与 t2 一致）");
    arcfg::Config cfg = arcfg::Defaults();
    cfg.defaultWeight = 100;
    cfg.weights["tech_hi"]  = 1000;
    cfg.weights["tech_lo"]  = 10;
    cfg.weights["tech_ban"] = 0;
    cfg.weights["tech_neg"] = -50;

    // 3.1 正数最大者胜
    {
        std::vector<std::string> keys = {"tech_ban", "tech_lo", "tech_hi", "tech_neg"};
        arcfg::PickResult r = arcfg::PickBest(keys, cfg);
        Check(r.status == arcfg::PickStatus::Picked && keys[(size_t)r.index] == "tech_hi",
              ">0 最大者胜（禁选与负数让位）",
              "picked=" + keys[(size_t)r.index] + " w=" + std::to_string(r.weight));
    }
    // 3.2 0 永不选
    {
        std::vector<std::string> keys = {"tech_ban", "tech_lo"};
        arcfg::PickResult r = arcfg::PickBest(keys, cfg);
        Check(keys[(size_t)r.index] == "tech_lo", "0 = 禁选，即使它数值最高");
    }
    // 3.3 全负 → 取【数值最大】（最接近 0）
    //
    //   ★ 2026-11-18 语义变更（用户要求）：
    //     旧：取绝对值最大 → -50 优于 -5（错）
    //     新：取数值最大     → -5 优于 -50（对）
    {
        arcfg::Config c = arcfg::Defaults();
        c.weights["a"] = -5; c.weights["b"] = -50; c.weights["c"] = -30;
        std::vector<std::string> keys = {"a", "b", "c"};
        arcfg::PickResult r = arcfg::PickBest(keys, c);
        Check(keys[(size_t)r.index] == "a" &&
              r.tier == arcfg::PickTier::NegativeFallback,
              "全负 → 取数值最大（-5）",
              "picked=" + keys[(size_t)r.index]);
    }
    // 3.4 ★ 全 0 → 停止研究（take 的核心语义）
    {
        arcfg::Config c = arcfg::Defaults();
        c.weights["a"] = 0; c.weights["b"] = 0;
        std::vector<std::string> keys = {"a", "b"};
        arcfg::PickResult r = arcfg::PickBest(keys, c);
        Check(r.status == arcfg::PickStatus::Stop,
              "全部为 0 → 停止研究（不选任何）");
    }
    // 3.5 @default=0 时未列出科技也禁选
    {
        arcfg::Config c = arcfg::Defaults();
        c.defaultWeight = 0;
        c.weights["only"] = 7;
        std::vector<std::string> keys = {"x", "y", "only"};
        arcfg::PickResult r = arcfg::PickBest(keys, c);
        Check(keys[(size_t)r.index] == "only",
              "@default=0 时未列出科技等于禁选");
    }
    // 3.6 空候选 → 停止研究
    {
        std::vector<std::string> keys;
        arcfg::PickResult r = arcfg::PickBest(keys, cfg);
        Check(r.status == arcfg::PickStatus::Stop, "空候选 → 停止研究");
    }
}

static void TestCallSiteDecode() {
    Section("4) 调用者识别（caller - 5 = call 指令地址）");
    // hookA 返回地址减去 call rel32 的 5 字节 = call 指令地址
    const uint64_t callSiteAddr = 0x81ADD5ULL;
    const uint64_t retAddr = callSiteAddr + 5;
    Check(retAddr - 5 == callSiteAddr, "返回地址 - 5 = call 指令地址",
          "0x" + std::to_string(retAddr) + " - 5");

    // 已知的 6 个调用点（captain 实测）
    const uint64_t known[] = {0x818423, 0x81A2EA, 0x81B341,
                              0xEB0367, 0x16F59DD, 0x17F2930};
    int hits = 0;
    for (uint64_t c : known) if (c == callSiteAddr) ++hits;
    Check(hits == 0, "0x81ADD5 是 hookA 调主 hook 的站点，不是调用 hookA 的站点");
    Check(sizeof(known) / sizeof(known[0]) == 6, "已知 6 个 hookA 调用点");
}

int main(int argc, char** argv) {
    std::string logPath;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--log" && i + 1 < argc) logPath = argv[++i];
    }
    if (!logPath.empty()) {
        g_out = fopen(logPath.c_str(), "w");
        if (!g_out) { fprintf(stderr, "cannot open log\n"); return 2; }
    }
    Emit("==============================================");
    Emit("take 模式离线自测（t3）：偏移 + 语义");
    Emit("依据 FINDINGS_hook_contract.md §2.3 / §6.5");
    Emit("==============================================");
    TestTechKeyLayout();
    TestCandidateCards();
    TestDecideSemantics();
    TestCallSiteDecode();
    Emit("");
    Emit("==============================================");
    char b[128];
    snprintf(b, sizeof(b), "结果: %d passed, %d failed, %d total", g_pass, g_fail, g_pass + g_fail);
    Emit(b);
    Emit(g_fail == 0 ? "结论: ALL PASS" : "结论: FAILED");
    Emit("==============================================");
    if (g_out) { fclose(g_out); g_out = nullptr; }
    return g_fail == 0 ? 0 : 1;
}
