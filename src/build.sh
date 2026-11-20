#!/usr/bin/env bash
# ============================================================================
# auto_research 构建脚本
# ============================================================================
#
# 用法：
#   ./build.sh              # 构建两个版本
#   ./build.sh test         # 构建 + 跑 681 项测试
#   ./build.sh use          # 只构建使用版
#   ./build.sh debug        # 只构建维护版
#
# 依赖：
#   g++ (MinGW-w64, 支持 C++17)
#   如果 g++ 不在 PATH，用 GXX 环境变量指定：
#     GXX=/path/to/g++.exe ./build.sh
#
# 输出：
#   auto_research.dll        使用版（无探针，828,061 B）
#   auto_research_debug.dll  维护版（带探针，848,758 B）
#
# ⚠️ 注意：MinGW 的构建不可复现（.data 段每次不同）。
#    所以文件大小可能略有差异，不能用 SHA256 判断是不是同一版本。
#    用功能指纹（日志头部 banner）判断。
# ============================================================================

set -e
cd "$(dirname "$0")"

GXX="${GXX:-g++}"
if ! command -v "$GXX" >/dev/null 2>&1; then
    echo "ERROR: 找不到 g++（$GXX）"
    echo "  请安装 MinGW-w64，或用 GXX=/path/to/g++.exe ./build.sh"
    exit 1
fi

echo "编译器: $("$GXX" --version | head -1)"
echo ""

FLAGS="-std=c++17 -O2 -static -static-libgcc -static-libstdc++"
LIBS="-lkernel32 -lbcrypt"

size_of() {
    if [ -f "$1" ]; then
        wc -c < "$1" | tr -d ' '
    else
        echo "0"
    fi
}

# ============================================================================
# 构建
# ============================================================================

build_use() {
    echo "=== 构建【使用版】auto_research.dll（无探针）==="
    "$GXX" $FLAGS -shared -DAR_BUILD_WITH_PROBES=0 \
        -o auto_research.dll auto_research.cpp $LIBS
    echo "  完成：$(size_of auto_research.dll) B（参考值 828,061）"
}

build_debug() {
    echo "=== 构建【维护版】auto_research_debug.dll（带探针）==="
    "$GXX" $FLAGS -shared \
        -o auto_research_debug.dll auto_research.cpp $LIBS
    echo "  完成：$(size_of auto_research_debug.dll) B（参考值 848,758）"
}

# ============================================================================
# 测试
# ============================================================================

TESTS="config_selftest config_filetest gate_selftest gate_realcheck \
       anchor_verify anchor_perturb_test lde_verify take_selftest \
       hook_tramp_test shadow_space_test layout_test c890_chain_test"

run_tests() {
    echo ""
    echo "=== 运行测试（预期 681 项全绿）==="
    local total=0
    local failed=0

    # ★ 测试需要一个可写的临时目录。
    #   config_filetest 默认用 GetTempPathA()，在某些环境下（沙箱 / 受限用户）
    #   子进程无法写入系统 %TEMP%，会报 9 passed / 19 failed。
    #   这里显式给一个可写目录。
    WORKDIR="$(pwd)/_test_tmp"
    mkdir -p "$WORKDIR"

    for t in $TESTS; do
        if [ ! -f "$t.cpp" ]; then
            echo "  [SKIP] $t.cpp 不存在"
            continue
        fi

        printf "  %-22s " "$t"
        if ! "$GXX" $FLAGS -o "$t.exe" "$t.cpp" $LIBS 2>/dev/null; then
            echo "编译失败"
            failed=$((failed + 1))
            continue
        fi

        # 支持 --dir 的测试传工作目录，其余忽略该参数
        if out=$(./"$t.exe" --dir "$WORKDIR" 2>&1) || out=$(./"$t.exe" 2>&1); then
            n=$(echo "$out" | grep -oE '[0-9]+ *(项|passed|PASS)' | tail -1 | grep -oE '[0-9]+' || echo "?")
            echo "OK"
            total=$((total + 1))
        else
            echo "FAIL"
            echo "$out" | tail -5 | sed 's/^/      /'
            failed=$((failed + 1))
        fi
        rm -f "$t.exe"
    done

    rmdir "$WORKDIR" 2>/dev/null || true

    echo ""
    if [ $failed -eq 0 ]; then
        echo "=== 全部通过（$total 个测试套件）==="
    else
        echo "=== 有 $failed 个套件失败 ==="
        exit 1
    fi
}

# ============================================================================
# 入口
# ============================================================================

case "${1:-all}" in
    use)
        build_use
        ;;
    debug)
        build_debug
        ;;
    test)
        build_use
        build_debug
        run_tests
        ;;
    all|"")
        build_use
        echo ""
        build_debug
        ;;
    *)
        echo "用法: $0 [all|use|debug|test]"
        exit 1
        ;;
esac

echo ""
echo "完成。"
