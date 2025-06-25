#!/bin/bash

# Android ARM64 构建测试脚本
# 用于本地测试 Android 构建配置

set -euo pipefail

echo "🔧 Android ARM64 构建测试脚本"
echo "================================"

# 检查必要的环境变量
if [ -z "${ANDROID_NDK_HOME:-}" ]; then
    echo "❌ 错误: ANDROID_NDK_HOME 环境变量未设置"
    echo "请设置 Android NDK 路径，例如:"
    echo "export ANDROID_NDK_HOME=/path/to/android-ndk-r28"
    exit 1
fi

echo "📍 Android NDK 路径: $ANDROID_NDK_HOME"

# 检查 NDK 工具链
TOOLCHAIN_DIR="${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/bin"
CC="${TOOLCHAIN_DIR}/aarch64-linux-android21-clang"
CXX="${TOOLCHAIN_DIR}/aarch64-linux-android21-clang++"
AR="${TOOLCHAIN_DIR}/llvm-ar"
STRIP="${TOOLCHAIN_DIR}/llvm-strip"

echo "🔍 检查工具链..."
if [ ! -f "$CC" ]; then
    echo "❌ 错误: 未找到 Android 编译器: $CC"
    echo "可用的编译器:"
    ls -la "$TOOLCHAIN_DIR" | grep aarch64 || echo "未找到 aarch64 编译器"
    exit 1
fi

if [ ! -f "$AR" ]; then
    echo "❌ 错误: 未找到 AR 工具: $AR"
    exit 1
fi

echo "✅ 工具链检查通过"
echo "  CC: $CC"
echo "  CXX: $CXX"
echo "  AR: $AR"
echo "  STRIP: $STRIP"

# 测试编译器
echo "🧪 测试编译器..."
$CC --version

# 检查 Go 环境
echo "🐹 检查 Go 环境..."
go version
echo "Go 环境变量:"
go env GOOS GOARCH CGO_ENABLED

# 安装构建工具
echo "🔨 安装构建工具..."
if ! command -v build &> /dev/null; then
    echo "安装 sing-box 构建工具..."
    go install -v ./cmd/internal/build
fi

which build
build --help || echo "构建工具安装完成"

# 设置环境变量
export CGO_ENABLED=1
export GOOS=linux
export GOARCH=arm64
export CC="$CC"
export CXX="$CXX"
export AR="$AR"
export STRIP="$STRIP"
export CGO_CFLAGS="-D__ANDROID_API__=21"
export CGO_LDFLAGS="-D__ANDROID_API__=21"

# 构建标签
BUILD_TAGS="with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_tailscale"

echo "🏗️ 开始构建测试..."
echo "构建标签: $BUILD_TAGS"
echo "环境变量:"
echo "  CGO_ENABLED=$CGO_ENABLED"
echo "  GOOS=$GOOS"
echo "  GOARCH=$GOARCH"
echo "  CC=$CC"

# 创建测试目录
mkdir -p test_build

# 执行构建
echo "🚀 执行构建..."
build go build -v -trimpath -o test_build/sing-box \
    -tags "$BUILD_TAGS" \
    -ldflags "-s -w -buildid= -X github.com/sagernet/sing-box/constant.Version=test-build" \
    ./cmd/sing-box

# 验证构建结果
echo "✅ 构建完成，验证结果..."
ls -la test_build/
file test_build/sing-box

# 检查文件类型
if file test_build/sing-box | grep -q "ARM aarch64"; then
    echo "✅ 构建成功: ARM64 二进制文件"
else
    echo "⚠️  警告: 文件类型可能不正确"
    file test_build/sing-box
fi

# 设置可执行权限
chmod +x test_build/sing-box

echo "🎉 Android ARM64 构建测试完成!"
echo "生成的文件: test_build/sing-box"

# 清理测试文件（可选）
read -p "是否删除测试文件? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf test_build
    echo "🗑️  测试文件已删除"
else
    echo "📁 测试文件保留在: test_build/"
fi
