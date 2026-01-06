#!/bin/bash

# GatTrace 跨平台构建脚本
# 
# 重要说明：
# 为了兼容 Windows 7，必须使用 Go 1.20 或更早版本构建
# Go 1.21+ 的运行时依赖 bcryptprimitives.dll (仅 Windows 10+ 可用)
#
# 使用方法：
# 1. 使用 gvm: source ~/.gvm/scripts/gvm && gvm use go1.20 && ./scripts/build.sh
# 2. 或确保系统 Go 版本为 1.20 或更早

set -e

# 检查 Go 版本
GO_VERSION=$(go version | grep -oE 'go1\.[0-9]+' | head -1)
echo "🔍 检测到 Go 版本: $GO_VERSION"

if [[ "$GO_VERSION" > "go1.20" ]]; then
    echo "⚠️  警告: Go $GO_VERSION 构建的 Windows 版本不兼容 Windows 7"
    echo "   建议使用 Go 1.20: gvm use go1.20"
    echo ""
fi

# 项目信息
PROJECT_NAME="GatTrace"
VERSION=${VERSION:-"1.2.0"}
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT=${GIT_COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")}

# 构建目录
BUILD_DIR="release"
BINARY_NAME="GatTrace"

# 支持的平台
PLATFORMS=(
    "windows/amd64"
    "windows/386"
    "windows/arm64"
    "linux/amd64"
    "linux/386"
    "linux/arm64"
    "linux/arm"
    "darwin/amd64"
    "darwin/arm64"
)

# 清理构建目录
echo "🧹 清理构建目录..."
rm -rf ${BUILD_DIR}
mkdir -p ${BUILD_DIR}

# 构建标志
# -trimpath 移除编译路径信息，保护隐私
LDFLAGS="-s -w -X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME} -X main.GitCommit=${GIT_COMMIT}"
BUILDFLAGS="-trimpath"

echo "🚀 开始跨平台构建..."
echo "版本: ${VERSION}"
echo "构建时间: ${BUILD_TIME}"
echo "Git提交: ${GIT_COMMIT}"
echo ""

# 遍历所有平台进行构建
for platform in "${PLATFORMS[@]}"; do
    platform_split=(${platform//\// })
    GOOS=${platform_split[0]}
    GOARCH=${platform_split[1]}
    
    output_name=${BINARY_NAME}
    if [ $GOOS = "windows" ]; then
        output_name+='.exe'
    fi
    
    output_path="${BUILD_DIR}/${BINARY_NAME}-${GOOS}-${GOARCH}"
    if [ $GOOS = "windows" ]; then
        output_path+='.exe'
    fi
    
    echo "🔨 构建 ${GOOS}/${GOARCH}..."
    
    env GOOS=$GOOS GOARCH=$GOARCH go build \
        ${BUILDFLAGS} \
        -ldflags="${LDFLAGS}" \
        -o ${output_path} \
        ./cmd/GatTrace
    
    if [ $? -ne 0 ]; then
        echo "❌ 构建失败: ${GOOS}/${GOARCH}"
        exit 1
    fi
    
    # 显示文件大小
    if command -v ls >/dev/null 2>&1; then
        size=$(ls -lh ${output_path} | awk '{print $5}')
        echo "   ✅ 完成 (${size})"
    else
        echo "   ✅ 完成"
    fi
done

echo ""
echo "🎉 所有平台构建完成！"
echo "构建文件位于: ${BUILD_DIR}/"
ls -la ${BUILD_DIR}/

# 生成校验和文件
echo ""
echo "🔐 生成校验和文件..."
cd ${BUILD_DIR}
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum * > checksums.txt
elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 * > checksums.txt
else
    echo "⚠️  警告: 无法生成校验和文件 (缺少 sha256sum 或 shasum)"
fi
cd ..

echo "✅ 构建完成！"