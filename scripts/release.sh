#!/bin/bash

# GatTrace 发布脚本
# 创建完整的发布包，包括文档、示例和安装脚本

set -e

# 项目信息
PROJECT_NAME="GatTrace"
VERSION=${VERSION:-"1.1.1"}
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT=${GIT_COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")}

# 目录配置
BUILD_DIR="dist"
RELEASE_DIR="release"
DOCS_DIR="docs"

# 函数定义
create_install_instructions() {
    local dir=$1
    local platform=$2
    
    if [[ $platform == windows-* ]]; then
        cat > "${dir}/INSTALL.txt" << 'EOF'
GatTrace Windows 安装说明
========================

1. 解压文件到目标目录
2. 将 GatTrace.exe 添加到系统 PATH 环境变量
3. 打开命令提示符或 PowerShell
4. 运行: GatTrace --help

使用示例:
  GatTrace --output C:\GatTrace\output
  GatTrace --silent --output C:\GatTrace\output

注意事项:
- 需要管理员权限以获取完整的系统信息
- 建议在安全的环境中运行
- 输出文件包含敏感的系统信息，请妥善保管
EOF
    else
        cat > "${dir}/INSTALL.md" << 'EOF'
# GatTrace 安装说明

## 安装步骤

1. 解压文件到目标目录：
   ```bash
   tar -xzf GatTrace-*.tar.gz
   cd GatTrace-*
   ```

2. 复制到系统路径（可选）：
   ```bash
   sudo cp GatTrace /usr/local/bin/
   sudo chmod +x /usr/local/bin/GatTrace
   ```

3. 验证安装：
   ```bash
   GatTrace --version
   ```

## 使用示例

```bash
# 显示帮助
GatTrace --help

# 基本使用
GatTrace --output ./output

# 静默模式
GatTrace --silent --output ./output

# 详细模式
GatTrace --verbose --output ./output
```

## 注意事项

- 某些功能需要 root 权限以获取完整的系统信息
- 建议在安全的环境中运行
- 输出文件包含敏感的系统信息，请妥善保管
- 支持的操作系统：Linux、macOS、Windows
EOF
    fi
}

create_example_config() {
    local dir=$1
    
    cat > "${dir}/example-config.json" << 'EOF'
{
  "output_directory": "./GatTrace-output",
  "silent_mode": false,
  "verbose_mode": false,
  "collectors": {
    "network": true,
    "processes": true,
    "users": true,
    "persistence": true,
    "filesystem": true,
    "security_logs": true,
    "system_info": true
  },
  "filters": {
    "exclude_system_processes": false,
    "max_file_scan_depth": 3,
    "log_time_range_hours": 24
  },
  "output_formats": {
    "json": true,
    "html": true,
    "csv": false
  }
}
EOF
}

create_release_notes() {
    cat > "${RELEASE_DIR}/RELEASE_NOTES.md" << EOF
# GatTrace ${VERSION} 发布说明

发布时间: ${BUILD_TIME}
Git提交: ${GIT_COMMIT}

## 新功能

- ✅ 跨平台系统信息采集（Windows、Linux、macOS）
- ✅ 网络信息采集（接口、连接、路由、DNS）
- ✅ 进程信息采集（进程列表、可执行文件哈希）
- ✅ 用户权限采集（当前用户、登录历史、SSH密钥）
- ✅ 持久化机制检测（自启动项、服务、计划任务）
- ✅ 文件系统扫描（最近文件、元数据）
- ✅ 安全日志采集（平台特定日志源）
- ✅ 系统状态监控（启动时间、NTP状态、内核模块）
- ✅ HTML 报告生成（交互式界面）
- ✅ 只读操作保证（不修改系统状态）
- ✅ 权限透明处理（优雅降级）
- ✅ 错误管理和恢复

## 技术特性

- 🔒 只读操作，不修改系统状态
- 🛡️ 权限检测和优雅降级
- 📊 结构化 JSON 输出
- 🌐 交互式 HTML 报告
- 🔐 文件完整性验证（SHA256）
- ⏱️ ISO 8601 时间戳标准化
- 🎯 会话唯一性保证
- 📝 详细错误报告

## 支持的平台

- Windows (amd64, arm64)
- Linux (amd64, arm64)
- macOS (amd64, arm64)

## 安装方法

1. 下载对应平台的压缩包
2. 解压到目标目录
3. 参考 INSTALL 文件进行安装

## 使用示例

\`\`\`bash
# 基本使用
GatTrace --output ./output

# 静默模式
GatTrace --silent --output ./output

# 查看帮助
GatTrace --help
\`\`\`

## 校验和

请使用 checksums.txt 文件验证下载文件的完整性：

\`\`\`bash
sha256sum -c checksums.txt
\`\`\`

## 注意事项

- 某些功能需要管理员/root权限
- 输出文件包含敏感系统信息，请妥善保管
- 建议在安全环境中运行

## 支持

如有问题或建议，请提交 Issue 或 Pull Request。
EOF
}

echo "🚀 开始创建发布包..."
echo "版本: ${VERSION}"
echo "构建时间: ${BUILD_TIME}"
echo "Git提交: ${GIT_COMMIT}"
echo ""

# 清理并创建发布目录
echo "🧹 准备发布目录..."
rm -rf ${RELEASE_DIR}
mkdir -p ${RELEASE_DIR}

# 确保构建目录存在
if [ ! -d "${BUILD_DIR}" ]; then
    echo "❌ 构建目录不存在，请先运行构建"
    exit 1
fi

# 创建各平台发布包
PLATFORMS=(
    "windows-amd64"
    "windows-arm64"
    "linux-amd64"
    "linux-arm64"
    "darwin-amd64"
    "darwin-arm64"
)

for platform in "${PLATFORMS[@]}"; do
    echo "📦 创建 ${platform} 发布包..."
    
    # 创建平台目录
    platform_dir="${RELEASE_DIR}/${PROJECT_NAME}-${VERSION}-${platform}"
    mkdir -p "${platform_dir}"
    
    # 复制二进制文件
    binary_name="${PROJECT_NAME}-${platform}"
    if [[ $platform == windows-* ]]; then
        binary_name="${binary_name}.exe"
    fi
    
    if [ -f "${BUILD_DIR}/${binary_name}" ]; then
        cp "${BUILD_DIR}/${binary_name}" "${platform_dir}/${PROJECT_NAME}"
        if [[ $platform == windows-* ]]; then
            mv "${platform_dir}/${PROJECT_NAME}" "${platform_dir}/${PROJECT_NAME}.exe"
        fi
    else
        echo "⚠️  警告: 未找到 ${binary_name}，跳过"
        continue
    fi
    
    # 复制文档
    cp README.md "${platform_dir}/" 2>/dev/null || echo "README.md" > "${platform_dir}/README.md"
    cp LICENSE "${platform_dir}/" 2>/dev/null || echo "MIT License" > "${platform_dir}/LICENSE"
    
    # 创建版本信息文件
    cat > "${platform_dir}/VERSION" << EOF
GatTrace ${VERSION}
构建时间: ${BUILD_TIME}
Git提交: ${GIT_COMMIT}
平台: ${platform}
EOF
    
    # 创建安装说明
    create_install_instructions "${platform_dir}" "${platform}"
    
    # 创建示例配置
    create_example_config "${platform_dir}"
    
    # 创建压缩包
    cd "${RELEASE_DIR}"
    if [[ $platform == windows-* ]]; then
        # Windows 使用 zip
        if command -v zip >/dev/null 2>&1; then
            zip -r "${PROJECT_NAME}-${VERSION}-${platform}.zip" "${PROJECT_NAME}-${VERSION}-${platform}/"
        else
            tar -czf "${PROJECT_NAME}-${VERSION}-${platform}.tar.gz" "${PROJECT_NAME}-${VERSION}-${platform}/"
        fi
    else
        # Unix 系统使用 tar.gz
        tar -czf "${PROJECT_NAME}-${VERSION}-${platform}.tar.gz" "${PROJECT_NAME}-${VERSION}-${platform}/"
    fi
    cd ..
    
    echo "   ✅ 完成: ${platform}"
done

# 生成发布说明
echo "📝 生成发布说明..."
create_release_notes

# 生成校验和
echo "🔐 生成校验和文件..."
cd "${RELEASE_DIR}"
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum *.tar.gz *.zip 2>/dev/null > checksums.txt || true
elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 *.tar.gz *.zip 2>/dev/null > checksums.txt || true
else
    echo "⚠️  警告: 无法生成校验和文件"
fi
cd ..

echo ""
echo "🎉 发布包创建完成！"
echo "发布文件位于: ${RELEASE_DIR}/"
ls -la "${RELEASE_DIR}/"