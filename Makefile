# GatTrace Makefile
# 跨平台应急响应系统信息采集工具

# 项目信息
PROJECT_NAME := GatTrace
VERSION ?= 1.1.1
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# 构建配置
BUILD_DIR := release
BINARY_NAME := GatTrace
LDFLAGS := -s -w -X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -X main.GitCommit=$(GIT_COMMIT)

# Go 配置
GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
GOTEST := $(GOCMD) test
GOGET := $(GOCMD) get
GOMOD := $(GOCMD) mod

# 默认目标
.PHONY: all
all: clean test build

# 清理
.PHONY: clean
clean:
	@echo "🧹 清理构建文件..."
	@rm -rf $(BUILD_DIR)
	@$(GOCLEAN)

# 依赖管理
.PHONY: deps
deps:
	@echo "📦 下载依赖..."
	@$(GOMOD) download
	@$(GOMOD) tidy

# 测试
.PHONY: test
test:
	@echo "🧪 运行测试..."
	@$(GOTEST) -v -timeout 120s ./...

# 快速测试（跳过慢速测试）
.PHONY: test-fast
test-fast:
	@echo "⚡ 运行快速测试..."
	@$(GOTEST) -v -timeout 60s -short ./...

# 本地构建（当前平台）
.PHONY: build
build:
	@echo "🔨 构建本地版本..."
	@mkdir -p $(BUILD_DIR)
	@$(GOBUILD) -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/GatTrace
	@echo "✅ 构建完成: $(BUILD_DIR)/$(BINARY_NAME)"

# 跨平台构建
.PHONY: build-all
build-all:
	@echo "🚀 开始跨平台构建..."
	@./scripts/build.sh

# Windows 构建
.PHONY: build-windows
build-windows:
	@echo "🔨 构建 Windows 版本..."
	@mkdir -p $(BUILD_DIR)
	@GOOS=windows GOARCH=amd64 $(GOBUILD) -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/GatTrace
	@GOOS=windows GOARCH=arm64 $(GOBUILD) -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-windows-arm64.exe ./cmd/GatTrace

# Linux 构建
.PHONY: build-linux
build-linux:
	@echo "🔨 构建 Linux 版本..."
	@mkdir -p $(BUILD_DIR)
	@GOOS=linux GOARCH=amd64 $(GOBUILD) -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/GatTrace
	@GOOS=linux GOARCH=arm64 $(GOBUILD) -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/GatTrace

# macOS 构建
.PHONY: build-darwin
build-darwin:
	@echo "🔨 构建 macOS 版本..."
	@mkdir -p $(BUILD_DIR)
	@GOOS=darwin GOARCH=amd64 $(GOBUILD) -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/GatTrace
	@GOOS=darwin GOARCH=arm64 $(GOBUILD) -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/GatTrace

# 运行
.PHONY: run
run: build
	@echo "🚀 运行 GatTrace..."
	@./$(BUILD_DIR)/$(BINARY_NAME) --help

# 安装
.PHONY: install
install:
	@echo "📦 安装 GatTrace..."
	@$(GOBUILD) -ldflags="$(LDFLAGS)" -o $(GOPATH)/bin/$(BINARY_NAME) ./cmd/GatTrace

# 开发模式
.PHONY: dev
dev:
	@echo "🔧 开发模式..."
	@$(GOBUILD) -race -o $(BUILD_DIR)/$(BINARY_NAME)-dev ./cmd/GatTrace

# 代码格式化
.PHONY: fmt
fmt:
	@echo "🎨 格式化代码..."
	@$(GOCMD) fmt ./...

# 代码检查
.PHONY: vet
vet:
	@echo "🔍 代码检查..."
	@$(GOCMD) vet ./...

# 完整检查
.PHONY: check
check: fmt vet test

# 生成文档
.PHONY: docs
docs:
	@echo "📚 生成文档..."
	@$(GOCMD) doc -all ./...

# 显示版本信息
.PHONY: version
version:
	@echo "项目: $(PROJECT_NAME)"
	@echo "版本: $(VERSION)"
	@echo "构建时间: $(BUILD_TIME)"
	@echo "Git提交: $(GIT_COMMIT)"

# 显示帮助
.PHONY: help
help:
	@echo "GatTrace 构建系统"
	@echo ""
	@echo "可用目标:"
	@echo "  all          - 清理、测试、构建"
	@echo "  clean        - 清理构建文件"
	@echo "  deps         - 下载依赖"
	@echo "  test         - 运行所有测试"
	@echo "  test-fast    - 运行快速测试"
	@echo "  build        - 构建本地版本"
	@echo "  build-all    - 跨平台构建"
	@echo "  build-windows- 构建 Windows 版本"
	@echo "  build-linux  - 构建 Linux 版本"
	@echo "  build-darwin - 构建 macOS 版本"
	@echo "  run          - 构建并运行"
	@echo "  install      - 安装到 GOPATH"
	@echo "  dev          - 开发模式构建"
	@echo "  fmt          - 格式化代码"
	@echo "  vet          - 代码检查"
	@echo "  check        - 完整检查"
	@echo "  docs         - 生成文档"
	@echo "  version      - 显示版本信息"
	@echo "  help         - 显示此帮助"