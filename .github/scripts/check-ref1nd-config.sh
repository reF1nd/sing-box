#!/bin/bash

# reF1nd 工作流配置检查脚本
# 用于验证工作流所需的文件和配置是否正确

set -e

echo "🔍 检查 reF1nd 工作流配置..."
echo "=================================="

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 检查结果统计
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
WARNING_CHECKS=0

# 检查函数
check_file() {
    local file_path="$1"
    local description="$2"
    local required="$3"  # true/false
    
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    
    if [ -f "$file_path" ]; then
        echo -e "${GREEN}✅${NC} $description: $file_path"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
        return 0
    else
        if [ "$required" = "true" ]; then
            echo -e "${RED}❌${NC} $description: $file_path (必需文件缺失)"
            FAILED_CHECKS=$((FAILED_CHECKS + 1))
            return 1
        else
            echo -e "${YELLOW}⚠️${NC} $description: $file_path (可选文件缺失)"
            WARNING_CHECKS=$((WARNING_CHECKS + 1))
            return 0
        fi
    fi
}

check_directory() {
    local dir_path="$1"
    local description="$2"
    
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    
    if [ -d "$dir_path" ]; then
        echo -e "${GREEN}✅${NC} $description: $dir_path"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
        return 0
    else
        echo -e "${RED}❌${NC} $description: $dir_path (目录不存在)"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
        return 1
    fi
}

check_executable() {
    local file_path="$1"
    local description="$2"
    
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    
    if [ -f "$file_path" ] && [ -x "$file_path" ]; then
        echo -e "${GREEN}✅${NC} $description: $file_path (可执行)"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
        return 0
    elif [ -f "$file_path" ]; then
        echo -e "${YELLOW}⚠️${NC} $description: $file_path (文件存在但不可执行)"
        WARNING_CHECKS=$((WARNING_CHECKS + 1))
        return 0
    else
        echo -e "${RED}❌${NC} $description: $file_path (文件不存在)"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
        return 1
    fi
}

echo ""
echo "📁 检查必需文件..."
echo "-------------------"

# 检查工作流文件
check_file ".github/workflows/ref1nd-release.yml" "reF1nd 工作流文件" true

# 检查脚本文件
check_file ".github/scripts/telegram-upload.sh" "Telegram 上传脚本" true
check_executable ".github/scripts/telegram-upload.sh" "Telegram 上传脚本执行权限"

# 检查构建配置文件
check_file ".fpm_systemd" "FPM systemd 配置" true
check_file ".fpm_openwrt" "FPM OpenWrt 配置" true
check_file ".github/deb2ipk.sh" "deb2ipk 转换脚本" true
check_executable ".github/deb2ipk.sh" "deb2ipk 脚本执行权限"

echo ""
echo "📋 检查项目文件..."
echo "-------------------"

# 检查项目基础文件
check_file "go.mod" "Go 模块文件" true
check_file "Makefile" "Makefile" false
check_file "LICENSE" "许可证文件" true
check_file "cmd/sing-box/main.go" "主程序入口" true

# 检查构建相关目录和文件
check_directory "cmd/internal" "内部命令目录"
check_file "cmd/internal/read_tag/main.go" "版本读取工具" true

echo ""
echo "🔧 检查配置文件内容..."
echo "----------------------"

# 检查 .fpm_systemd 内容
if [ -f ".fpm_systemd" ]; then
    if grep -q "sing-box" ".fpm_systemd"; then
        echo -e "${GREEN}✅${NC} .fpm_systemd 包含 sing-box 配置"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        echo -e "${YELLOW}⚠️${NC} .fpm_systemd 可能缺少 sing-box 配置"
        WARNING_CHECKS=$((WARNING_CHECKS + 1))
    fi
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
fi

# 检查 .fpm_openwrt 内容
if [ -f ".fpm_openwrt" ]; then
    if grep -q "sing-box" ".fpm_openwrt"; then
        echo -e "${GREEN}✅${NC} .fpm_openwrt 包含 sing-box 配置"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        echo -e "${YELLOW}⚠️${NC} .fpm_openwrt 可能缺少 sing-box 配置"
        WARNING_CHECKS=$((WARNING_CHECKS + 1))
    fi
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
fi

echo ""
echo "🔐 检查 GitHub Secrets 配置提醒..."
echo "--------------------------------"

echo -e "${BLUE}ℹ️${NC} 请确保在 GitHub 仓库设置中配置了以下 Secrets:"
echo "   • TELEGRAM_BOT_TOKEN (必需) - Telegram Bot Token"
echo "   • TELEGRAM_CHAT_ID (必需) - Telegram 聊天 ID"
echo "   • GPG_KEY (可选) - GPG 私钥，用于包签名"
echo "   • GPG_PASSPHRASE (可选) - GPG 密码"
echo "   • GPG_KEY_ID (可选) - GPG 密钥 ID"

echo ""
echo "🧪 检查 Go 环境..."
echo "------------------"

TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if command -v go >/dev/null 2>&1; then
    GO_VERSION=$(go version | cut -d' ' -f3)
    echo -e "${GREEN}✅${NC} Go 已安装: $GO_VERSION"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
    
    # 检查 Go 版本是否满足要求 (1.24+)
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if go version | grep -E "go1\.(2[4-9]|[3-9][0-9])" >/dev/null; then
        echo -e "${GREEN}✅${NC} Go 版本满足要求 (1.24+)"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        echo -e "${YELLOW}⚠️${NC} Go 版本可能过低，建议使用 1.24+"
        WARNING_CHECKS=$((WARNING_CHECKS + 1))
    fi
else
    echo -e "${YELLOW}⚠️${NC} Go 未安装 (本地测试需要)"
    WARNING_CHECKS=$((WARNING_CHECKS + 1))
fi

echo ""
echo "📊 检查结果汇总"
echo "================"
echo -e "总检查项: ${BLUE}$TOTAL_CHECKS${NC}"
echo -e "通过: ${GREEN}$PASSED_CHECKS${NC}"
echo -e "警告: ${YELLOW}$WARNING_CHECKS${NC}"
echo -e "失败: ${RED}$FAILED_CHECKS${NC}"

echo ""
if [ $FAILED_CHECKS -eq 0 ]; then
    if [ $WARNING_CHECKS -eq 0 ]; then
        echo -e "${GREEN}🎉 所有检查都通过了！reF1nd 工作流已准备就绪。${NC}"
        exit 0
    else
        echo -e "${YELLOW}⚠️ 检查完成，有一些警告项目。工作流应该可以正常运行。${NC}"
        exit 0
    fi
else
    echo -e "${RED}❌ 检查发现问题，请修复后再运行工作流。${NC}"
    echo ""
    echo "🔧 修复建议:"
    echo "1. 确保所有必需文件都存在"
    echo "2. 检查文件路径是否正确"
    echo "3. 为脚本文件添加执行权限: chmod +x .github/scripts/*.sh"
    echo "4. 确保 Go 项目结构正确"
    exit 1
fi
