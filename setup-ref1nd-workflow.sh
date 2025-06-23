#!/bin/bash

# reF1nd 工作流设置脚本 (Bash)
# 用于在 Linux/macOS 环境下设置 reF1nd 工作流

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}🚀 设置 reF1nd 工作流...${NC}"
echo -e "${CYAN}=========================${NC}"

# 检查是否在 Git 仓库中
if [ ! -d ".git" ]; then
    echo -e "${RED}❌ 错误: 当前目录不是 Git 仓库${NC}"
    exit 1
fi

# 检查必需文件是否存在
required_files=(
    ".github/workflows/ref1nd-release.yml"
    ".github/scripts/telegram-upload.sh"
    ".github/scripts/check-ref1nd-config.sh"
)

missing_files=()
for file in "${required_files[@]}"; do
    if [ ! -f "$file" ]; then
        missing_files+=("$file")
    fi
done

if [ ${#missing_files[@]} -gt 0 ]; then
    echo -e "${RED}❌ 缺少必需文件:${NC}"
    for file in "${missing_files[@]}"; do
        echo -e "${RED}   • $file${NC}"
    done
    exit 1
fi

echo -e "${GREEN}✅ 所有必需文件都存在${NC}"

# 设置脚本执行权限
echo ""
echo -e "${YELLOW}🔧 设置脚本执行权限...${NC}"

chmod +x .github/scripts/telegram-upload.sh
chmod +x .github/scripts/check-ref1nd-config.sh
chmod +x .github/deb2ipk.sh 2>/dev/null || echo -e "${YELLOW}⚠️ .github/deb2ipk.sh 不存在，跳过${NC}"

# 通过 Git 设置权限 (确保在仓库中正确记录)
git update-index --chmod=+x .github/scripts/telegram-upload.sh
git update-index --chmod=+x .github/scripts/check-ref1nd-config.sh
git update-index --chmod=+x .github/deb2ipk.sh 2>/dev/null || true

echo -e "${GREEN}✅ 脚本执行权限设置完成${NC}"

# 检查 GitHub Secrets 配置
echo ""
echo -e "${YELLOW}🔐 GitHub Secrets 配置检查...${NC}"
echo "请确保在 GitHub 仓库设置中配置了以下 Secrets:"
echo -e "${CYAN}   • TELEGRAM_BOT_TOKEN (必需) - Telegram Bot Token${NC}"
echo -e "${CYAN}   • TELEGRAM_CHAT_ID (必需) - Telegram 聊天 ID${NC}"
echo -e "   • GPG_KEY (可选) - GPG 私钥，用于包签名"
echo -e "   • GPG_PASSPHRASE (可选) - GPG 密码"
echo -e "   • GPG_KEY_ID (可选) - GPG 密钥 ID"

# 提供 Telegram Bot 设置指导
echo ""
echo -e "${YELLOW}📱 Telegram Bot 设置指导:${NC}"
echo "1. 与 @BotFather 对话创建新 Bot"
echo "2. 获取 Bot Token (格式: 123456789:ABCdefGHIjklMNOpqrsTUVwxyz)"
echo "3. 将 Bot 添加到目标群组或频道"
echo "4. 获取聊天 ID:"
echo "   • 群组: -123456789 (负数)"
echo "   • 频道: @channel_username 或 -100123456789"
echo "   • 私聊: 123456789 (正数)"

# 检查 Go 环境
echo ""
echo -e "${YELLOW}🧪 检查 Go 环境...${NC}"

if command -v go >/dev/null 2>&1; then
    go_version=$(go version)
    echo -e "${GREEN}✅ Go 已安装: $go_version${NC}"
    
    # 检查版本是否满足要求
    if echo "$go_version" | grep -E "go1\.(2[4-9]|[3-9][0-9])" >/dev/null; then
        echo -e "${GREEN}✅ Go 版本满足要求 (1.24+)${NC}"
    else
        echo -e "${YELLOW}⚠️ Go 版本可能过低，建议使用 1.24+${NC}"
    fi
else
    echo -e "${YELLOW}⚠️ Go 未安装，本地测试需要 Go 环境${NC}"
fi

# 运行配置检查脚本
echo ""
echo -e "${YELLOW}🔍 运行配置检查...${NC}"

if [ -f ".github/scripts/check-ref1nd-config.sh" ]; then
    ./.github/scripts/check-ref1nd-config.sh
else
    echo -e "${YELLOW}⚠️ 配置检查脚本不存在${NC}"
fi

# 提供使用说明
echo ""
echo -e "${CYAN}📖 使用说明:${NC}"
echo -e "${CYAN}=============${NC}"
echo ""
echo -e "${NC}1. 自动触发 (推荐):${NC}"
echo -e "   ${BLUE}git tag v1.8.0-reF1nd-beta1${NC}"
echo -e "   ${BLUE}git push origin v1.8.0-reF1nd-beta1${NC}"
echo ""
echo -e "${NC}2. 手动触发:${NC}"
echo "   • 进入 GitHub Actions 页面"
echo "   • 选择 'reF1nd Release Build' 工作流"
echo "   • 点击 'Run workflow' 并输入标签名"
echo ""
echo -e "${NC}3. 查看构建结果:${NC}"
echo "   • GitHub Actions 页面查看日志"
echo "   • Telegram 接收文件和通知"
echo "   • Artifacts 页面下载文件"

echo ""
echo -e "${GREEN}🎉 reF1nd 工作流设置完成！${NC}"
echo -e "${GREEN}现在可以推送包含 'reF1nd' 的标签来触发构建。${NC}"

# 询问是否要创建测试标签
echo ""
read -p "是否要创建一个测试标签? (y/N): " create_tag

if [[ "$create_tag" =~ ^[Yy]$ ]]; then
    read -p "请输入标签名称 (例: v1.0.0-reF1nd-test): " tag_name
    
    if [[ "$tag_name" == *"reF1nd"* ]]; then
        if git tag "$tag_name"; then
            echo -e "${GREEN}✅ 标签 '$tag_name' 创建成功${NC}"
            echo -e "${YELLOW}运行以下命令推送标签并触发构建:${NC}"
            echo -e "${CYAN}   git push origin $tag_name${NC}"
        else
            echo -e "${RED}❌ 创建标签失败${NC}"
        fi
    else
        echo -e "${RED}❌ 标签名称必须包含 'reF1nd'${NC}"
    fi
fi

echo ""
echo -e "${CYAN}📚 更多信息请查看: .github/workflows/README-ref1nd.md${NC}"
