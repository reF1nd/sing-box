# reF1nd 工作流设置脚本 (PowerShell)
# 用于在 Windows 环境下设置 reF1nd 工作流

Write-Host "🚀 设置 reF1nd 工作流..." -ForegroundColor Cyan
Write-Host "=========================" -ForegroundColor Cyan

# 检查是否在 Git 仓库中
if (-not (Test-Path ".git")) {
    Write-Host "❌ 错误: 当前目录不是 Git 仓库" -ForegroundColor Red
    exit 1
}

# 检查必需文件是否存在
$requiredFiles = @(
    ".github/workflows/ref1nd-release.yml",
    ".github/scripts/telegram-upload.sh",
    ".github/scripts/check-ref1nd-config.sh"
)

$missingFiles = @()
foreach ($file in $requiredFiles) {
    if (-not (Test-Path $file)) {
        $missingFiles += $file
    }
}

if ($missingFiles.Count -gt 0) {
    Write-Host "❌ 缺少必需文件:" -ForegroundColor Red
    foreach ($file in $missingFiles) {
        Write-Host "   • $file" -ForegroundColor Red
    }
    exit 1
}

Write-Host "✅ 所有必需文件都存在" -ForegroundColor Green

# 设置脚本执行权限 (通过 Git)
Write-Host ""
Write-Host "🔧 设置脚本执行权限..." -ForegroundColor Yellow

try {
    # 使用 Git 设置文件权限
    git update-index --chmod=+x .github/scripts/telegram-upload.sh
    git update-index --chmod=+x .github/scripts/check-ref1nd-config.sh
    git update-index --chmod=+x .github/deb2ipk.sh
    
    Write-Host "✅ 脚本执行权限设置完成" -ForegroundColor Green
} catch {
    Write-Host "⚠️ 警告: 无法设置脚本执行权限，GitHub Actions 会自动处理" -ForegroundColor Yellow
}

# 检查 GitHub Secrets 配置
Write-Host ""
Write-Host "🔐 GitHub Secrets 配置检查..." -ForegroundColor Yellow
Write-Host "请确保在 GitHub 仓库设置中配置了以下 Secrets:"
Write-Host "   • TELEGRAM_BOT_TOKEN (必需) - Telegram Bot Token" -ForegroundColor Cyan
Write-Host "   • TELEGRAM_CHAT_ID (必需) - Telegram 聊天 ID" -ForegroundColor Cyan
Write-Host "   • GPG_KEY (可选) - GPG 私钥，用于包签名" -ForegroundColor Gray
Write-Host "   • GPG_PASSPHRASE (可选) - GPG 密码" -ForegroundColor Gray
Write-Host "   • GPG_KEY_ID (可选) - GPG 密钥 ID" -ForegroundColor Gray

# 提供 Telegram Bot 设置指导
Write-Host ""
Write-Host "📱 Telegram Bot 设置指导:" -ForegroundColor Yellow
Write-Host "1. 与 @BotFather 对话创建新 Bot" -ForegroundColor White
Write-Host "2. 获取 Bot Token (格式: 123456789:ABCdefGHIjklMNOpqrsTUVwxyz)" -ForegroundColor White
Write-Host "3. 将 Bot 添加到目标群组或频道" -ForegroundColor White
Write-Host "4. 获取聊天 ID:" -ForegroundColor White
Write-Host "   • 群组: -123456789 (负数)" -ForegroundColor Gray
Write-Host "   • 频道: @channel_username 或 -100123456789" -ForegroundColor Gray
Write-Host "   • 私聊: 123456789 (正数)" -ForegroundColor Gray

# 检查 Go 环境
Write-Host ""
Write-Host "🧪 检查 Go 环境..." -ForegroundColor Yellow

try {
    $goVersion = go version
    Write-Host "✅ Go 已安装: $goVersion" -ForegroundColor Green
    
    # 检查版本是否满足要求
    if ($goVersion -match "go1\.([2-9][4-9]|[3-9][0-9])") {
        Write-Host "✅ Go 版本满足要求 (1.24+)" -ForegroundColor Green
    } else {
        Write-Host "⚠️ Go 版本可能过低，建议使用 1.24+" -ForegroundColor Yellow
    }
} catch {
    Write-Host "⚠️ Go 未安装，本地测试需要 Go 环境" -ForegroundColor Yellow
}

# 运行配置检查脚本 (如果在 Git Bash 环境中)
Write-Host ""
Write-Host "🔍 运行配置检查..." -ForegroundColor Yellow

if (Get-Command "bash" -ErrorAction SilentlyContinue) {
    try {
        bash .github/scripts/check-ref1nd-config.sh
    } catch {
        Write-Host "⚠️ 无法运行配置检查脚本，请手动检查" -ForegroundColor Yellow
    }
} else {
    Write-Host "⚠️ 未找到 bash，跳过配置检查" -ForegroundColor Yellow
    Write-Host "   可以安装 Git for Windows 来获得 bash 支持" -ForegroundColor Gray
}

# 提供使用说明
Write-Host ""
Write-Host "📖 使用说明:" -ForegroundColor Cyan
Write-Host "=============" -ForegroundColor Cyan
Write-Host ""
Write-Host "1. 自动触发 (推荐):" -ForegroundColor White
Write-Host "   git tag v1.8.0-reF1nd-beta1" -ForegroundColor Gray
Write-Host "   git push origin v1.8.0-reF1nd-beta1" -ForegroundColor Gray
Write-Host ""
Write-Host "2. 手动触发:" -ForegroundColor White
Write-Host "   • 进入 GitHub Actions 页面" -ForegroundColor Gray
Write-Host "   • 选择 'reF1nd Release Build' 工作流" -ForegroundColor Gray
Write-Host "   • 点击 'Run workflow' 并输入标签名" -ForegroundColor Gray
Write-Host ""
Write-Host "3. 查看构建结果:" -ForegroundColor White
Write-Host "   • GitHub Actions 页面查看日志" -ForegroundColor Gray
Write-Host "   • Telegram 接收文件和通知" -ForegroundColor Gray
Write-Host "   • Artifacts 页面下载文件" -ForegroundColor Gray

Write-Host ""
Write-Host "🎉 reF1nd 工作流设置完成！" -ForegroundColor Green
Write-Host "现在可以推送包含 'reF1nd' 的标签来触发构建。" -ForegroundColor Green

# 询问是否要创建测试标签
Write-Host ""
$createTag = Read-Host "是否要创建一个测试标签? (y/N)"
if ($createTag -eq "y" -or $createTag -eq "Y") {
    $tagName = Read-Host "请输入标签名称 (例: v1.0.0-reF1nd-test)"
    
    if ($tagName -match "reF1nd") {
        try {
            git tag $tagName
            Write-Host "✅ 标签 '$tagName' 创建成功" -ForegroundColor Green
            Write-Host "运行以下命令推送标签并触发构建:" -ForegroundColor Yellow
            Write-Host "   git push origin $tagName" -ForegroundColor Cyan
        } catch {
            Write-Host "❌ 创建标签失败: $_" -ForegroundColor Red
        }
    } else {
        Write-Host "❌ 标签名称必须包含 'reF1nd'" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "📚 更多信息请查看: .github/workflows/README-ref1nd.md" -ForegroundColor Cyan
