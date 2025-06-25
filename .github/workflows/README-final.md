# Android ARM64 构建和部署工作流 - 最终版本

## 🎯 功能概述

这是一个完整的 Android ARM64 构建和自动部署工作流，实现了从源码编译到自动部署的全流程自动化。

### ✅ 核心功能
- **Android ARM64 二进制文件构建** - 使用 Android NDK r28 进行原生编译
- **自动部署到 Magisk 仓库** - 推送到 `ridesnails/box_for_magisk` 仓库的 `simple` 分支
- **智能文件变更检测** - 避免无意义的提交，支持强制更新
- **Telegram 状态通知** - 详细的构建和部署状态报告
- **灵活的触发方式** - 支持标签自动触发和手动触发

## 🚀 使用方法

### 自动触发（推荐）
```bash
# 创建并推送标签
git tag v1.10.0
git push origin v1.10.0
```

### 手动触发
1. 访问 GitHub Actions 页面
2. 选择 "Android ARM64 Build and Deploy" 工作流
3. 点击 "Run workflow"
4. 输入版本号 (例如: `1.10.0`)
5. 点击 "Run workflow" 确认

## 🔑 必需配置

### GitHub Secrets

| Secret 名称 | 必需 | 说明 |
|------------|------|------|
| `BOX_FOR_MAGISK_TOKEN` | 推荐 | 用于推送到 box_for_magisk 仓库的 Personal Access Token |
| `GITHUB_TOKEN` | 备用 | 如果没有专用 token，使用默认 token |
| `TELEGRAM_BOT_TOKEN` | 可选 | Telegram 机器人令牌 |
| `TELEGRAM_CHAT_ID` | 可选 | Telegram 聊天 ID |

### Personal Access Token 权限
- `repo` - 完整仓库访问权限
- `contents:write` - 内容写入权限

## 🔧 工作流程

```
标签触发 → 准备信息 → Android构建 → 部署到Magisk → Telegram通知
    ↓         ↓         ↓          ↓           ↓
  获取版本   提取提交   NDK编译    更新二进制   发送报告
  生成日志   生成变更   创建包     智能检测     包含状态
```

### 详细步骤

1. **准备阶段** (`prepare`)
   - 获取版本号和提交信息
   - 生成更新日志

2. **构建阶段** (`build_android_arm64`)
   - 设置 Go 1.24+ 和 Android NDK r28
   - 使用 `aarch64-linux-android21-clang` 编译
   - 生成 Android ARM64 二进制文件和压缩包

3. **部署阶段** (`deploy_to_magisk`)
   - 下载构建产物
   - 检出 `ridesnails/box_for_magisk` 仓库
   - 更新 `box/bin/sing-box` 文件 (权限 755)
   - 智能检测变更并提交推送

4. **通知阶段** (`notify`)
   - 发送详细的 Telegram 构建报告

## 📦 构建产物

### 生成的文件
- **二进制文件**: `sing-box` (Android ARM64 可执行文件)
- **压缩包**: `sing-box-{version}-android-arm64.tar.gz`

### 部署位置
- **仓库**: `ridesnails/box_for_magisk`
- **分支**: `simple`
- **文件路径**: `box/bin/sing-box`
- **文件权限**: 755 (可执行)

## 🔍 构建配置

### 编译环境
- **Go 版本**: 1.24+
- **Android NDK**: r28
- **编译器**: `aarch64-linux-android21-clang`
- **目标平台**: `android/arm64`
- **CGO**: 启用

### 构建标签
```
with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_tailscale
```

## 📱 Telegram 通知示例

```
📱 sing-box Android ARM64 构建报告

✅ 构建和部署成功

🏷️ 版本: 1.10.0
🕐 构建时间: 2024-01-01 12:00:00 UTC

📋 提交信息:
abc1234 - feat: 新功能 (开发者)

🔧 构建状态:
• Android ARM64 构建: ✅
• Magisk 仓库部署: ✅

📦 部署信息:
• 目标仓库: ridesnails/box_for_magisk
• 目标分支: simple
• 文件路径: box/bin/sing-box
• 文件权限: 755 (可执行)

📝 更新日志:
• feat: 添加新功能
• fix: 修复已知问题

🔗 详细日志: [GitHub Actions](链接)
```

## 🛠️ 故障排除

### 常见问题

1. **构建失败**
   - 检查 Go 版本和 NDK 配置
   - 查看构建日志中的错误信息

2. **推送权限错误**
   - 检查 `BOX_FOR_MAGISK_TOKEN` 配置
   - 验证 token 权限和有效性

3. **Telegram 通知失败**
   - 检查 `TELEGRAM_BOT_TOKEN` 和 `TELEGRAM_CHAT_ID`
   - 验证机器人权限

### 调试方法
- 查看 GitHub Actions 完整日志
- 检查各个步骤的输出
- 验证 secrets 配置

## 🎉 成功标准

工作流成功运行后：
- ✅ Android ARM64 二进制文件构建成功
- ✅ 文件推送到 `ridesnails/box_for_magisk/simple` 分支
- ✅ `box/bin/sing-box` 文件更新为最新版本
- ✅ Telegram 通知包含完整状态
- ✅ GitHub Actions artifact 可供下载

## 📚 技术要点

### 关键修复
1. **编译器配置**: 使用正确的 NDK 设置
2. **环境变量**: `BUILD_GOOS=android`, `BUILD_GOARCH=arm64`
3. **文件检测**: MD5 对比和强制更新机制
4. **错误处理**: 完善的调试信息

### 最佳实践
- 使用专用的 Personal Access Token
- 配置 Telegram 通知获得实时状态
- 定期检查 token 有效性
- 监控构建日志确保正常运行

这个最终版本集成了今天所有的修复和改进，提供了稳定可靠的 Android ARM64 构建和部署解决方案。
