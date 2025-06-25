# Android ARM64 完整构建和部署工作流

## 🎯 功能概述

这是一个完整的 Android ARM64 构建和自动部署工作流，包含：
- ✅ Android ARM64 二进制文件构建
- ✅ 自动推送到 `ridesnails/box_for_magisk` 仓库
- ✅ Telegram 状态通知
- ✅ 智能文件变更检测

## 🚀 触发方式

### 1. 自动触发（推荐）
当推送以 `v` 开头的标签时自动运行：
```bash
git tag v1.10.0
git push origin v1.10.0
```

### 2. 手动触发
1. 访问 GitHub Actions 页面
2. 选择 "Android ARM64 Final Build" 工作流
3. 点击 "Run workflow"
4. 输入版本号 (例如: `1.10.0`)
5. 点击 "Run workflow" 确认

## 🔧 工作流程

```
标签/手动触发 → 准备构建信息 → Android ARM64 构建 → 推送到 Magisk 仓库 → Telegram 通知
      ↓              ↓              ↓              ↓              ↓
   获取版本信息    提取提交信息    使用 NDK 构建    更新二进制文件    发送构建报告
   生成更新日志    生成变更日志    创建压缩包      智能检测变更      包含部署状态
```

### 详细步骤

#### 1. **准备阶段** (`prepare`)
- 获取版本号 (从标签或手动输入)
- 提取最新提交信息
- 生成更新日志 (基于 Git 提交历史)

#### 2. **构建阶段** (`build_android_arm64`)
- 设置 Go 环境 (1.24+)
- 安装 Android NDK r28 (带本地缓存)
- 安装内部构建工具
- 使用 `aarch64-linux-android21-clang` 编译
- 生成 Android ARM64 二进制文件
- 创建压缩包并上传 artifact

#### 3. **部署阶段** (`push_to_magisk`)
- 下载构建产物
- 检出 `ridesnails/box_for_magisk` 仓库 (`simple` 分支)
- 更新 `box/bin/sing-box` 文件
- 设置正确的文件权限 (755)
- 智能检测文件变更，避免无意义提交
- 提交并推送更改

#### 4. **通知阶段** (`notify`)
- 发送详细的 Telegram 构建报告
- 包含构建状态、部署状态和版本信息
- 显示提交信息和更新日志
- 提供 GitHub Actions 日志链接

## 🔑 所需配置

### GitHub Secrets

| Secret 名称 | 必需 | 说明 |
|------------|------|------|
| `BOX_FOR_MAGISK_TOKEN` | 推荐 | 用于推送到 box_for_magisk 仓库的 Personal Access Token |
| `GITHUB_TOKEN` | 备用 | 如果没有专用 token，使用默认 token |
| `TELEGRAM_BOT_TOKEN` | 可选 | Telegram 机器人令牌 (用于通知) |
| `TELEGRAM_CHAT_ID` | 可选 | Telegram 聊天 ID (用于通知) |

### Personal Access Token 权限

如果使用 `BOX_FOR_MAGISK_TOKEN`，需要以下权限：
- `repo` - 完整仓库访问权限
- `contents:write` - 内容写入权限

### Telegram 配置

1. **创建 Telegram Bot**:
   - 与 @BotFather 对话
   - 发送 `/newbot` 创建新机器人
   - 获取 Bot Token

2. **获取 Chat ID**:
   - 将机器人添加到群组或与机器人私聊
   - 发送消息给机器人
   - 访问 `https://api.telegram.org/bot<TOKEN>/getUpdates`
   - 从响应中获取 `chat.id`

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
- **Android NDK**: r28 (带本地缓存)
- **编译器**: `aarch64-linux-android21-clang`
- **目标平台**: `android/arm64`
- **CGO**: 启用

### 构建标签
```
with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_tailscale
```

### 链接器标志
```
-s -buildid= -X github.com/sagernet/sing-box/constant.Version={version}
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
• Magisk 仓库推送: ✅

📦 部署信息:
• 目标仓库: ridesnails/box_for_magisk
• 目标分支: simple
• 文件路径: box/bin/sing-box
• 文件权限: 755 (可执行)

📝 更新日志:
• feat: 添加新功能
• fix: 修复已知问题
• docs: 更新文档

🔗 详细日志: [GitHub Actions](链接)
```

## 🛠️ 使用示例

### 发布新版本
```bash
# 1. 确保代码已提交
git add .
git commit -m "feat: 新功能或修复"

# 2. 创建并推送标签
git tag v1.10.0
git push origin v1.10.0

# 3. 工作流自动运行，大约 5-10 分钟后完成
# 4. 检查 Telegram 通知确认部署状态
```

### 手动构建测试版本
```bash
# 使用 GitHub Actions 页面手动触发
# 输入版本号: 1.10.0-test
```

## 🔍 故障排除

### 常见问题

1. **构建失败**
   - 检查 Go 版本兼容性
   - 验证构建标签和依赖项
   - 查看 GitHub Actions 日志

2. **推送权限错误**
   - 检查 `BOX_FOR_MAGISK_TOKEN` 是否配置
   - 验证 token 权限是否足够
   - 确认目标仓库和分支存在

3. **Telegram 通知失败**
   - 检查 `TELEGRAM_BOT_TOKEN` 和 `TELEGRAM_CHAT_ID`
   - 验证机器人是否有发送消息权限
   - 确认 Chat ID 格式正确

### 调试方法
- 查看 GitHub Actions 完整日志
- 检查各个步骤的输出和环境变量
- 验证 secrets 配置是否正确

## 📚 相关文档

- [sing-box 构建文档](https://sing-box.sagernet.org/installation/build-from-source/)
- [Android NDK 官方文档](https://developer.android.com/ndk)
- [GitHub Actions 文档](https://docs.github.com/en/actions)
- [Telegram Bot API](https://core.telegram.org/bots/api)

## 🎉 成功标准

工作流成功运行后，您将看到：
1. ✅ Android ARM64 二进制文件构建成功
2. ✅ 文件推送到 `ridesnails/box_for_magisk/simple` 分支
3. ✅ `box/bin/sing-box` 文件更新为最新版本
4. 📱 Telegram 通知包含完整的部署状态
5. 🔗 GitHub Actions artifact 可供下载

这个完整的工作流现在已经准备就绪，可以自动处理从构建到部署的整个流程！
