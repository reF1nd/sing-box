# sing-box reF1nd 自动化构建工作流

这是一个专门为 sing-box 项目设计的自动化构建工作流，用于构建和发布包含 `reF1nd` 标签的定制版本。

## 🎯 功能概述

### 自动化构建
- **触发方式**: 推送包含 `reF1nd` 的 Git 标签时自动触发
- **并行构建**: 同时构建多个平台的二进制文件和系统包
- **智能打包**: 自动生成不同格式的安装包

### 构建产物
**二进制文件**:
- Windows AMD64 (`.exe`)
- Linux AMD64
- Linux ARM64 (OpenWrt aarch64_cortex-a53)

**系统包**:
- Debian 包 (`.deb`) - Linux AMD64
- Alpine 包 (`.apk`) - Linux AMD64
- OpenWrt IPK 包 (`.ipk`) - aarch64_cortex-a53

### Telegram 集成
- 自动推送所有构建文件到 Telegram
- 发送详细的构建报告和状态通知
- 包含版本信息、提交记录和更新日志
- 支持重试机制和错误处理

## 📁 文件结构

```
.github/
├── workflows/
│   ├── ref1nd-release.yml          # 主工作流文件
│   └── README-ref1nd.md            # 详细文档
└── scripts/
    ├── telegram-upload.sh          # Telegram 文件上传脚本
    └── check-ref1nd-config.sh      # 配置检查脚本

setup-ref1nd-workflow.sh            # Linux/macOS 设置脚本
setup-ref1nd-workflow.ps1           # Windows 设置脚本
REFIND-WORKFLOW-SETUP.md            # 本文档
```

## 🚀 快速开始

### 1. 运行设置脚本

**Linux/macOS**:
```bash
./setup-ref1nd-workflow.sh
```

**Windows (PowerShell)**:
```powershell
.\setup-ref1nd-workflow.ps1
```

### 2. 配置 GitHub Secrets

在 GitHub 仓库设置中添加以下 Secrets：

| Secret 名称 | 必需 | 说明 |
|------------|------|------|
| `TELEGRAM_BOT_TOKEN` | ✅ | Telegram Bot Token |
| `TELEGRAM_CHAT_ID` | ✅ | Telegram 聊天 ID |
| `GPG_KEY` | ❌ | GPG 私钥 (用于包签名) |
| `GPG_PASSPHRASE` | ❌ | GPG 密码 |
| `GPG_KEY_ID` | ❌ | GPG 密钥 ID |

### 3. 创建和推送标签

```bash
# 创建包含 reF1nd 的标签
git tag v1.8.0-reF1nd-beta1

# 推送标签触发构建
git push origin v1.8.0-reF1nd-beta1
```

## 📱 Telegram Bot 设置

### 创建 Bot
1. 与 [@BotFather](https://t.me/BotFather) 对话
2. 发送 `/newbot` 创建新 Bot
3. 按提示设置 Bot 名称和用户名
4. 获取 Bot Token (格式: `123456789:ABCdefGHIjklMNOpqrsTUVwxyz`)

### 获取聊天 ID
- **私聊**: 与 [@userinfobot](https://t.me/userinfobot) 对话获取你的用户 ID
- **群组**: 将 Bot 添加到群组，聊天 ID 为负数 (如: `-123456789`)
- **频道**: 将 Bot 添加为管理员，聊天 ID 为 `@channel_username` 或 `-100123456789`

## 🔧 工作流程详解

### 阶段 1: 准备 (prepare)
- 解析标签名称获取版本号
- 收集 Git 提交信息
- 生成更新日志 (最近 10 个提交)

### 阶段 2: 并行构建
**二进制构建** (`build_binaries`):
- Windows AMD64
- Linux AMD64  
- Linux ARM64

**系统包构建** (`build_packages`):
- Debian 包 (使用 FPM)
- Alpine 包 (使用 FPM)
- OpenWrt IPK 包 (deb2ipk 转换)

### 阶段 3: 收集和上传 (collect_and_upload)
- 下载所有构建产物
- 合并到统一的 Artifact
- 上传到 GitHub Actions (保留 30 天)

### 阶段 4: Telegram 通知 (telegram_notify)
- 逐个推送构建文件到 Telegram
- 发送详细的构建状态报告
- 包含错误处理和重试机制

## 📊 构建状态监控

### GitHub Actions 页面
- 实时查看构建进度
- 详细的构建日志
- 下载构建产物

### Telegram 通知
- 文件推送通知 (每个文件单独发送)
- 构建完成报告
- 错误和警告信息

## 🛠️ 自定义配置

### 修改构建目标
编辑 `.github/workflows/ref1nd-release.yml` 中的 `matrix` 配置：

```yaml
strategy:
  matrix:
    include:
      - { os: windows, arch: amd64, ext: .exe }
      - { os: linux, arch: amd64, ext: "" }
      # 添加更多目标...
```

### 修改构建标签
在工作流的环境变量中修改：

```yaml
env:
  BUILD_TAGS: 'with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_tailscale'
```

### 自定义 Telegram 消息
编辑 `.github/scripts/telegram-upload.sh` 脚本中的消息模板。

## 🔍 故障排除

### 常见问题

1. **工作流未触发**
   - 确认标签名包含 `reF1nd`
   - 检查工作流文件语法
   - 查看 GitHub Actions 页面

2. **构建失败**
   - 检查 Go 版本兼容性
   - 确认依赖包可用
   - 查看构建日志

3. **Telegram 推送失败**
   - 验证 Bot Token 正确性
   - 确认 Bot 已添加到目标聊天
   - 检查聊天 ID 格式

4. **包构建失败**
   - 检查 FPM 配置文件
   - 确认 `deb2ipk.sh` 脚本可执行
   - 验证系统依赖

### 调试模式
在工作流文件中添加调试环境变量：

```yaml
env:
  ACTIONS_STEP_DEBUG: true
  ACTIONS_RUNNER_DEBUG: true
```

## 📚 相关文档

- [详细工作流文档](.github/workflows/README-ref1nd.md)
- [GitHub Actions 官方文档](https://docs.github.com/en/actions)
- [Telegram Bot API](https://core.telegram.org/bots/api)
- [FPM 打包工具](https://fpm.readthedocs.io/)

## 🤝 贡献

欢迎提交 Issue 和 Pull Request 来改进这个工作流！

## 📄 许可证

本工作流遵循与 sing-box 项目相同的许可证。
