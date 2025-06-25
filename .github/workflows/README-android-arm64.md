# Android ARM64 构建和部署工作流

## 📱 功能概述

这个工作流专门用于构建 sing-box 的 Android ARM64 二进制文件，并自动推送到 `ridesnails/box_for_magisk` 仓库的 `simple` 分支。

## 🚀 触发方式

### 1. 自动触发
- **标签推送**: 当推送以 `v` 开头的标签时自动触发
  ```bash
  git tag v1.10.0
  git push origin v1.10.0
  ```

### 2. 手动触发
- 在 GitHub Actions 页面手动运行
- 需要输入版本号 (例如: `1.10.0`)

## 🔧 工作流程

```
标签/手动触发 → 准备构建信息 → Android ARM64 构建 → 推送到 Magisk 仓库 → Telegram 通知
      ↓              ↓              ↓              ↓              ↓
   获取版本信息    提取提交信息    使用 NDK 构建    更新二进制文件    发送构建报告
```

### 详细步骤

1. **准备阶段** (`prepare`)
   - 获取版本号 (从标签或手动输入)
   - 提取提交信息
   - 生成更新日志

2. **构建阶段** (`build_android_arm64`)
   - 设置 Go 环境 (1.24+)
   - 安装 Android NDK r28
   - 安装内部构建工具
   - 使用 `aarch64-linux-android21-clang` 编译
   - 生成 Android ARM64 二进制文件
   - 创建压缩包

3. **部署阶段** (`push_to_magisk`)
   - 下载构建产物
   - 检出 `ridesnails/box_for_magisk` 仓库
   - 更新 `box/bin/sing-box` 文件
   - 提交并推送更改

4. **通知阶段** (`notify`)
   - 发送 Telegram 构建报告
   - 包含构建状态和部署信息

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

### 链接器标志
```
-s -buildid= -X github.com/sagernet/sing-box/constant.Version={version}
```

## 📱 Telegram 通知

通知内容包括：
- ✅/❌ 构建状态
- ✅/❌ 部署状态
- 📦 版本信息
- 📋 提交信息
- 📝 更新日志
- 🔗 构建日志链接

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
```

### 手动构建
1. 访问 GitHub Actions 页面
2. 选择 "Android ARM64 Build and Deploy" 工作流
3. 点击 "Run workflow"
4. 输入版本号 (例如: `1.10.0`)
5. 点击 "Run workflow" 确认

## 🔍 故障排除

### 常见问题

1. **NDK 编译器未找到**
   - 检查 NDK 版本是否正确 (r28)
   - 验证编译器路径设置

2. **推送权限错误**
   - 检查 `BOX_FOR_MAGISK_TOKEN` 是否配置
   - 验证 token 权限是否足够

3. **构建失败**
   - 检查 Go 版本兼容性
   - 验证构建标签和依赖项

### 调试方法
- 查看 GitHub Actions 日志
- 检查各个步骤的输出
- 验证环境变量设置

## 📚 相关文档

- [sing-box 构建文档](https://sing-box.sagernet.org/installation/build-from-source/)
- [Android NDK 官方文档](https://developer.android.com/ndk)
- [GitHub Actions 文档](https://docs.github.com/en/actions)

## 🔄 维护说明

- 定期检查 Android NDK 版本更新
- 监控目标仓库结构变化
- 根据需要调整构建参数
- 更新文档和通知内容
