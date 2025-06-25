# Android ARM64 二进制推送功能

## 📱 功能概述

已成功为 reF1nd Release Build 工作流添加了 Android ARM64 构建和自动推送功能。

## 🔧 新增功能

### 1. Android ARM64 构建
- **目标平台**: Android ARM64 (aarch64-linux-android21)
- **构建工具**: Android NDK r28
- **编译器**: aarch64-linux-android21-clang
- **CGO**: 启用 (CGO_ENABLED=1)

### 2. 自动推送到 box_for_magisk 仓库
- **目标仓库**: `ridesnails/box_for_magisk`
- **目标分支**: `simple`
- **目标路径**: `box/bin/sing-box`
- **文件权限**: 可执行 (chmod +x)

## 🚀 工作流程

```
标签触发 → 并行构建 → Android 二进制推送 → Telegram 通知
    ↓           ↓              ↓              ↓
  触发器    包含 Android    推送到 box_for_magisk   包含推送状态
```

### 详细步骤

1. **构建阶段** (`build_binaries`)
   - 新增 Android ARM64 构建目标
   - 使用 Android NDK 进行交叉编译
   - 生成原生 Android 二进制文件

2. **推送阶段** (`push_android_binary`)
   - 下载 Android ARM64 构建产物
   - 提取二进制文件
   - 检出 `ridesnails/box_for_magisk` 仓库
   - 更新 `box/bin/sing-box` 文件
   - 提交并推送更改

3. **通知阶段** (`telegram_notify`)
   - 包含 Android 推送状态
   - 显示部署信息

## 🔑 所需配置

### GitHub Secrets

| Secret 名称 | 必需 | 说明 |
|------------|------|------|
| `BOX_FOR_MAGISK_TOKEN` | 推荐 | 用于推送到 box_for_magisk 仓库的 Personal Access Token |
| `GITHUB_TOKEN` | 备用 | 如果没有专用 token，使用默认 token |

### Personal Access Token 权限

如果使用 `BOX_FOR_MAGISK_TOKEN`，需要以下权限：
- `repo` - 完整仓库访问权限
- `workflow` - 工作流权限（如果需要）

## 📦 构建产物

### 新增的构建目标
- **Android ARM64**: `sing-box-{version}-android-arm64.tar.gz`
- **原始二进制**: `sing-box` (Android ARM64 可执行文件)

### 部署位置
- **仓库**: `ridesnails/box_for_magisk`
- **分支**: `simple`
- **文件**: `box/bin/sing-box`
- **权限**: 755 (可执行)

## 🔍 状态监控

### Telegram 通知增强
新增以下状态信息：
- ✅/❌ Android 推送状态
- 📱 Android 部署详情
- 🔗 仓库和分支信息

### 构建状态
- **二进制文件**: 包含 Android ARM64
- **Android 推送**: 独立状态跟踪
- **整体状态**: 综合所有步骤的结果

## 🛠️ 使用方法

### 触发构建
```bash
# 创建 reF1nd 标签
git tag v1.8.0-reF1nd-beta1
git push origin v1.8.0-reF1nd-beta1
```

### 手动触发
1. 进入 GitHub Actions 页面
2. 选择 "reF1nd Release Build" 工作流
3. 点击 "Run workflow"
4. 输入包含 `reF1nd` 的标签名

## 🔧 故障排除

### 常见问题

1. **Android 构建失败**
   - 检查 Android NDK 版本
   - 确认交叉编译环境
   - 查看构建日志

2. **推送失败**
   - 验证 `BOX_FOR_MAGISK_TOKEN` 权限
   - 确认目标仓库和分支存在
   - 检查网络连接

3. **二进制文件不可执行**
   - 确认 `chmod +x` 执行成功
   - 检查文件权限设置

### 调试步骤

1. **检查构建产物**
   ```bash
   # 在工作流中查看文件信息
   ls -la android_binary/
   file sing-box-android-arm64
   ```

2. **验证推送**
   ```bash
   # 检查 Git 状态
   git status
   git log -1
   ```

## 📋 技术细节

### Android 构建配置
```yaml
- { os: android, arch: arm64, ext: "", ndk: "aarch64-linux-android21" }
```

### 环境变量
```yaml
env:
  CGO_ENABLED: "1"
  GOOS: linux
  GOARCH: arm64
  CC: aarch64-linux-android21-clang
  CXX: aarch64-linux-android21-clang++
```

### 提交信息格式
```
Update sing-box binary to {version} (reF1nd)
```

## 🎯 预期结果

成功运行后，您将看到：
1. ✅ Android ARM64 二进制文件构建成功
2. ✅ 文件推送到 `ridesnails/box_for_magisk/simple` 分支
3. ✅ `box/bin/sing-box` 文件更新为最新版本
4. 📱 Telegram 通知包含完整的部署状态

## 🔄 后续维护

- 定期检查 Android NDK 版本更新
- 监控目标仓库的结构变化
- 根据需要调整构建参数
- 更新文档和通知内容
