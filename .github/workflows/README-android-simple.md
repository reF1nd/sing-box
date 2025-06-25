# Android ARM64 简化构建工作流

## 🎯 目标

这是一个专门用于测试 Android ARM64 编译的简化工作流，去掉了所有可能导致问题的复杂功能，专注于确保编译成功。

## 🚀 触发方式

### 1. 手动触发（推荐用于测试）
1. 访问 GitHub Actions 页面
2. 选择 "Android ARM64 Simple Build" 工作流
3. 点击 "Run workflow"
4. 输入版本号 (例如: `1.10.0-test`)
5. 点击 "Run workflow" 确认

### 2. 标签触发
```bash
git tag v1.10.0-test
git push origin v1.10.0-test
```

## 🔧 工作流程

```
触发 → 准备版本信息 → Android ARM64 构建 → 上传构建产物
  ↓         ↓              ↓              ↓
获取版本   提取版本号    使用 NDK 编译    保存二进制文件
```

## 📦 构建配置

### 编译环境
- **Go 版本**: 1.24+
- **Android NDK**: r28
- **编译器**: `aarch64-linux-android21-clang`
- **目标平台**: `linux/arm64` (Android 兼容)
- **CGO**: 启用

### 构建标签
```
with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_tailscale
```

### 关键修复
1. **编译器设置**: 使用简单名称而非完整路径
2. **环境变量**: 使用 `BUILD_GOOS` 和 `BUILD_GOARCH`
3. **构建命令**: 显式传递环境变量给构建工具

## 📋 构建产物

### 生成的文件
- **二进制文件**: `sing-box` (Android ARM64 可执行文件)
- **压缩包**: `sing-box-{version}-android-arm64.tar.gz`

### 下载方式
1. 构建完成后，访问 GitHub Actions 运行页面
2. 在 "Artifacts" 部分找到 `android-arm64-binary`
3. 点击下载

## 🔍 验证构建

### 检查构建日志
在 GitHub Actions 日志中查找：
```
✅ 找到 Android 编译器: aarch64-linux-android21-clang
✅ Android ARM64 构建完成
```

### 验证文件类型
下载后可以使用 `file` 命令验证：
```bash
file sing-box
# 应该显示: ELF 64-bit LSB executable, ARM aarch64
```

## 🛠️ 故障排除

### 常见问题

1. **编译器未找到**
   ```
   ❌ 未找到 Android 编译器: aarch64-linux-android21-clang
   ```
   - 检查 NDK 版本是否正确 (r28)
   - 查看日志中的 PATH 设置

2. **链接器错误**
   ```
   FATAL[xxxx] exit status 1
   ```
   - 检查构建标签是否正确
   - 验证 CGO 设置

3. **构建工具未找到**
   ```
   build: command not found
   ```
   - 确保 `go install -v ./cmd/internal/build` 执行成功

### 调试步骤
1. 查看完整的 GitHub Actions 日志
2. 检查 "验证编译器" 步骤的输出
3. 查看构建命令的详细输出
4. 验证环境变量设置

## 📈 成功标准

构建成功的标志：
- [ ] NDK 正确安装
- [ ] 编译器找到并验证版本
- [ ] 构建工具安装成功
- [ ] Android ARM64 二进制文件生成
- [ ] 文件类型验证通过
- [ ] Artifact 上传成功

## 🔄 下一步计划

一旦这个简化版本构建成功：

### 阶段 2: 添加部署功能
- 推送二进制文件到 `ridesnails/box_for_magisk` 仓库
- 更新 `box/bin/sing-box` 文件

### 阶段 3: 添加通知功能
- Telegram 构建状态通知
- 包含构建和部署信息

## 📚 参考资料

- [现有的 Android 构建配置](.github/workflows/build.yml#L162-L172)
- [sing-box 构建文档](https://sing-box.sagernet.org/installation/build-from-source/)
- [Android NDK 文档](https://developer.android.com/ndk)

## 💡 使用建议

1. **首次测试**: 使用手动触发，输入测试版本号
2. **验证成功**: 下载并检查生成的二进制文件
3. **确认无误**: 再考虑添加自动部署功能

这个简化版本专注于解决编译问题，确保 Android ARM64 构建能够成功完成。
