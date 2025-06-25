# Android 构建错误修复

## 🐛 问题分析

从构建日志来看，Android ARM64 构建失败的原因是：

1. **链接器错误**: 链接器参数配置不正确
2. **NDK 路径问题**: Android NDK 工具链路径设置错误
3. **构建工具使用**: 没有正确使用 sing-box 的内部构建工具

## 🔧 修复内容

### 1. 修复 Android NDK 设置

**之前的问题**:
```yaml
export CC='${{ matrix.ndk }}-clang'
```

**修复后**:
```yaml
export ANDROID_NDK_HOME="${{ steps.setup-ndk.outputs.ndk-path }}"
export CC="${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/bin/${{ matrix.ndk }}-clang"
```

### 2. 使用正确的构建工具

**之前的问题**:
```bash
go build -v -trimpath -o dist/sing-box
```

**修复后**:
```bash
go install -v ./cmd/internal/build
build go build -v -trimpath -o dist/sing-box
```

### 3. 修复环境变量设置

**修复后的完整配置**:
```yaml
env:
  CGO_ENABLED: "1"
  GOOS: android
  GOARCH: arm64
```

### 4. 添加构建步骤 ID

为 Android NDK 设置步骤添加了 ID，以便后续步骤引用：
```yaml
- name: Setup Android NDK
  if: matrix.os == 'android'
  id: setup-ndk  # 新增
  uses: nttld/setup-ndk@v1
```

## 🧪 测试验证

创建了独立的测试工作流 `test-android-build.yml` 来验证修复：

### 测试内容
1. ✅ Android NDK 环境配置
2. ✅ 编译器路径验证
3. ✅ 构建工具安装
4. ✅ Android ARM64 二进制构建
5. ✅ 构建结果验证

### 运行测试
```bash
# 手动触发测试工作流
# 在 GitHub Actions 页面选择 "Test Android Build"
# 输入测试版本号，如: v1.0.0-reF1nd-test
```

## 📱 Android 构建流程

### 完整的构建步骤

1. **环境准备**
   ```bash
   # 设置 Go 环境
   go-version: ^1.24
   
   # 安装 Android NDK r28
   ndk-version: r28
   ```

2. **工具安装**
   ```bash
   # 安装 sing-box 内部构建工具
   go install -v ./cmd/internal/build
   ```

3. **环境变量设置**
   ```bash
   export ANDROID_NDK_HOME="${NDK_PATH}"
   export CC="${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang"
   export CXX="${CC}++"
   ```

4. **构建执行**
   ```bash
   build go build -v -trimpath -o dist/sing-box \
     -tags "${BUILD_TAGS}" \
     -ldflags "-s -buildid= -X github.com/sagernet/sing-box/constant.Version=${VERSION}" \
     ./cmd/sing-box
   ```

## 🔍 故障排除

### 常见问题

1. **NDK 路径错误**
   - 检查 `${{ steps.setup-ndk.outputs.ndk-path }}` 是否正确
   - 验证编译器文件是否存在

2. **构建工具未找到**
   - 确保 `go install -v ./cmd/internal/build` 执行成功
   - 检查 `build` 命令是否在 PATH 中

3. **链接器错误**
   - 验证 CC 和 CXX 环境变量设置
   - 检查 CGO_ENABLED=1 是否正确设置

### 调试命令

```bash
# 检查 NDK 安装
ls -la "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/" | grep aarch64

# 测试编译器
$CC --version

# 检查构建工具
which build
build --help
```

## 📦 二进制文件处理

### 文件提取逻辑增强

修复了二进制文件提取逻辑，添加了更详细的调试信息：

```bash
echo "=== 查看下载的文件 ==="
ls -la

# 查找所有可能的文件
find . -name "*sing-box*" -type f

# 验证文件类型
file sing-box-android-arm64
```

## 🚀 部署到 box_for_magisk

### 推送流程

1. **下载 Android 构建产物**
2. **提取二进制文件**
3. **检出目标仓库** (`ridesnails/box_for_magisk`)
4. **更新二进制文件** (`box/bin/sing-box`)
5. **提交并推送更改**

### 权限要求

需要配置以下 GitHub Secrets：
- `BOX_FOR_MAGISK_TOKEN` (推荐) - 专用访问令牌
- 或使用 `GITHUB_TOKEN` (如果有权限)

## ✅ 验证清单

构建成功后，应该看到：

- [ ] Android NDK 正确安装
- [ ] 编译器路径正确设置
- [ ] 构建工具成功安装
- [ ] Android ARM64 二进制文件生成
- [ ] 文件推送到 box_for_magisk 仓库
- [ ] Telegram 通知包含 Android 状态

## 🔄 后续优化

1. **缓存优化**: 缓存 Android NDK 安装
2. **并行构建**: 优化构建时间
3. **错误处理**: 增强错误恢复机制
4. **监控告警**: 添加构建失败通知

## 📚 参考资料

- [Android NDK 官方文档](https://developer.android.com/ndk)
- [Go 交叉编译指南](https://golang.org/doc/install/source#environment)
- [sing-box 构建文档](https://sing-box.sagernet.org/installation/build-from-source/)
