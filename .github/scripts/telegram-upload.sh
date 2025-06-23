#!/bin/bash

# Telegram 文件上传脚本
# 用于批量上传构建产物到 Telegram

set -e

TELEGRAM_BOT_TOKEN="$1"
TELEGRAM_CHAT_ID="$2"
VERSION="$3"
FILES_DIR="$4"

if [ -z "$TELEGRAM_BOT_TOKEN" ] || [ -z "$TELEGRAM_CHAT_ID" ] || [ -z "$VERSION" ] || [ -z "$FILES_DIR" ]; then
    echo "Usage: $0 <bot_token> <chat_id> <version> <files_dir>"
    exit 1
fi

# 检查文件目录是否存在
if [ ! -d "$FILES_DIR" ]; then
    echo "Error: Files directory $FILES_DIR does not exist"
    exit 1
fi

# Telegram API 基础 URL
API_URL="https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}"

# 发送文件函数
send_file() {
    local file_path="$1"
    local caption="$2"
    local max_retries=3
    local retry_count=0
    
    while [ $retry_count -lt $max_retries ]; do
        echo "Sending file: $(basename "$file_path") (attempt $((retry_count + 1)))"
        
        if curl -X POST "${API_URL}/sendDocument" \
            -F "chat_id=${TELEGRAM_CHAT_ID}" \
            -F "document=@${file_path}" \
            -F "caption=${caption}" \
            -F "parse_mode=HTML" \
            --silent --show-error; then
            echo "✅ Successfully sent: $(basename "$file_path")"
            return 0
        else
            echo "❌ Failed to send: $(basename "$file_path")"
            retry_count=$((retry_count + 1))
            if [ $retry_count -lt $max_retries ]; then
                echo "Retrying in 5 seconds..."
                sleep 5
            fi
        fi
    done
    
    echo "❌ Failed to send after $max_retries attempts: $(basename "$file_path")"
    return 1
}

# 发送通知消息函数
send_message() {
    local message="$1"
    local max_retries=3
    local retry_count=0
    
    while [ $retry_count -lt $max_retries ]; do
        echo "Sending notification message (attempt $((retry_count + 1)))"
        
        if curl -X POST "${API_URL}/sendMessage" \
            -d "chat_id=${TELEGRAM_CHAT_ID}" \
            -d "text=${message}" \
            -d "parse_mode=Markdown" \
            -d "disable_web_page_preview=true" \
            --silent --show-error; then
            echo "✅ Successfully sent notification"
            return 0
        else
            echo "❌ Failed to send notification"
            retry_count=$((retry_count + 1))
            if [ $retry_count -lt $max_retries ]; then
                echo "Retrying in 3 seconds..."
                sleep 3
            fi
        fi
    done
    
    echo "❌ Failed to send notification after $max_retries attempts"
    return 1
}

echo "=== 开始上传文件到 Telegram ==="
echo "版本: $VERSION"
echo "文件目录: $FILES_DIR"

# 统计文件
total_files=0
success_files=0
failed_files=0

# 发送二进制文件 (zip, tar.gz)
echo ""
echo "📦 上传二进制文件..."
for file in "$FILES_DIR"/*.{zip,tar.gz}; do
    if [ -f "$file" ]; then
        total_files=$((total_files + 1))
        filename=$(basename "$file")
        
        # 判断平台类型
        if [[ "$filename" == *"windows"* ]]; then
            platform_icon="🪟"
            platform_name="Windows"
        elif [[ "$filename" == *"linux"* ]]; then
            platform_icon="🐧"
            platform_name="Linux"
        else
            platform_icon="💻"
            platform_name="Unknown"
        fi
        
        caption="$platform_icon <b>$filename</b>
🏷️ 版本: <code>$VERSION</code>
🔧 平台: $platform_name
📋 类型: 二进制文件
⭐ reF1nd 定制版本"
        
        if send_file "$file" "$caption"; then
            success_files=$((success_files + 1))
        else
            failed_files=$((failed_files + 1))
        fi
        
        # 避免 Telegram API 频率限制
        sleep 2
    fi
done

# 发送系统包文件 (deb, apk, ipk)
echo ""
echo "📦 上传系统包..."
for file in "$FILES_DIR"/*.{deb,apk,ipk}; do
    if [ -f "$file" ]; then
        total_files=$((total_files + 1))
        filename=$(basename "$file")
        
        # 判断包类型
        if [[ "$filename" == *.deb ]]; then
            package_icon="📦"
            package_type="Debian 包"
        elif [[ "$filename" == *.apk ]]; then
            package_icon="🏔️"
            package_type="Alpine 包"
        elif [[ "$filename" == *.ipk ]]; then
            package_icon="📡"
            package_type="OpenWrt 包"
        else
            package_icon="📋"
            package_type="系统包"
        fi
        
        caption="$package_icon <b>$filename</b>
🏷️ 版本: <code>$VERSION</code>
📋 类型: $package_type
⭐ reF1nd 定制版本"
        
        if send_file "$file" "$caption"; then
            success_files=$((success_files + 1))
        else
            failed_files=$((failed_files + 1))
        fi
        
        # 避免 Telegram API 频率限制
        sleep 2
    fi
done

echo ""
echo "=== 上传完成 ==="
echo "总文件数: $total_files"
echo "成功: $success_files"
echo "失败: $failed_files"

# 发送上传完成通知
if [ $total_files -gt 0 ]; then
    if [ $failed_files -eq 0 ]; then
        status_icon="✅"
        status_text="全部上传成功"
    elif [ $success_files -gt 0 ]; then
        status_icon="⚠️"
        status_text="部分上传成功"
    else
        status_icon="❌"
        status_text="上传失败"
    fi
    
    summary_message="$status_icon **文件上传完成**

📊 **统计信息**:
• 总文件数: \`$total_files\`
• 成功上传: \`$success_files\`
• 失败文件: \`$failed_files\`

🏷️ **版本**: \`$VERSION\`
⭐ **类型**: reF1nd 定制版本"
    
    send_message "$summary_message"
fi

# 返回适当的退出码
if [ $failed_files -gt 0 ]; then
    exit 1
else
    exit 0
fi
