package remote

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

func convertToBytes(sizeStr string) int64 {
	sizeStr = strings.TrimSpace(sizeStr)
	if value, err := strconv.ParseInt(sizeStr, 10, 64); err == nil {
		return value
	}
	var unit string
	var value float64
	_, err := fmt.Sscanf(sizeStr, "%f%s", &value, &unit)
	if err != nil {
		return 0
	}

	switch unit {
	case "TB":
		return int64(value * 1024 * 1024 * 1024 * 1024)
	case "GB":
		return int64(value * 1024 * 1024 * 1024)
	case "MB":
		return int64(value * 1024 * 1024)
	case "KB":
		return int64(value * 1024)
	default:
		return 0
	}
}

// parseExpire parses the expire, e.g.:
// 2023-12-05
func convertToUnix(expire string) int64 {
	expire = strings.TrimSpace(expire)
	if value, err := strconv.ParseInt(expire, 10, 64); err == nil {
		return value
	}
	t, err := time.Parse("2006-01-02", expire)
	if err != nil {
		return 0
	}
	return t.Unix()
}

func decodeBase64Safe(content string) string {
	if decode, err := base64.StdEncoding.DecodeString(content); err == nil {
		return string(decode)
	}
	if decode, err := base64.RawStdEncoding.DecodeString(content); err == nil {
		return string(decode)
	}
	if decode, err := base64.URLEncoding.DecodeString(content); err == nil {
		return string(decode)
	}
	if decode, err := base64.RawURLEncoding.DecodeString(content); err == nil {
		return string(decode)
	}
	return content
}

func getFirstLine(content string) (string, string) {
	lines := strings.Split(content, "\n")
	if len(lines) == 1 {
		return lines[0], ""
	}
	others := strings.Join(lines[1:], "\n")
	return lines[0], others
}

func parseInfo(infoStr string) (*adapter.ProviderRemoteInfo, bool) {
	replaceReg := regexp.MustCompile(`([ \t🚀💡#]|STATUS=|".*")+`)
	splitReg := regexp.MustCompile(`[,;]+`)
	infoStr = replaceReg.ReplaceAllString(infoStr, "")
	info := &adapter.ProviderRemoteInfo{
		LastUpdated: time.Now(),
	}
	if infoStr == "" {
		return info, false
	}
	sections := splitReg.Split(infoStr, -1)
	if len(sections) < 2 {
		return info, false
	}
	splitNReg := regexp.MustCompile(`[:=]`)
	for _, section := range sections {
		parts := splitNReg.Split(section, 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		switch key {
		case "↑", "upload":
			info.Upload = convertToBytes(value)
		case "↓", "download":
			info.Download = convertToBytes(value)
		case "TOT", "total":
			info.Total = convertToBytes(value)
		case "Expires", "expire":
			info.Expire = convertToUnix(value)
		case "updated":
			updated, _ := strconv.ParseInt(value, 10, 64)
			info.LastUpdated = time.Unix(updated, 0)
		}
	}
	return info, true
}
