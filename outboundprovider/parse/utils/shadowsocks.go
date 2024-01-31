package utils

func CheckShadowsocksMethod(cipher string) bool {
	switch cipher {
	case "aes-128-gcm":
	case "aes-192-gcm":
	case "aes-256-gcm":
	case "aes-128-cfb":
	case "aes-192-cfb":
	case "aes-256-cfb":
	case "aes-128-ctr":
	case "aes-192-ctr":
	case "aes-256-ctr":
	case "rc4-md5":
	case "chacha20-ietf":
	case "xchacha20":
	case "chacha20-ietf-poly1305":
	case "xchacha20-ietf-poly1305":
	case "2022-blake3-aes-128-gcm":
	case "2022-blake3-aes-256-gcm":
	case "2022-blake3-chacha20-poly1305":
	default:
		return false
	}
	return true
}
