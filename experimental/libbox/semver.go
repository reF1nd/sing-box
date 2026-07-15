package libbox

import (
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/common/badversion"

	"golang.org/x/mod/semver"
)

func CompareSemver(left string, right string) bool {
	leftVersion, leftRevision, loaded := parseComparableSemver(left)
	if !loaded {
		return false
	}
	rightVersion, rightRevision, loaded := parseComparableSemver(right)
	if !loaded {
		return false
	}
	if leftVersion == rightVersion {
		return leftRevision > rightRevision
	}
	return leftVersion.GreaterThan(rightVersion)
}

func parseComparableSemver(version string) (badversion.Version, uint64, bool) {
	normalizedVersion := normalizeSemver(version)
	if !semver.IsValid(normalizedVersion) {
		return badversion.Version{}, 0, false
	}
	const forkSuffix = "-reF1nd"
	suffixIndex := strings.LastIndex(normalizedVersion, forkSuffix)
	if suffixIndex == -1 {
		return badversion.Parse(normalizedVersion), 0, true
	}
	revisionText := normalizedVersion[suffixIndex+len(forkSuffix):]
	var revision uint64
	if revisionText != "" {
		if !strings.HasPrefix(revisionText, ".") {
			return badversion.Parse(normalizedVersion), 0, true
		}
		var err error
		revision, err = strconv.ParseUint(revisionText[1:], 10, 64)
		if err != nil {
			return badversion.Parse(normalizedVersion), 0, true
		}
	}
	baseVersion := normalizedVersion[:suffixIndex]
	if !semver.IsValid(baseVersion) {
		return badversion.Parse(normalizedVersion), 0, true
	}
	return badversion.Parse(baseVersion), revision, true
}

func normalizeSemver(version string) string {
	trimmedVersion := strings.TrimSpace(version)
	if strings.HasPrefix(trimmedVersion, "v") {
		return trimmedVersion
	}
	return "v" + trimmedVersion
}
