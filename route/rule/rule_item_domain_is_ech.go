package rule

import (
	"strings"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
)

type domainIsECHItem struct{}

func (domainIsECHItem) Match(metadata *adapter.InboundContext) bool {
	return metadata.SniffHasECHExtension &&
		(metadata.Protocol == C.ProtocolTLS || metadata.Protocol == C.ProtocolQUIC) &&
		metadata.SniffHost != "" &&
		strings.EqualFold(metadata.SniffHost, metadata.ECHPublicName)
}

func (domainIsECHItem) String() string {
	return "domain_is_ech=true"
}
