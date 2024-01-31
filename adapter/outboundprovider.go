package adapter

import (
	"time"

	"github.com/sagernet/sing-box/option"
)

type OutboundProvider interface {
	Service
	PreStarter
	Tag() string
	DependentOutbound() string
	Outbounds() []Outbound
	Outbound(tag string) (Outbound, bool)
	BasicOutbounds() []Outbound
	FilterOutbounds(matcher OutboundMatcher, invert bool) []Outbound
	Update()
	HealthCheck()
	GetSubsctibeData() OutboundProviderSubscribeData
}

type OutboundProviderSubscribeData struct {
	Update   time.Time `json:"update"`
	Expire   time.Time `json:"expire"`
	Download uint64    `json:"download"`
	Upload   uint64    `json:"upload"`
	Total    uint64    `json:"total"`
}

type OutboundProviderData struct {
	SubscribeData OutboundProviderSubscribeData `json:"subscribeData"`
	Outbounds     []option.Outbound             `json:"outbounds"`
}
