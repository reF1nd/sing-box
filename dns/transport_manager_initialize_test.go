package dns

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
)

type initializeTestTransport struct {
	adapter.DNSTransport
	stages []adapter.StartStage
}

func (*initializeTestTransport) Type() string           { return "local" }
func (*initializeTestTransport) Tag() string            { return "local" }
func (*initializeTestTransport) Dependencies() []string { return nil }
func (t *initializeTestTransport) Start(stage adapter.StartStage) error {
	t.stages = append(t.stages, stage)
	return nil
}

func TestImplicitDefaultDNSReceivesInitialize(t *testing.T) {
	transport := new(initializeTestTransport)
	manager := NewTransportManager(log.NewNOPFactory().Logger(), nil, nil, "")
	manager.Initialize(func() (adapter.DNSTransport, error) { return transport, nil })
	for _, stage := range adapter.ListStartStages {
		if err := manager.Start(stage); err != nil {
			t.Fatal(err)
		}
	}
	if len(transport.stages) != len(adapter.ListStartStages) {
		t.Fatalf("stages=%v", transport.stages)
	}
	for i, stage := range adapter.ListStartStages {
		if transport.stages[i] != stage {
			t.Fatalf("stages=%v", transport.stages)
		}
	}
}
