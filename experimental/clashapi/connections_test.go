package clashapi

import (
	"encoding/json"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/trafficcontrol"
)

func TestConnectionObjectPreferAndroidPackageName(t *testing.T) {
	connection := connectionObject(trafficcontrol.TrackerMetadata{
		Metadata: adapter.InboundContext{
			ProcessInfo: &adapter.ConnectionOwner{
				UserId:              -1,
				ProcessPath:         "/system/bin/app_process64",
				AndroidPackageNames: []string{"io.nekohasekai.sfa"},
			},
		},
		Upload:   new(atomic.Int64),
		Download: new(atomic.Int64),
	})
	response, err := connection.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var content struct {
		Metadata struct {
			ProcessPath string `json:"processPath"`
		} `json:"metadata"`
	}
	err = json.Unmarshal(response, &content)
	if err != nil {
		t.Fatal(err)
	}
	if content.Metadata.ProcessPath != "io.nekohasekai.sfa" {
		t.Fatalf("unexpected process path: %s", content.Metadata.ProcessPath)
	}
}
