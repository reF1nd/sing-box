package option

import (
	"testing"

	"github.com/sagernet/sing/common/json"
	"github.com/stretchr/testify/require"
)

func TestSnellInboundMultiUserAuthentication(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr bool
	}{
		{
			name:    "default userkey",
			content: `{"version":5,"psk":"server-key","users":[{"name":"alice","userkey":"alice-key"}]}`,
		},
		{
			name:    "per-user psk",
			content: `{"version":5,"multi_user_authentication":"psk","users":[{"name":"alice","psk":"alice-key"}]}`,
		},
		{
			name:    "psk mode rejects top-level psk presence",
			content: `{"version":5,"psk":"","multi_user_authentication":"psk","users":[{"psk":"alice-key"}]}`,
			wantErr: true,
		},
		{
			name:    "psk mode rejects empty userkey presence",
			content: `{"version":5,"multi_user_authentication":"psk","users":[{"psk":"alice-key","userkey":""}]}`,
			wantErr: true,
		},
		{
			name:    "psk mode rejects null userkey presence",
			content: `{"version":5,"multi_user_authentication":"psk","users":[{"psk":"alice-key","userkey":null}]}`,
			wantErr: true,
		},
		{
			name:    "userkey mode rejects empty psk presence",
			content: `{"version":5,"psk":"server-key","users":[{"userkey":"alice-key","psk":""}]}`,
			wantErr: true,
		},
		{
			name:    "userkey mode rejects null psk presence",
			content: `{"version":5,"psk":"server-key","users":[{"userkey":"alice-key","psk":null}]}`,
			wantErr: true,
		},
		{
			name:    "mode requires users",
			content: `{"version":5,"psk":"server-key","multi_user_authentication":"userkey"}`,
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var options SnellInboundOptions
			err := json.Unmarshal([]byte(test.content), &options)
			if test.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestSnellOutboundVersionsAndNetwork(t *testing.T) {
	for version := 1; version <= 6; version++ {
		var options SnellOutboundOptions
		require.NoError(t, json.Unmarshal([]byte(`{"server":"127.0.0.1","server_port":1080,"psk":"password","version":`+string(rune('0'+version))+`,"network":["tcp","udp"]}`), &options))
		require.Equal(t, version, options.Version)
		require.Equal(t, NetworkList("tcp\nudp"), options.Network)
	}
	var v6Options SnellOutboundOptions
	require.Error(t, json.Unmarshal([]byte(`{"server":"127.0.0.1","server_port":1080,"psk":"password1234","version":6,"obfs_mode":"tls"}`), &v6Options))
}
