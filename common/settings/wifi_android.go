//go:build android

package settings

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/wifi"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/logger"
)

const (
	androidNL80211Family      = "nl80211"
	androidWIFIResyncInterval = 30 * time.Second
)

type androidWIFIMonitor struct {
	logger   logger.ContextLogger
	callback func(adapter.WIFIState)
	cancel   context.CancelFunc
}

func newAndroidWIFIMonitor(logger logger.ContextLogger, callback func(adapter.WIFIState)) (WIFIMonitor, error) {
	return &androidWIFIMonitor{logger: logger, callback: callback}, nil
}

func readAndroidWIFIState() (adapter.WIFIState, error) {
	client, err := wifi.New()
	if err != nil {
		return adapter.WIFIState{}, err
	}
	defer client.Close()
	interfaces, err := client.Interfaces()
	if err != nil {
		return adapter.WIFIState{}, err
	}
	for _, networkInterface := range interfaces {
		if networkInterface.Type != wifi.InterfaceTypeStation {
			continue
		}
		bss, err := client.BSS(networkInterface)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return adapter.WIFIState{}, err
		}
		return adapter.WIFIState{
			SSID:  bss.SSID,
			BSSID: bss.BSSID.String(),
		}, nil
	}
	return adapter.WIFIState{}, nil
}

func (m *androidWIFIMonitor) ReadWIFIState(ctx context.Context) adapter.WIFIState {
	state, _ := readAndroidWIFIState()
	return state
}

func (m *androidWIFIMonitor) Start() error {
	if m.callback == nil {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	state, err := readAndroidWIFIState()
	if err != nil {
		m.logger.Warn("read initial WIFI state: ", err)
	} else if state.SSID == "" {
		m.logger.Info("Android WIFI monitor started, not connected")
	} else {
		m.logger.Info("Android WIFI monitor started, SSID=", state.SSID, ", BSSID=", state.BSSID)
	}
	m.callback(state)
	go m.watch(ctx, state)
	return nil
}

func (m *androidWIFIMonitor) watch(ctx context.Context, lastState adapter.WIFIState) {
	events, err := subscribeNL80211Events(ctx)
	if err != nil {
		m.logger.Warn("subscribe Android WIFI events: ", err)
	}
	ticker := time.NewTicker(androidWIFIResyncInterval)
	defer ticker.Stop()
	var lastError error
	for {
		select {
		case <-ctx.Done():
			return
		case <-events:
		case <-ticker.C:
		}
		state, err := readAndroidWIFIState()
		if err != nil {
			if !errors.Is(err, lastError) {
				m.logger.Warn("read WIFI state: ", err)
				lastError = err
			}
			continue
		}
		if lastError != nil {
			m.logger.Info("read WIFI state recovered")
			lastError = nil
		}
		if state != lastState {
			lastState = state
			m.callback(state)
		}
	}
}

func subscribeNL80211Events(ctx context.Context) (<-chan struct{}, error) {
	conn, err := genetlink.Dial(nil)
	if err != nil {
		return nil, err
	}
	family, err := conn.GetFamily(androidNL80211Family)
	if err != nil {
		conn.Close()
		return nil, err
	}
	for _, group := range family.Groups {
		if group.Name == "mlme" || group.Name == "config" {
			if err = conn.JoinGroup(group.ID); err != nil {
				conn.Close()
				return nil, err
			}
		}
	}
	events := make(chan struct{}, 1)
	go func() {
		<-ctx.Done()
		conn.Close()
	}()
	go func() {
		for {
			if _, _, receiveErr := conn.Receive(); receiveErr != nil {
				return
			}
			select {
			case events <- struct{}{}:
			default:
			}
		}
	}()
	return events, nil
}

func (m *androidWIFIMonitor) Close() error {
	if m.cancel != nil {
		m.cancel()
	}
	return nil
}
