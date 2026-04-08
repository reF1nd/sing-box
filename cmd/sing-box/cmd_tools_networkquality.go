package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sagernet/sing-box/common/networkquality"
	"github.com/sagernet/sing-box/log"

	"github.com/spf13/cobra"
)

var (
	commandNetworkQualityFlagConfigURL  string
	commandNetworkQualityFlagSerial     bool
	commandNetworkQualityFlagMaxRuntime int
)

var commandNetworkQuality = &cobra.Command{
	Use:   "networkquality",
	Short: "Run a network quality test",
	Run: func(cmd *cobra.Command, args []string) {
		err := runNetworkQuality()
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	commandNetworkQuality.Flags().StringVar(
		&commandNetworkQualityFlagConfigURL,
		"config-url", "",
		"Network quality test config URL (default: Apple mensura)",
	)
	commandNetworkQuality.Flags().BoolVar(
		&commandNetworkQualityFlagSerial,
		"serial", false,
		"Run download and upload tests sequentially instead of in parallel",
	)
	commandNetworkQuality.Flags().IntVar(
		&commandNetworkQualityFlagMaxRuntime,
		"max-runtime", int(networkquality.DefaultMaxRuntime/time.Second),
		"Network quality maximum runtime in seconds",
	)
	commandTools.AddCommand(commandNetworkQuality)
}

func runNetworkQuality() error {
	instance, err := createPreStartedClient()
	if err != nil {
		return err
	}
	defer instance.Close()

	dialer, err := createDialer(instance, commandToolsFlagOutbound)
	if err != nil {
		return err
	}

	httpClient := networkquality.NewHTTPClient(dialer)
	defer httpClient.CloseIdleConnections()

	fmt.Fprintln(os.Stderr, "==== NETWORK QUALITY TEST ====")

	result, err := networkquality.Run(networkquality.Options{
		ConfigURL:  commandNetworkQualityFlagConfigURL,
		HTTPClient: httpClient,
		Serial:     commandNetworkQualityFlagSerial,
		MaxRuntime: time.Duration(commandNetworkQualityFlagMaxRuntime) * time.Second,
		Context:    globalCtx,
		OnProgress: func(p networkquality.Progress) {
			if !commandNetworkQualityFlagSerial && p.Phase != networkquality.PhaseIdle {
				fmt.Fprintf(os.Stderr, "\rDownload: %s  RPM: %d  Upload: %s  RPM: %d",
					formatBitrate(p.DownloadCapacity), p.DownloadRPM,
					formatBitrate(p.UploadCapacity), p.UploadRPM)
				return
			}
			switch networkquality.Phase(p.Phase) {
			case networkquality.PhaseIdle:
				if p.IdleLatencyMs > 0 {
					fmt.Fprintf(os.Stderr, "\rIdle Latency: %d ms", p.IdleLatencyMs)
				} else {
					fmt.Fprint(os.Stderr, "\rMeasuring idle latency...")
				}
			case networkquality.PhaseDownload:
				fmt.Fprintf(os.Stderr, "\rDownload: %s  RPM: %d",
					formatBitrate(p.DownloadCapacity), p.DownloadRPM)
			case networkquality.PhaseUpload:
				fmt.Fprintf(os.Stderr, "\rUpload: %s  RPM: %d",
					formatBitrate(p.UploadCapacity), p.UploadRPM)
			}
		},
	})
	if err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, strings.Repeat("-", 40))
	fmt.Fprintf(os.Stderr, "Idle Latency:            %d ms\n", result.IdleLatencyMs)
	fmt.Fprintf(os.Stderr, "Download Capacity:       %-20s Accuracy: %s\n", formatBitrate(result.DownloadCapacity), result.DownloadCapacityAccuracy)
	fmt.Fprintf(os.Stderr, "Upload Capacity:         %-20s Accuracy: %s\n", formatBitrate(result.UploadCapacity), result.UploadCapacityAccuracy)
	fmt.Fprintf(os.Stderr, "Download Responsiveness: %-20s Accuracy: %s\n", fmt.Sprintf("%d RPM", result.DownloadRPM), result.DownloadRPMAccuracy)
	fmt.Fprintf(os.Stderr, "Upload Responsiveness:   %-20s Accuracy: %s\n", fmt.Sprintf("%d RPM", result.UploadRPM), result.UploadRPMAccuracy)
	return nil
}

func formatBitrate(bps int64) string {
	switch {
	case bps >= 1_000_000_000:
		return fmt.Sprintf("%.1f Gbps", float64(bps)/1_000_000_000)
	case bps >= 1_000_000:
		return fmt.Sprintf("%.1f Mbps", float64(bps)/1_000_000)
	case bps >= 1_000:
		return fmt.Sprintf("%.1f Kbps", float64(bps)/1_000)
	default:
		return fmt.Sprintf("%d bps", bps)
	}
}
