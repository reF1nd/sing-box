//go:build with_ebpf && (linux || android)

package main

import (
	"fmt"
	"os"

	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
	"github.com/sagernet/sing-box/log"

	"github.com/spf13/cobra"
)

var (
	commandEBPFStatusMode      string
	commandEBPFStatusNetwork   []string
	commandEBPFStatusInterface string
	commandEBPFStatusIPv6      bool
	commandEBPFStatusJSON      bool
)

var commandEBPF = &cobra.Command{
	Use:   "ebpf",
	Short: "eBPF diagnostics",
}

var commandEBPFStatus = &cobra.Command{
	Use:   "status",
	Short: "Inspect eBPF inbound kernel support",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		if err := runEBPFStatus(); err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	commandEBPFStatus.Flags().StringVar(&commandEBPFStatusMode, "mode", "all", "Data path to inspect: all, local, or shared")
	commandEBPFStatus.Flags().StringSliceVar(&commandEBPFStatusNetwork, "network", []string{"tcp", "udp"}, "Protocols to inspect: tcp, udp, or tcp,udp")
	commandEBPFStatus.Flags().StringVar(&commandEBPFStatusInterface, "interface", "", "Configured shared interface")
	commandEBPFStatus.Flags().BoolVar(&commandEBPFStatusIPv6, "ipv6", true, "Inspect IPv6 support for the selected data path")
	commandEBPFStatus.Flags().BoolVar(&commandEBPFStatusJSON, "json", false, "Write the report as JSON")
	commandEBPF.AddCommand(commandEBPFStatus)
	commandTools.AddCommand(commandEBPF)
}

func runEBPFStatus() error {
	mode := commonEBPF.KernelProbeMode(commandEBPFStatusMode)
	report, err := commonEBPF.ProbeKernel(commonEBPF.KernelProbeOptions{
		Mode:          mode,
		Network:       commandEBPFStatusNetwork,
		InterfaceName: commandEBPFStatusInterface,
		EnableIPv6:    commandEBPFStatusIPv6,
	})
	if err != nil {
		return err
	}
	if commandEBPFStatusJSON {
		err = commonEBPF.WriteKernelProbeReportJSON(os.Stdout, report)
	} else {
		err = commonEBPF.WriteKernelProbeReport(os.Stdout, report)
	}
	if err != nil {
		return err
	}
	if issues := report.RequiredIssues(); issues > 0 {
		return fmt.Errorf("eBPF kernel capability probe found %d required issue(s): %w", issues, report.RequiredError())
	}
	return nil
}
