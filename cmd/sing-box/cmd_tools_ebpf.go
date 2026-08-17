//go:build with_ebpf && (linux || android)

package main

import (
	"fmt"
	"os"

	ECommon "github.com/sagernet/sing-box/common/ebpf"
	"github.com/sagernet/sing-box/log"

	"github.com/spf13/cobra"
)

var (
	commandEBPFStatusMode      string
	commandEBPFStatusNetwork   []string
	commandEBPFStatusCgroup    string
	commandEBPFStatusInterface string
	commandEBPFStatusJSON      bool
)

var commandEBPF = &cobra.Command{
	Use:   "ebpf",
	Short: "eBPF diagnostics",
}

var commandEBPFStatus = &cobra.Command{
	Use:   "status",
	Short: "Inspect eBPF inbound kernel support and active state",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		if err := runEBPFStatus(); err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	commandEBPFStatus.Flags().StringVar(&commandEBPFStatusMode, "mode", "all", "Data path to inspect: all, local, or shared-network")
	commandEBPFStatus.Flags().StringSliceVar(&commandEBPFStatusNetwork, "network", []string{"tcp", "udp"}, "Protocols to inspect: tcp, udp, or tcp,udp")
	commandEBPFStatus.Flags().StringVar(&commandEBPFStatusCgroup, "cgroup", "", "Configured cgroup v2 path")
	commandEBPFStatus.Flags().StringVar(&commandEBPFStatusInterface, "interface", "", "Configured shared-network interface")
	commandEBPFStatus.Flags().BoolVar(&commandEBPFStatusJSON, "json", false, "Write the report as JSON")
	commandEBPF.AddCommand(commandEBPFStatus)
	commandTools.AddCommand(commandEBPF)
}

func runEBPFStatus() error {
	report, err := ECommon.ProbeKernel(ECommon.KernelProbeOptions{
		Mode:          ECommon.KernelProbeMode(commandEBPFStatusMode),
		Network:       commandEBPFStatusNetwork,
		CgroupPath:    commandEBPFStatusCgroup,
		InterfaceName: commandEBPFStatusInterface,
	})
	if err != nil {
		return err
	}
	if commandEBPFStatusJSON {
		err = ECommon.WriteKernelProbeReportJSON(os.Stdout, report)
	} else {
		err = ECommon.WriteKernelProbeReport(os.Stdout, report)
	}
	if err != nil {
		return err
	}
	if failures := report.RequiredFailures(); failures > 0 {
		return fmt.Errorf("eBPF kernel capability probe found %d required failure(s)", failures)
	}
	return nil
}
