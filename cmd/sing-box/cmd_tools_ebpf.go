//go:build with_ebpf && (linux || android)

package main

import (
	"fmt"
	"os"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	"github.com/sagernet/sing-box/log"

	"github.com/spf13/cobra"
)

var (
	commandEBPFStatusMode       string
	commandEBPFStatusLocal      string
	commandEBPFStatusShared     string
	commandEBPFStatusNetwork    []string
	commandEBPFStatusInterface  string
	commandEBPFStatusLocalIface string
	commandEBPFStatusCgroupPath string
	commandEBPFStatusIPv6       bool
	commandEBPFStatusJSON       bool
	commandEBPFStatusFakeIPICMP bool
	commandEBPFStatusProcess    bool
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
	commandEBPFStatus.Flags().StringVar(&commandEBPFStatusLocal, "local-data-plane", "", "Local data plane: tc or cgroup (empty uses --mode)")
	commandEBPFStatus.Flags().StringVar(&commandEBPFStatusShared, "shared-data-plane", "", "Shared data plane: socket_assign or packet_rewrite (empty uses --mode)")
	commandEBPFStatus.Flags().StringSliceVar(&commandEBPFStatusNetwork, "network", []string{"tcp", "udp"}, "Protocols to inspect: tcp, udp, or tcp,udp")
	commandEBPFStatus.Flags().StringVar(&commandEBPFStatusInterface, "interface", "", "Configured shared interface")
	commandEBPFStatus.Flags().StringVar(&commandEBPFStatusLocalIface, "local-interface", "", "Interface to inspect for local TC (read-only)")
	commandEBPFStatus.Flags().StringVar(&commandEBPFStatusCgroupPath, "cgroup-path", "", "Cgroup v2 path to inspect for local cgroup (empty uses the current process cgroup)")
	commandEBPFStatus.Flags().BoolVar(&commandEBPFStatusIPv6, "ipv6", true, "Inspect IPv6 support for the selected data path")
	commandEBPFStatus.Flags().BoolVar(&commandEBPFStatusJSON, "json", false, "Write the report as JSON")
	commandEBPFStatus.Flags().BoolVar(&commandEBPFStatusFakeIPICMP, "fakeip-icmp", false, "Also inspect fakeip_icmp=reply support")
	commandEBPFStatus.Flags().BoolVar(&commandEBPFStatusProcess, "process-tracking", false, "Also inspect optional process tracking support")
	commandEBPF.AddCommand(commandEBPFStatus)
	commandTools.AddCommand(commandEBPF)
}

func runEBPFStatus() error {
	mode := commonEBPF.KernelProbeMode(commandEBPFStatusMode)
	var interfaceNames []string
	if commandEBPFStatusInterface != "" {
		interfaceNames = []string{commandEBPFStatusInterface}
	}
	report, err := commonEBPF.ProbeKernel(commonEBPF.KernelProbeOptions{
		Mode:                mode,
		LocalDataPlane:      commonEBPF.KernelProbeDataPlane(commandEBPFStatusLocal),
		SharedDataPlane:     commonEBPF.KernelProbeDataPlane(commandEBPFStatusShared),
		Network:             commandEBPFStatusNetwork,
		InterfaceNames:      interfaceNames,
		LocalInterface:      commandEBPFStatusLocalIface,
		CgroupPath:          commandEBPFStatusCgroupPath,
		EnableIPv6:          commandEBPFStatusIPv6,
		ICMPEchoReply:       commandEBPFStatusFakeIPICMP,
		NeedProcessTracking: commandEBPFStatusProcess,
		VerifyObjectLoad:    true,
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
