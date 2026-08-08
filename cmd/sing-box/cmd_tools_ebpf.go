//go:build with_ebpf && (linux || android)

package main

import (
	"os"
	"os/exec"
	"strings"

	ECommon "github.com/sagernet/sing-box/common/ebpf"
	"github.com/sagernet/sing-box/log"

	"github.com/spf13/cobra"
)

var (
	commandEBPFStatusMode      string
	commandEBPFStatusCgroup    string
	commandEBPFStatusInterface string
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
	commandEBPFStatus.Flags().StringVar(&commandEBPFStatusCgroup, "cgroup", "", "Configured cgroup v2 path")
	commandEBPFStatus.Flags().StringVar(&commandEBPFStatusInterface, "interface", "", "Configured shared-network interface")
	commandEBPF.AddCommand(commandEBPFStatus)
	commandTools.AddCommand(commandEBPF)
}

func runEBPFStatus() error {
	arguments := []string{"-s", "--", "--mode", commandEBPFStatusMode}
	if commandEBPFStatusCgroup != "" {
		arguments = append(arguments, "--cgroup", commandEBPFStatusCgroup)
	}
	if commandEBPFStatusInterface != "" {
		arguments = append(arguments, "--interface", commandEBPFStatusInterface)
	}
	command := exec.CommandContext(globalCtx, "sh", arguments...)
	command.Stdin = strings.NewReader(ECommon.KernelCheckScript())
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	return command.Run()
}
