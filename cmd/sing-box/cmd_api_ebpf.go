package main

import (
	"os"

	"github.com/sagernet/sing-box/daemon"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
)

var commandAPIEBPFDeep bool

var commandAPIEBPF = &cobra.Command{
	Use:   "ebpf",
	Short: "Print eBPF inbound diagnostics",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runAPIEBPF()
	},
}

func init() {
	commandAPIRoot.AddCommand(commandAPIEBPF)
	commandAPIEBPF.Flags().BoolVar(&commandAPIEBPFDeep, "deep", false, "Inspect owned kernel programs and map occupancy")
}

func runAPIEBPF() error {
	clientConn, client, err := createAPIClient()
	if err != nil {
		return err
	}
	defer clientConn.Close()
	diagnostics, err := client.GetEBPFDiagnostics(globalCtx, &daemon.EBPFDiagnosticsRequest{Deep: commandAPIEBPFDeep})
	if err != nil {
		return err
	}
	output, err := (protojson.MarshalOptions{
		Indent:          "  ",
		UseProtoNames:   true,
		EmitUnpopulated: true,
	}).Marshal(diagnostics)
	if err != nil {
		return err
	}
	output = append(output, '\n')
	_, err = os.Stdout.Write(output)
	return err
}
