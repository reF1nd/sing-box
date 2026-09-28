package main

import (
	"os"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/emptypb"
)

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
}

func runAPIEBPF() error {
	clientConn, client, err := createAPIClient()
	if err != nil {
		return err
	}
	defer clientConn.Close()
	diagnostics, err := client.GetEBPFDiagnostics(globalCtx, &emptypb.Empty{})
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
