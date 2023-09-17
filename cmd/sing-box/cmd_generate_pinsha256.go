package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"

	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/spf13/cobra"
)

var commandGeneratePinSHA256 = &cobra.Command{
	// openssl x509 -noout -fingerprint -sha256 -in certificate.crt
	Use:   "pinsha256 certificate.crt",
	Short: "Generate SHA256 fingerprint for a certificate file",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		err := generatePinSHA256(args)
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	commandGenerate.AddCommand(commandGeneratePinSHA256)
}

func generatePinSHA256(args []string) error {
	file, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	block, _ := pem.Decode(file)
	if block == nil {
		return E.New("pem decode error")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(cert.Raw)
	os.Stdout.WriteString("SHA256 fingerprint: " + hex.EncodeToString(hash[:]) + "\n")
	return nil
}
