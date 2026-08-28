package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseScenariosAll(t *testing.T) {
	scenarios, err := parseScenarios("all")
	require.NoError(t, err)
	require.Equal(t, []string{
		"tcp-short",
		"tcp-upload",
		"tcp-download",
		"udp-pps",
		"udp-unconnected-pps",
		"udp-churn",
	}, scenarios)
}

func TestParseScenariosDeduplicates(t *testing.T) {
	scenarios, err := parseScenarios("udp-churn,tcp-short,udp-churn")
	require.NoError(t, err)
	require.Equal(t, []string{"udp-churn", "tcp-short"}, scenarios)
}

func TestParseScenariosRejectsUnknown(t *testing.T) {
	_, err := parseScenarios("udp-burst")
	require.Error(t, err)
}
