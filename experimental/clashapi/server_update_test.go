package clashapi

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestExternalUIInstallPreservesExistingOnFailure(t *testing.T) {
	for _, name := range []string{"invalid zip", "path traversal", "root file"} {
		t.Run(name, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "ui")
			require.NoError(t, os.Mkdir(directory, 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(directory, "index.html"), []byte("old"), 0o644))
			var body bytes.Buffer
			if name == "invalid zip" {
				body.WriteString("invalid")
			} else {
				writer := zip.NewWriter(&body)
				path := "index.html"
				if name == "path traversal" {
					path = "root/../../escape.html"
				}
				file, err := writer.Create(path)
				require.NoError(t, err)
				_, err = file.Write([]byte("new"))
				require.NoError(t, err)
				require.NoError(t, writer.Close())
			}
			server := &Server{ctx: context.Background(), externalUI: directory}
			err := server.installExternalUI(&body)
			expected := "old"
			if name == "root file" {
				require.NoError(t, err)
				expected = "new"
			} else {
				require.Error(t, err)
			}
			content, err := os.ReadFile(filepath.Join(directory, "index.html"))
			require.NoError(t, err)
			require.Equal(t, expected, string(content))
		})
	}
}

func TestExternalUIConcurrentChecksAndClose(t *testing.T) {
	directory := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(directory, "index.html"), []byte("old"), 0o644))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	server := &Server{ctx: ctx, updateCancel: cancel, externalUI: directory, externalUIUpdateInterval: time.Hour}
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() { _ = server.checkAndDownloadExternalUI(false) })
	}
	workers.Wait()
	require.False(t, server.lastUpdated.IsZero())
	server.updateDone = make(chan struct{})
	go server.loopUpdate()
	require.NoError(t, server.Close())
	require.ErrorIs(t, server.checkAndDownloadExternalUI(false), context.Canceled)
}
