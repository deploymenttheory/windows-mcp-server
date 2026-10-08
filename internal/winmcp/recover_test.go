//go:build windows && (amd64 || arm64) && conformance

package winmcp

import (
	"context"
	"io"
	"log/slog"
	"testing"
)

// TestConformanceHostToleratesNoDesktopEngine covers the environment the CI
// runner may actually present. The host must build and serve whether or not a
// desktop engine could be created.
func TestConformanceHostToleratesNoDesktopEngine(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := buildConformanceServer(context.Background(), Config{Toolsets: []string{"all"}}, false, logger)
	if err != nil {
		t.Fatalf("the conformance host must build regardless of engine availability: %v", err)
	}
	if server == nil {
		t.Fatal("no server built")
	}
}
