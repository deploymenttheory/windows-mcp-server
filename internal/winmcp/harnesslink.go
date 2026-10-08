//go:build windows && (amd64 || arm64)

package winmcp

// harnesslink is the server's side of the agentweave-harness control channel.
// The servant contract — hello/hello.ack, signal evaluation by declared id
// only, a closed actuation rung set, liveness and lifecycle pushes — lives in
// mcp-server-core/runtime; what is Windows-specific is the transport. The
// bootstrap contract names a named pipe here, dialed with go-winio directly
// rather than through the harness's internal transport.

import (
	"fmt"
	"io"
	"time"

	"github.com/Microsoft/go-winio"

	"github.com/deploymenttheory/agentweave-harness/wire"
	"github.com/deploymenttheory/mcp-server-core/runtime"
)

// dialHarness connects to the control channel named pipe. Governed servers
// implement their own dialer against the documented bootstrap contract rather
// than importing the harness's internal transport; this is that dialer.
func dialHarness(pipe string) (io.ReadWriteCloser, error) {
	timeout := 10 * time.Second
	conn, err := winio.DialPipe(pipe, &timeout)
	if err != nil {
		return nil, fmt.Errorf("harness: dial %s: %w", pipe, err)
	}
	return conn, nil
}

// attachHarness dials the control channel and completes the handshake.
func attachHarness(
	pipe, token, serverVersion, sessionStamp string,
	deps runtime.ServantDeps,
) (*runtime.HarnessServant, wire.HelloAck, error) {
	s, ack, err := runtime.AttachHarness(dialHarness, pipe, token, serverVersion, sessionStamp, deps)
	if err != nil {
		return nil, wire.HelloAck{}, fmt.Errorf("attach: %w", err)
	}
	return s, ack, nil
}

// installedCredentialNames extracts the identifiers of installed credentials
// for a credential.event. Names only — the never-read invariant means a value
// never reaches this layer to leak.
func installedCredentialNames(creds []installedCredential) []string {
	names := make([]string, 0, len(creds))
	for _, c := range creds {
		names = append(names, c.Name)
	}
	return names
}
