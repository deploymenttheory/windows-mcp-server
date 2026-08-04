package windows

import "github.com/deploymenttheory/windows-mcp-server/internal/psdata"

// PSScript builds a PowerShell script binding every model-supplied value as data
// instead of interpolating it as source text — the defence against a value
// closing its own string literal and starting a new statement.
//
// It is an alias rather than a wrapper so the tool layer and the desktop engine
// share one implementation; see internal/psdata for why quoting cannot do this
// job and what makes binding safe.
//
// Use it for every model-supplied value that reaches PowerShell:
//
//	var ps PSScript
//	cmd := ps.Script("Get-Item -Path " + ps.Arg(path))
type PSScript = psdata.Builder
