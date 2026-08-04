package windows

import (
	"path/filepath"
	"strings"
)

// normalizeProtectedPath renders a path in the one form protected-path matching
// compares, so the same file cannot be reached under a different spelling.
//
// Windows accepts several names for one file that filepath.Clean does not fold
// together, and each was a way past the guard:
//
//	\\?\C:\...          the extended-length prefix. Clean preserves it and
//	                    os.OpenFile honours it, so it never equalled the
//	                    stored path.
//	C:\file.txt::$DATA  the default data stream, which is the file itself.
//	C:\file.txt.        a trailing dot, which Windows strips when opening.
//	C:\file.txt         a trailing space, likewise.
//
// All four now normalize to the same string, so one rule covers them.
//
// Deliberately still not folded, and the reason this stays a guardrail rather
// than a sandbox: 8.3 short names (PROGRA~1), hard links, and UNC-to-self
// (\\localhost\C$\...) all reach the file under another name. Closing those needs
// the path opened and compared by file ID, which is a larger change; the
// shell toolset reaches these files with no check at all, which is why it
// requires an explicit acknowledgement.
func normalizeProtectedPath(path string) string {
	p := strings.ToLower(strings.TrimSpace(path))

	// The extended-length prefix, in both its plain and UNC forms.
	const extPrefix = `\\?\`
	const extUNCPrefix = `\\?\unc\`
	switch {
	case strings.HasPrefix(p, extUNCPrefix):
		p = `\\` + p[len(extUNCPrefix):]
	case strings.HasPrefix(p, extPrefix):
		p = p[len(extPrefix):]
	}

	// An explicit data stream names the same bytes as the file itself.
	if i := strings.Index(p, "::$"); i >= 0 {
		p = p[:i]
	}

	p = filepath.Clean(p)

	// Windows ignores trailing dots and spaces when opening a path; Clean does not.
	return strings.TrimRight(p, ". ")
}
