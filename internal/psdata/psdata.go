// Package psdata builds PowerShell scripts in which caller-supplied values are
// carried as data rather than interpolated into the script as source text.
//
// It lives in its own package, rather than beside either caller, because both
// pkg/windows (the tool layer) and internal/desktop (the engine) assemble
// PowerShell and pkg/windows already imports internal/desktop — so a shared
// helper in either one would be a cycle or a copy. A security primitive that
// exists twice is one that gets fixed once, so it exists here instead.
//
// The package is deliberately untagged: it is pure string assembly with no
// Windows dependency, so its injection-safety tests run on any platform.
package psdata

import (
	"encoding/base64"
	"strconv"
	"strings"
)

// Builder assembles a PowerShell script in which every caller-supplied value is
// bound to a variable carrying base64 data.
//
// Quoting is not a viable defence here, which is why this type exists. The
// PowerShell lexer closes a single-quoted literal on U+2018, U+2019, U+201A and
// U+201B as well as on U+0027, so an escaper that doubles only the ASCII
// apostrophe lets a value containing a typographic quote terminate its literal
// and begin a new statement. -EncodedCommand does not help: the injection is in
// the script text before it is encoded.
//
// Binding removes the class rather than enumerating it. Base64's alphabet is
// [A-Za-z0-9+/=], which holds no character the lexer treats as a delimiter, so a
// bound value cannot be parsed as code however it is spelled — and it never
// passes through the lexer at all.
//
// The zero value is ready to use.
type Builder struct {
	binds []string
}

// Arg binds v and returns the variable reference to use in the script body.
//
// A variable in argument position is passed as a single value and is not
// re-tokenized, so a value beginning with "-" is bound as an argument and never
// read as a parameter name. Call Arg for every caller-supplied value; never
// concatenate one into the body directly.
func (s *Builder) Arg(v string) string {
	ref := "$wmcpA" + strconv.Itoa(len(s.binds))
	s.binds = append(s.binds, ref+" = "+decodeExpr(v))
	return ref
}

// Script returns body prefixed by the bindings Arg created, so the variables are
// in scope. With no bindings it returns body unchanged.
func (s *Builder) Script(body string) string {
	if len(s.binds) == 0 {
		return body
	}
	return strings.Join(s.binds, "; ") + "; " + body
}

// decodeExpr renders v as a PowerShell expression evaluating to exactly v.
func decodeExpr(v string) string {
	return "[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('" +
		base64.StdEncoding.EncodeToString([]byte(v)) + "'))"
}
