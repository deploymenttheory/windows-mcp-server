package psdata

import (
	"encoding/base64"
	"strings"
	"testing"
)

// quoteRunes are every character PowerShell's lexer accepts as a single-quote
// delimiter. An escaper that doubles only U+0027 lets the other four terminate a
// literal early, which is the injection this package exists to make impossible.
const quoteRunes = "'\u2018\u2019\u201A\u201B"

// TestBoundValueNeverReachesTheScriptBody is the core invariant: whatever the
// value contains, none of it appears as script text. Only base64 does.
func TestBoundValueNeverReachesTheScriptBody(t *testing.T) {
	payloads := []string{
		"x\u2019; Write-Output PWNED; #",    // the reported smart-quote break-out
		"x'; Write-Output PWNED; #",         // the ASCII form quoting did handle
		"x\u2018; calc; #",                  // left single quote
		"x\u201A; calc; #",                  // single low-9 quote
		"x\u201B; calc; #",                  // single high-reversed-9 quote
		"$(Write-Output PWNED)",             // subexpression
		"`; Write-Output PWNED",             // backtick escape
		"\"; Write-Output PWNED; \"",        // double quote
		"a\r\nWrite-Output PWNED",           // newline statement separator
		"-NoProfile -WhatIf",                // leading dash: must bind as a value
		"C:\\Program Files\\App\\thing.exe", // backslashes
		"\x00\x1b[31m",                      // control characters
		"\u00e9\u4e2d\u6587\U0001F600",      // non-ASCII and astral plane
		strings.Repeat("A", 4096),           // long
		"",                                  // empty
	}

	for _, payload := range payloads {
		var b Builder
		script := b.Script("Get-Item -Path " + b.Arg(payload))

		// The only representation of the value in the script is its base64 form.
		if enc := base64.StdEncoding.EncodeToString([]byte(payload)); !strings.Contains(script, enc) {
			t.Errorf("payload %q: base64 form missing from script", payload)
		}
		// No character the lexer could act on may appear outside the base64 blob.
		for _, r := range quoteRunes {
			if payload != "" && strings.ContainsRune(payload, r) && strings.ContainsRune(script, r) {
				// A quote rune in the script is only legitimate as the two delimiters
				// psdata itself emits around the base64 literal.
				if got := strings.Count(script, string(r)); r != '\'' || got != 2 {
					t.Errorf("payload %q: quote rune %q leaked into script text: %s", payload, r, script)
				}
			}
		}
		if strings.Contains(script, "PWNED") || strings.Contains(script, "calc") {
			t.Errorf("payload %q: literal payload text leaked into script: %s", payload, script)
		}
	}
}

// TestScriptBodyIsSyntacticallyIsolated pins the shape callers depend on: the
// bindings come first, separated from the body, so a body referencing a bound
// variable always finds it in scope.
func TestScriptBodyIsSyntacticallyIsolated(t *testing.T) {
	var b Builder
	a0 := b.Arg("first")
	a1 := b.Arg("second")
	script := b.Script("Do-Thing " + a0 + " " + a1)

	if a0 == a1 {
		t.Fatalf("Arg returned the same reference twice: %q", a0)
	}
	for _, ref := range []string{a0, a1} {
		bindAt := strings.Index(script, ref+" = ")
		if bindAt < 0 {
			t.Fatalf("no binding emitted for %s: %s", ref, script)
		}
		if useAt := strings.Index(script, "Do-Thing"); bindAt > useAt {
			t.Errorf("binding for %s emitted after the body", ref)
		}
	}
}

// TestNoBindingsLeavesBodyUnchanged keeps constant-only commands free of an
// empty binding prefix.
func TestNoBindingsLeavesBodyUnchanged(t *testing.T) {
	var b Builder
	const body = "Get-Process | Select-Object Name"
	if got := b.Script(body); got != body {
		t.Errorf("Script(%q) = %q, want it unchanged", body, got)
	}
}

// TestEncodedValueUsesOnlyInertCharacters is the property the whole design rests
// on: base64's alphabet contains no character the PowerShell lexer treats as a
// delimiter, so a bound value cannot be parsed as code however it is spelled.
func TestEncodedValueUsesOnlyInertCharacters(t *testing.T) {
	var b Builder
	b.Arg("\u2019'\"`$();\r\n\x00")
	script := b.Script("noop")

	start := strings.Index(script, "FromBase64String('")
	if start < 0 {
		t.Fatalf("no base64 literal in %q", script)
	}
	start += len("FromBase64String('")
	end := strings.Index(script[start:], "'")
	if end < 0 {
		t.Fatalf("unterminated base64 literal in %q", script)
	}
	for _, r := range script[start : start+end] {
		isB64 := (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') ||
			(r >= '0' && r <= '9') || r == '+' || r == '/' || r == '='
		if !isB64 {
			t.Errorf("non-base64 character %q inside the encoded literal", r)
		}
	}
}
