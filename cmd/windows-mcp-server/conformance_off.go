//go:build windows && (amd64 || arm64) && !conformance

package main

import "github.com/spf13/cobra"

// addConformanceCommand is a no-op in a released build.
//
// The conformance host serves the full tool manifest over HTTP with no
// authentication, for the sole purpose of letting the official conformance suite
// connect to it. Keeping it behind a build tag means the shipped binary has no
// listener at all, rather than one guarded by a flag somebody could set.
func addConformanceCommand(*cobra.Command) {}
