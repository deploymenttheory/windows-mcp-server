//go:build windows && (amd64 || arm64)

package winmcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/deploymenttheory/windows-mcp-server/internal/desktop"
	"github.com/deploymenttheory/windows-mcp-server/internal/journeys"
)

// errNoOutputPath reports a record request with no --out destination.
var errNoOutputPath = errors.New("an output path is required (--out)")

// RecordJourney captures a human's interaction with the desktop and writes it as a
// journey file. It installs input hooks, resolves each click to a UI element and
// each keystroke to a character (redacting password fields), and on stop compiles
// the captured stream into a journey via journeys.Emit.
//
// Recording ends when the user presses the stop key (F9) or ctx is cancelled. The
// result is a reviewable draft: the recorded steps, with password input redacted,
// for a human to confirm and augment with assertions before checking it in.
func RecordJourney(ctx context.Context, cfg Config, name, out string) (journeys.Journey, error) {
	if out == "" {
		return journeys.Journey{}, errNoOutputPath
	}

	logger, cleanup, err := newLogger(cfg.LogFile)
	if err != nil {
		return journeys.Journey{}, err
	}
	defer cleanup()

	// The engine owns its own lifetime; see the note in RunStdio.
	dsk, err := desktop.New(logger, desktop.Options{}) //nolint:contextcheck // owns its lifetime
	if err != nil {
		return journeys.Journey{}, fmt.Errorf("failed to start desktop engine: %w", err)
	}
	defer func() { _ = dsk.Close() }()

	// Collect the mapped events as they arrive. RecordInput runs the callback on its
	// own goroutine; a mutex is unnecessary because we only read `events` after
	// RecordInput returns.
	var events []journeys.Event
	err = dsk.RecordInput(ctx, desktop.DefaultRecordStopKey, func(in desktop.RecordedInput) {
		if e, ok := mapRecordedInput(in); ok {
			events = append(events, e)
		}
	})
	if err != nil {
		return journeys.Journey{}, fmt.Errorf("record input: %w", err)
	}

	journey := journeys.Emit(name, events)
	blob, err := json.MarshalIndent(journey, "", "  ")
	if err != nil {
		return journeys.Journey{}, fmt.Errorf("render journey: %w", err)
	}
	// 0o600 rather than 0o644. A journey is not meant to hold a secret, but that
	// rests entirely on the recorder's redaction being right, and redaction depends
	// on UIA being able to report the focused element. Write it owner-only so a
	// redaction miss is not also world-readable. (The mode is advisory on Windows,
	// where the file inherits the directory ACL; it states the intent.)
	if err := os.WriteFile(out, blob, 0o600); err != nil {
		return journeys.Journey{}, fmt.Errorf("write journey %s: %w", out, err)
	}
	return journey, nil
}

// mapRecordedInput converts one engine-level recorded action into a journey event.
// It reports ok=false for an action that produces no event.
func mapRecordedInput(in desktop.RecordedInput) (journeys.Event, bool) {
	switch in.Kind {
	case "click":
		return elementEvent(journeys.EventClick, in), true
	case "assert":
		return elementEvent(journeys.EventAssert, in), true
	case "char":
		return journeys.Event{Kind: journeys.EventChar, Char: in.Char, Secure: in.Secure}, true
	case "key":
		return journeys.Event{Kind: journeys.EventKey, Key: in.Key}, true
	default:
		return journeys.Event{}, false
	}
}

// elementEvent maps a hit-tested capture — a click or a mark — into the emitter's
// vocabulary, carrying both the identity of the element and what it can do.
func elementEvent(kind journeys.EventKind, in desktop.RecordedInput) journeys.Event {
	return journeys.Event{
		Kind: kind,
		X:    in.X, Y: in.Y,
		// The automation id is read at every hit-test and used to be dropped here,
		// so recordings were keyed on the accessible name while the one identifier
		// that survives translation sat unused in the same struct.
		AutomationID: in.Element.AutomationID,
		Name:         in.Element.Name,
		ControlType:  in.Element.ControlType,
		Button:       in.Button,
		Double:       in.Double,
		Facts: journeys.ElementFacts{
			Value:             in.State.Value,
			Checked:           in.State.Checked,
			Selected:          in.State.Selected,
			Enabled:           in.State.Enabled,
			Expanded:          in.State.Expanded,
			HasValue:          in.State.HasValue,
			HasToggle:         in.State.HasToggle,
			HasSelection:      in.State.HasSelection,
			HasInvoke:         in.State.HasInvoke,
			HasExpandCollapse: in.State.HasExpandCollapse,
		},
	}
}
