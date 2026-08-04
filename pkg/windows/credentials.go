//go:build windows && (amd64 || arm64)

package windows

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/deploymenttheory/windows-mcp-server/internal/desktop"
	"github.com/deploymenttheory/windows-mcp-server/pkg/inventory"
)

// Credentials exposes the credentials supplied to the server at startup.
//
// The security property this tool is built around: it can *use* a secret but can
// never *reveal* one. There is deliberately no action that returns plaintext. The
// inject action reads the secret inside the desktop engine and converts it
// straight to keystrokes, so the value never enters a tool result, the audit log,
// the conversation transcript, or the model's context — only the number of
// characters typed comes back.
func Credentials() inventory.ServerTool {
	return NewToolFromHandler(
		ToolsetCredentials,
		mcp.Tool{
			Name: "Credentials",
			Description: "Use credentials supplied to this server at startup and held in the Windows Credential Manager. " +
				"Modes: 'list' reports the available credentials (names, targets, usernames — never secrets); " +
				"'verify' checks one is still present; 'inject' types a credential's secret into a field, " +
				"optionally clicking a target first (by 'label'/'name' from the last Snapshot, or explicit 'loc' [x,y]).\n\n" +
				"Secrets cannot be read: no mode returns a credential's value, so use 'inject' to sign in rather than " +
				"trying to retrieve a password. Refer to credentials by their 'name'.",
			Annotations: &mcp.ToolAnnotations{
				Title:        "Credentials list/verify/inject",
				ReadOnlyHint: false, // inject synthesizes input
			},
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"mode": {
						Type:        "string",
						Description: "list (default), verify, or inject.",
						Enum:        []any{"list", "verify", "inject"},
					},
					"name": {
						Type:        "string",
						Description: "Credential name, as reported by mode 'list'. Required for verify and inject.",
					},
					"label": {
						Type:        "integer",
						Description: "Optional: click this Snapshot label (e.g. the password field) before typing.",
					},
					"name_target": {
						Type:        "string",
						Description: "Optional: click the element with this UIA name before typing (alternative to label).",
					},
					"control_type": {
						Type:        "string",
						Description: "Optional: narrow name_target to this control type (e.g. Edit).",
					},
					"nth": {
						Type:        "integer",
						Description: "Optional: which name_target match to use when several share a name (0-based).",
					},
					"loc": {
						Type:        "array",
						Description: "Optional: click these [x,y] physical pixels before typing.",
						Items:       &jsonschema.Schema{Type: "integer"},
					},
					"press_enter": {
						Type:        "boolean",
						Description: "Optional: press Enter after injecting, to submit the form.",
					},
				},
				Required: []string{"mode"},
			},
		},
		credentialsHandler,
	)
}

func credentialsHandler(_ context.Context, deps ToolDependencies, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args, err := ArgsMap(req)
	if err != nil {
		return NewToolResultError(err.Error()), nil
	}
	mode, err := OptionalStringEnum(args, "mode", "list", "list", "verify", "inject")
	if err != nil {
		return NewToolResultError(err.Error()), nil
	}

	registry := deps.Credentials()
	if len(registry) == 0 {
		return NewToolResultError("no credentials are configured; start the server with --credentials-file " +
			"to supply credentials at init"), nil
	}

	switch mode {
	case "list":
		return credentialsList(deps, registry)
	case "verify":
		return credentialsVerify(deps, registry, args)
	default:
		return credentialsInject(deps, registry, args)
	}
}

// credentialsList reports the configured credentials with live presence, and
// never includes a secret.
func credentialsList(deps ToolDependencies, registry []desktop.CredentialInfo) (*mcp.CallToolResult, error) {
	out := make([]desktop.CredentialInfo, 0, len(registry))
	for _, c := range registry {
		c.Present, _ = deps.Desktop().CredentialPresent(c.Target, desktop.CredentialType(c.Type))
		c.Injectable = desktop.CredentialType(c.Type).Readable()
		out = append(out, c)
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return NewToolResultErrorFromErr("failed to render credential list", err), nil
	}
	return NewToolResultText(string(b)), nil
}

func credentialsVerify(
	deps ToolDependencies,
	registry []desktop.CredentialInfo,
	args map[string]any,
) (*mcp.CallToolResult, error) {
	cred, err := lookupCredential(registry, args)
	if err != nil {
		return NewToolResultError(err.Error()), nil
	}
	present, err := deps.Desktop().CredentialPresent(cred.Target, desktop.CredentialType(cred.Type))
	if err != nil {
		return NewToolResultErrorFromErr("failed to check the credential store", err), nil
	}
	if !present {
		return NewToolResultTextf("Credential %q (target %q) is NOT present in the Windows Credential Manager.",
			cred.Name, cred.Target), nil
	}
	return NewToolResultTextf("Credential %q (target %q, username %q) is present and %s.",
		cred.Name, cred.Target, cred.Username,
		map[bool]string{true: "injectable", false: "write-only (Windows will not return its secret)"}[cred.Injectable],
	), nil
}

// credentialsInject types the secret, optionally clicking a target field first so
// the click and the keystrokes are one serialized operation and no other window
// can take focus between them.
func credentialsInject(
	deps ToolDependencies,
	registry []desktop.CredentialInfo,
	args map[string]any,
) (*mcp.CallToolResult, error) {
	cred, err := lookupCredential(registry, args)
	if err != nil {
		return NewToolResultError(err.Error()), nil
	}

	clickAt, err := resolveCredentialTarget(deps, args)
	if err != nil {
		return NewToolResultError(err.Error()), nil
	}

	// The engine confirms, on the STA thread and immediately before typing, that
	// the destination masks its input — unless this credential opts out. See
	// desktop.requireMaskedFocus.
	typed, err := deps.Desktop().InjectCredential(
		cred.Target, desktop.CredentialType(cred.Type), clickAt, cred.AllowUnmaskedTarget)
	if err != nil {
		// A refused destination is a decision the model can act on — retarget, or
		// ask the operator for the opt-out — so it gets the remedy spelled out
		// rather than reading as an engine failure.
		if errors.Is(err, desktop.ErrInjectTargetNotMasked) {
			return NewToolResultErrorf("%s%s", err.Error(), desktop.InjectRemedy()), nil
		}
		return NewToolResultErrorFromErr(fmt.Sprintf("failed to inject credential %q", cred.Name), err), nil
	}

	pressEnter := OptionalBool(args, "press_enter", false)
	if pressEnter {
		if err := deps.Desktop().SendShortcut([]string{"enter"}); err != nil {
			return NewToolResultErrorFromErr("injected the credential but failed to press Enter", err), nil
		}
	}

	// The character count is safe to report and confirms the injection happened;
	// the value itself is never returned.
	msg := fmt.Sprintf("Injected credential %q (%d characters) for target %q.", cred.Name, typed, cred.Target)
	if pressEnter {
		msg += " Pressed Enter."
	}
	return NewToolResultText(msg + " Take a Snapshot to confirm the result."), nil
}

// resolveCredentialTarget maps the optional click-target arguments to a point.
// It reuses the shared label/name/loc resolution so credential injection targets
// elements exactly the way Click and Type do. Returns nil for "type at focus".
func resolveCredentialTarget(deps ToolDependencies, args map[string]any) (*desktop.Point, error) {
	// resolveTarget reads the element name from "name", which this tool uses for
	// the credential name; expose it as "name_target" and translate here.
	local := map[string]any{}
	for k, v := range args {
		if k == "name" {
			continue
		}
		local[k] = v
	}
	if nt, ok := args["name_target"]; ok {
		local["name"] = nt
	}

	x, y, ok, err := resolveTarget(deps, local)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil // type at the current focus
	}
	return &desktop.Point{X: x, Y: y}, nil
}

// lookupCredential resolves the required "name" argument to a configured entry.
func lookupCredential(registry []desktop.CredentialInfo, args map[string]any) (desktop.CredentialInfo, error) {
	name, err := RequiredString(args, "name")
	if err != nil {
		return desktop.CredentialInfo{}, err
	}
	for _, c := range registry {
		if c.Name == name {
			c.Injectable = desktop.CredentialType(c.Type).Readable()
			return c, nil
		}
	}
	available := make([]string, 0, len(registry))
	for _, c := range registry {
		available = append(available, c.Name)
	}
	return desktop.CredentialInfo{}, fmt.Errorf("no credential named %q; configured credentials: %v", name, available)
}
