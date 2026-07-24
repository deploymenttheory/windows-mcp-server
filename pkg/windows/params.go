package windows

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ArgsMap unmarshals a tool call's raw arguments into a generic map. Tools that
// need the Python-parity coercions below (bool-or-string, list-or-string) use
// this rather than a typed struct, because some MCP clients (notably Claude
// Desktop) strip anyOf schemas and send booleans and arrays as JSON strings.
func ArgsMap(req *mcp.CallToolRequest) (map[string]any, error) {
	if req == nil || len(req.Params.Arguments) == 0 {
		return map[string]any{}, nil
	}
	var m map[string]any
	if err := json.Unmarshal(req.Params.Arguments, &m); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	if m == nil {
		m = map[string]any{}
	}
	return m, nil
}

// RequiredString returns a required string argument.
func RequiredString(args map[string]any, key string) (string, error) {
	v, ok := args[key]
	if !ok || v == nil {
		return "", fmt.Errorf("missing required parameter: %s", key)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("parameter %s must be a string", key)
	}
	if s == "" {
		return "", fmt.Errorf("required parameter %s is empty", key)
	}
	return s, nil
}

// OptionalString returns a string argument or the fallback when absent.
func OptionalString(args map[string]any, key, fallback string) string {
	if v, ok := args[key]; ok && v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return fallback
}

// OptionalInt returns an int argument or the fallback. It accepts JSON numbers
// and numeric strings.
func OptionalInt(args map[string]any, key string, fallback int) (int, error) {
	v, ok := args[key]
	if !ok || v == nil {
		return fallback, nil
	}
	switch n := v.(type) {
	case float64:
		return int(n), nil
	case int:
		return n, nil
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return fallback, fmt.Errorf("parameter %s must be an integer", key)
		}
		return int(i), nil
	case string:
		if n == "" {
			return fallback, nil
		}
		i, err := strconv.Atoi(strings.TrimSpace(n))
		if err != nil {
			return fallback, fmt.Errorf("parameter %s must be an integer", key)
		}
		return i, nil
	default:
		return fallback, fmt.Errorf("parameter %s must be an integer", key)
	}
}

// OptionalBool returns a bool argument or the fallback. It accepts real JSON
// booleans and the strings "true"/"false" (case-insensitive), matching how some
// MCP clients encode booleans.
func OptionalBool(args map[string]any, key string, fallback bool) bool {
	v, ok := args[key]
	if !ok || v == nil {
		return fallback
	}
	switch b := v.(type) {
	case bool:
		return b
	case string:
		switch strings.ToLower(strings.TrimSpace(b)) {
		case "true", "1", "yes":
			return true
		case "false", "0", "no", "":
			return false
		}
	}
	return fallback
}

// OptionalStringEnum returns a string argument constrained to allowed values,
// falling back when absent. It errors on a present-but-invalid value.
func OptionalStringEnum(args map[string]any, key, fallback string, allowed ...string) (string, error) {
	s := OptionalString(args, key, fallback)
	for _, a := range allowed {
		if s == a {
			return s, nil
		}
	}
	return "", fmt.Errorf("parameter %s must be one of %s", key, strings.Join(allowed, ", "))
}

// OptionalIntSlice returns an []int argument. It accepts a JSON array of numbers
// or a JSON string containing such an array (e.g. "[10, 20]"), matching clients
// that stringify array parameters.
func OptionalIntSlice(args map[string]any, key string) ([]int, error) {
	v, ok := args[key]
	if !ok || v == nil {
		return nil, nil
	}
	switch raw := v.(type) {
	case string:
		if strings.TrimSpace(raw) == "" {
			return nil, nil
		}
		var arr []int
		if err := json.Unmarshal([]byte(raw), &arr); err != nil {
			return nil, fmt.Errorf("parameter %s must be an array of integers", key)
		}
		return arr, nil
	case []any:
		out := make([]int, 0, len(raw))
		for _, e := range raw {
			f, ok := e.(float64)
			if !ok {
				return nil, fmt.Errorf("parameter %s must be an array of integers", key)
			}
			out = append(out, int(f))
		}
		return out, nil
	default:
		return nil, fmt.Errorf("parameter %s must be an array of integers", key)
	}
}
