//go:build windows && (amd64 || arm64)

package winmcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestCompletionValuesAreAlwaysAnArray guards a bug the Go type system cannot
// see.
//
// `completion.values` is required to be an array. A nil []string is a perfectly
// good Go value that marshals to `null`, so every code path that produced no
// suggestions put `null` on the wire — which the conformance suite reported as
// "completion.values is not an array". The assertion is deliberately made
// against the marshalled bytes rather than the struct: checking len(Values) == 0
// would have passed throughout the entire time the bug existed.
func TestCompletionValuesAreAlwaysAnArray(t *testing.T) {
	inv, _, err := buildInventory(Config{Toolsets: []string{"all"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	handler := completionHandler(inv)

	cases := map[string]*mcp.CompleteParams{
		"no ref at all": {
			Argument: mcp.CompleteParamsArgument{Name: "persona", Value: ""},
		},
		"resource ref is not completed": {
			Ref:      &mcp.CompleteReference{Type: "ref/resource", URI: "windows://desktop/snapshot"},
			Argument: mcp.CompleteParamsArgument{Name: "anything", Value: ""},
		},
		"prompt ref, unknown argument": {
			Ref:      &mcp.CompleteReference{Type: "ref/prompt", Name: "rpa-journey"},
			Argument: mcp.CompleteParamsArgument{Name: "not-an-argument", Value: ""},
		},
		"prompt ref, prefix matches nothing": {
			Ref:      &mcp.CompleteReference{Type: "ref/prompt", Name: "rpa-journey"},
			Argument: mcp.CompleteParamsArgument{Name: "persona", Value: "zzzzz-no-such-persona"},
		},
	}

	for name, params := range cases {
		t.Run(name, func(t *testing.T) {
			res, err := handler(context.Background(), &mcp.CompleteRequest{Params: params})
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(res)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), `"values":null`) {
				t.Errorf("values serialized as null, which is not an array: %s", raw)
			}
			var wire struct {
				Completion struct {
					Values *[]string `json:"values"`
				} `json:"completion"`
			}
			if err := json.Unmarshal(raw, &wire); err != nil {
				t.Fatal(err)
			}
			if wire.Completion.Values == nil {
				t.Errorf("completion.values is absent or null on the wire: %s", raw)
			}
		})
	}
}

// TestCompletionStillSuggests checks the fix did not turn every response into an
// empty array — the handler must still complete a real prompt argument.
func TestCompletionStillSuggests(t *testing.T) {
	inv, _, err := buildInventory(Config{Toolsets: []string{"all"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	res, err := completionHandler(inv)(context.Background(), &mcp.CompleteRequest{
		Params: &mcp.CompleteParams{
			Ref:      &mcp.CompleteReference{Type: "ref/prompt", Name: "rpa-journey"},
			Argument: mcp.CompleteParamsArgument{Name: "persona"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Completion.Values) == 0 {
		t.Error("persona completion returned nothing; the argument should have suggestions")
	}
	if res.Completion.Total != len(res.Completion.Values) {
		t.Errorf("total = %d but %d values returned", res.Completion.Total, len(res.Completion.Values))
	}
}
