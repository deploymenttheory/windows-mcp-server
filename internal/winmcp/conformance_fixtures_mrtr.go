//go:build windows && (amd64 || arm64) && conformance

package winmcp

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The fixtures in this file arm the SEP-2322 (multi-round-trip), SEP-2243
// (x-mcp-header) and remaining SEP-2575 scenarios. None of them fakes a wire
// behaviour: the input_required result shape, the requestState echo, the
// header-to-argument validation and the response-stream discipline are all
// implemented by go-sdk v1.7.0 itself (mcp/mrtr.go, mcp/streamable_headers.go).
// A handler here only decides *when* to ask for input; the SDK owns how that
// looks on the wire, and the suite measures it through this server's real
// middleware chain.

// mrtrStateKey signs requestState envelopes. Per-process is enough: SEP-2322
// state only has to survive the rounds of one suite run against one host, and
// a fresh key on restart just means an old state verifies as tampered — which
// is the correct answer to replaying state across server generations.
var mrtrStateKey = newMRTRStateKey()

func newMRTRStateKey() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic("conformance fixture could not draw a requestState key: " + err.Error())
	}
	return key
}

// mrtrStateEnvelope is what a requestState decodes to: the payload this server
// minted plus the HMAC that proves it minted it.
type mrtrStateEnvelope struct {
	Data string `json:"data"`
	HMAC string `json:"hmac"`
}

// signMRTRState wraps a payload as base64(JSON{data, hmac}). SEP-2322 requires
// servers to integrity-protect requestState because the client echoes it back
// verbatim; HMAC-SHA256 is the real mechanism, not a tamper-marker heuristic,
// so *any* mutation of the state fails verification, not just the suite's
// "-TAMPERED" suffix.
func signMRTRState(payload string) string {
	mac := hmac.New(sha256.New, mrtrStateKey)
	mac.Write([]byte(payload))
	envelope, err := json.Marshal(mrtrStateEnvelope{Data: payload, HMAC: hex.EncodeToString(mac.Sum(nil))})
	if err != nil {
		panic("conformance fixture could not marshal a requestState envelope: " + err.Error())
	}
	return base64.StdEncoding.EncodeToString(envelope)
}

// verifyMRTRState returns the signed payload, or an error on any decode, parse
// or MAC failure. The suite tampers by appending a suffix, which breaks the
// base64 framing and lands in the first branch; a subtler forgery fails the MAC.
func verifyMRTRState(state string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(state)
	if err != nil {
		return "", fmt.Errorf("requestState is not the base64 envelope this server issues: %w", err)
	}
	var envelope mrtrStateEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return "", fmt.Errorf("requestState envelope does not parse: %w", err)
	}
	claimed, err := hex.DecodeString(envelope.HMAC)
	if err != nil {
		return "", fmt.Errorf("requestState HMAC is not hex: %w", err)
	}
	mac := hmac.New(sha256.New, mrtrStateKey)
	mac.Write([]byte(envelope.Data))
	if !hmac.Equal(mac.Sum(nil), claimed) {
		return "", errMRTRStateForged
	}
	return envelope.Data, nil
}

// errMRTRStateForged marks a requestState whose envelope parses but whose MAC
// was not produced by this process.
var errMRTRStateForged = errors.New("requestState HMAC does not verify")

// mrtrStateRejection is the refusal for a requestState that fails verification.
// The scenario asserts only that a JSON-RPC error comes back; the code and
// message match the SDK's own reference server.
func mrtrStateRejection() error {
	return &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "requestState integrity check failed"}
}

// acceptedElicitContent returns the content of an accepted ElicitResult under
// exactly the given key, or nil when the response is absent, of another type,
// or not an acceptance. Keying on the exact name matters: the
// missing-input-response scenario answers under a wrong key and expects a
// re-request, not a completion.
func acceptedElicitContent(responses mcp.InputResponseMap, key string) map[string]any {
	resp, ok := responses[key]
	if !ok {
		return nil
	}
	elicit, ok := resp.(*mcp.ElicitResult)
	if !ok || elicit == nil || elicit.Action != "accept" {
		return nil
	}
	return elicit.Content
}

// samplingResponseText extracts the first text block of a sampling response.
// The SDK unmarshals role-bearing responses as *CreateMessageWithToolsResult,
// the superset of the legacy single-content shape.
//
//nolint:staticcheck // the SEP-2322 scenarios request the SEP-2577-deprecated sampling shapes by design
func samplingResponseText(responses mcp.InputResponseMap, key string) (string, bool) {
	resp, ok := responses[key].(*mcp.CreateMessageWithToolsResult)
	if !ok || resp == nil {
		return "", false
	}
	for _, c := range resp.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			return tc.Text, true
		}
	}
	return "(non-text response)", true
}

func mrtrTextResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}
}

func nameElicitRequest(message string) *mcp.ElicitParams {
	return &mcp.ElicitParams{
		Message: message,
		RequestedSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"name": map[string]any{"type": "string"}},
			"required":   []any{"name"},
		},
	}
}

func confirmElicitRequest() *mcp.ElicitParams {
	return &mcp.ElicitParams{
		Message: "Please confirm",
		RequestedSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"ok": map[string]any{"type": "boolean"}},
			"required":   []any{"ok"},
		},
	}
}

// registerMRTRFixtures adds the SEP-2322 / SEP-2243 / SEP-2575 diagnostic
// fixtures. Called only from registerConformanceFixtures, so everything here
// obeys the same contract: conformance tag only, appended to reg so the
// rug-pull baselines are pinned over the manifest actually served.
func registerMRTRFixtures(server *mcp.Server, reg *conformanceFixtures) {
	addTool := func(name, description string, handler mcp.ToolHandler) {
		addFixtureTool(server, reg, name, description, handler)
	}

	addTool("test_input_required_result_elicitation",
		"MRTR (SEP-2322): asks for the caller name via an in-band elicitation request.",
		mrtrElicitationFixture)
	addTool("test_input_required_result_sampling",
		"MRTR (SEP-2322): asks for an LLM completion via an in-band sampling request.",
		mrtrSamplingFixture)
	addTool("test_input_required_result_list_roots",
		"MRTR (SEP-2322): asks for the client roots via an in-band roots/list request.",
		mrtrListRootsFixture)
	addTool("test_input_required_result_request_state",
		"MRTR (SEP-2322): round-trips integrity-protected requestState alongside an elicitation request.",
		mrtrRequestStateFixture)
	addTool("test_input_required_result_multiple_inputs",
		"MRTR (SEP-2322): asks for elicitation, sampling and roots input in a single round.",
		mrtrMultipleInputsFixture)
	addTool("test_input_required_result_multi_round",
		"MRTR (SEP-2322): two elicitation rounds with evolving requestState before completing.",
		mrtrMultiRoundFixture)
	addTool("test_input_required_result_tampered_state",
		"MRTR (SEP-2322): rejects retries whose requestState fails integrity verification.",
		mrtrTamperedStateFixture)
	addTool("test_input_required_result_capabilities",
		"MRTR (SEP-2322): only requests input kinds the declared client capabilities cover.",
		mrtrCapabilitiesFixture)

	// SEP-2575: the check watches the tools/call response stream and fails on any
	// frame carrying a method other than notifications/*. A plain result is the
	// honest implementation — the scenario's probe declares only the elicitation
	// capability and the requirement under test is that the server does NOT
	// initiate an interaction on the stream.
	addTool("test_streaming_elicitation",
		"Diagnostic (SEP-2575): the response stream must carry only this call's frames, "+
			"never an independent server-initiated request.",
		streamingObservationFixture)

	// SEP-2243: the scenario finds the first tool whose schema carries an
	// x-mcp-header annotation on a string property, then drives Mcp-Param-*
	// acceptance and rejection cases against it. Validation itself — literal vs
	// =?base64?...?= decoding, strict padding, header/body mismatch → -32020 over
	// HTTP 400 — happens in the SDK transport before this handler runs; the
	// handler exists so the acceptance cases have something to execute.
	headerTool := &mcp.Tool{
		Name:        "test_x_mcp_header",
		Description: "Diagnostic (SEP-2243): declares a parameter mirrored into the Mcp-Param-Region header.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"region": map[string]any{
					"type":         "string",
					"description":  "mirrored into Mcp-Param-Region",
					"x-mcp-header": "Region",
				},
				"level": map[string]any{"type": "integer", "description": "non-mirrored argument"},
			},
		},
		Annotations: &mcp.ToolAnnotations{Title: "test_x_mcp_header", ReadOnlyHint: true},
	}
	server.AddTool(headerTool, xMCPHeaderFixture)
	reg.Tools = append(reg.Tools, headerTool)

	prompt := &mcp.Prompt{
		Name:        "test_input_required_result_prompt",
		Description: "MRTR (SEP-2322): a prompt that elicits its context before returning messages.",
	}
	server.AddPrompt(prompt, mrtrPromptFixture)
	reg.Prompts = append(reg.Prompts, prompt)
}

// mrtrElicitationFixture completes only on an accepted response under exactly
// "user_name"; anything else — first call, wrong key, extra unknown keys — is
// answered with a fresh request for that key. It never issues requestState, and
// the SDK already rejects structurally invalid inputResponses before the
// handler runs, which together cover the result-type, missing-input-response,
// ignore-extra-params and validate-input checks that reuse this tool.
func mrtrElicitationFixture(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if content := acceptedElicitContent(req.Params.InputResponses, "user_name"); content != nil {
		if name, _ := content["name"].(string); name != "" {
			return mrtrTextResult(fmt.Sprintf("Hello, %s!", name)), nil
		}
	}
	return &mcp.CallToolResult{
		InputRequests: mcp.InputRequestMap{"user_name": nameElicitRequest("What is your name?")},
	}, nil
}

//nolint:staticcheck // the SEP-2322 scenarios request the SEP-2577-deprecated sampling shapes by design
func mrtrSamplingFixture(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if text, ok := samplingResponseText(req.Params.InputResponses, "capital_question"); ok {
		return mrtrTextResult("Sampling response: " + text), nil
	}
	return &mcp.CallToolResult{
		InputRequests: mcp.InputRequestMap{
			"capital_question": &mcp.CreateMessageParams{
				Messages: []*mcp.SamplingMessage{
					{Role: "user", Content: &mcp.TextContent{Text: "What is the capital of France?"}},
				},
				MaxTokens: 100,
			},
		},
	}, nil
}

//nolint:staticcheck // the SEP-2322 scenarios request the SEP-2577-deprecated roots shapes by design
func mrtrListRootsFixture(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if resp, ok := req.Params.InputResponses["client_roots"].(*mcp.ListRootsResult); ok && resp != nil {
		uris := make([]string, 0, len(resp.Roots))
		for _, root := range resp.Roots {
			uris = append(uris, root.URI)
		}
		return mrtrTextResult(fmt.Sprintf("Client exposed %d root(s): %s",
			len(resp.Roots), strings.Join(uris, ", "))), nil
	}
	return &mcp.CallToolResult{
		InputRequests: mcp.InputRequestMap{"client_roots": &mcp.ListRootsParams{}},
	}, nil
}

func mrtrRequestStateFixture(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if content := acceptedElicitContent(req.Params.InputResponses, "confirm"); content != nil {
		if _, err := verifyMRTRState(req.Params.RequestState); err != nil {
			return nil, mrtrStateRejection()
		}
		return mrtrTextResult("state-ok: requestState verified and confirmation accepted"), nil
	}
	return &mcp.CallToolResult{
		InputRequests: mcp.InputRequestMap{"confirm": confirmElicitRequest()},
		RequestState:  signMRTRState("request-state"),
	}, nil
}

//nolint:staticcheck // the SEP-2322 scenarios request the SEP-2577-deprecated sampling/roots shapes by design
func mrtrMultipleInputsFixture(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	name, _ := acceptedElicitContent(req.Params.InputResponses, "user_name")["name"].(string)
	greeting, hasGreeting := samplingResponseText(req.Params.InputResponses, "greeting")
	rootsResp, hasRoots := req.Params.InputResponses["client_roots"].(*mcp.ListRootsResult)

	if name != "" && hasGreeting && hasRoots && rootsResp != nil {
		return mrtrTextResult(fmt.Sprintf("%s %s — %d root(s) visible",
			greeting, name, len(rootsResp.Roots))), nil
	}
	return &mcp.CallToolResult{
		InputRequests: mcp.InputRequestMap{
			"user_name": nameElicitRequest("What is your name?"),
			"greeting": &mcp.CreateMessageParams{
				Messages: []*mcp.SamplingMessage{
					{Role: "user", Content: &mcp.TextContent{Text: "Generate a greeting"}},
				},
				MaxTokens: 50,
			},
			"client_roots": &mcp.ListRootsParams{},
		},
		RequestState: signMRTRState("multiple-inputs"),
	}, nil
}

// mrtrMultiRoundFixture keeps the round number and the name elicited in round
// one inside the signed payload — the host is stateless, so requestState is the
// only memory there is. The two rounds' payloads differ by construction, which
// is what makes the suite's "state must change between rounds" assertion hold.
func mrtrMultiRoundFixture(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if req.Params.RequestState == "" {
		return &mcp.CallToolResult{
			InputRequests: mcp.InputRequestMap{"step1": nameElicitRequest("Step 1: What is your name?")},
			RequestState:  signMRTRState("round=1"),
		}, nil
	}
	payload, err := verifyMRTRState(req.Params.RequestState)
	if err != nil {
		return nil, mrtrStateRejection()
	}
	if payload == "round=1" {
		name, _ := acceptedElicitContent(req.Params.InputResponses, "step1")["name"].(string)
		if name == "" {
			name = "unknown"
		}
		return &mcp.CallToolResult{
			InputRequests: mcp.InputRequestMap{
				"step2": &mcp.ElicitParams{
					Message: "Step 2: What is your favorite color?",
					RequestedSchema: map[string]any{
						"type":       "object",
						"properties": map[string]any{"color": map[string]any{"type": "string"}},
						"required":   []any{"color"},
					},
				},
			},
			RequestState: signMRTRState("round=2;name=" + name),
		}, nil
	}
	color, _ := acceptedElicitContent(req.Params.InputResponses, "step2")["color"].(string)
	if color == "" {
		color = "unknown"
	}
	name := strings.TrimPrefix(payload, "round=2;name=")
	return mrtrTextResult(fmt.Sprintf("Multi-round complete: %s likes %s", name, color)), nil
}

func mrtrTamperedStateFixture(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if req.Params.RequestState != "" {
		if _, err := verifyMRTRState(req.Params.RequestState); err != nil {
			return nil, mrtrStateRejection()
		}
		if acceptedElicitContent(req.Params.InputResponses, "confirm") != nil {
			return mrtrTextResult("state-ok: requestState verified and confirmation accepted"), nil
		}
	}
	return &mcp.CallToolResult{
		InputRequests: mcp.InputRequestMap{"confirm": confirmElicitRequest()},
		RequestState:  signMRTRState("tampered-state-probe"),
	}, nil
}

// mrtrCapabilitiesFixture only asks for input kinds the client declared, read
// from the per-request _meta envelope. The scenario declares sampling alone and
// asserts that no elicitation/create request appears in the answer.
//
//nolint:staticcheck // the SEP-2322 scenarios request the SEP-2577-deprecated sampling/roots shapes by design
func mrtrCapabilitiesFixture(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if len(req.Params.InputResponses) > 0 {
		return mrtrTextResult("Capability-aware input requests fulfilled"), nil
	}
	caps := req.ClientCapabilities()
	requests := mcp.InputRequestMap{}
	if caps != nil && caps.Elicitation != nil {
		requests["user_name"] = nameElicitRequest("What is your name?")
	}
	if caps != nil && caps.Sampling != nil {
		requests["greeting"] = &mcp.CreateMessageParams{
			Messages: []*mcp.SamplingMessage{
				{Role: "user", Content: &mcp.TextContent{Text: "Generate a short greeting"}},
			},
			MaxTokens: 50,
		}
	}
	if caps != nil && (caps.RootsV2 != nil || caps.Roots.ListChanged) {
		requests["client_roots"] = &mcp.ListRootsParams{}
	}
	if len(requests) == 0 {
		return mrtrTextResult("No declared client capability supports an in-band input request"), nil
	}
	return &mcp.CallToolResult{InputRequests: requests}, nil
}

// streamingObservationFixture returns a plain result. The requirement under
// test is negative — no server-initiated request may appear on the response
// stream — and this server has no elicitation flow to suppress, so a plain
// response is the truthful demonstration, exactly as in the SDK's reference
// server.
func streamingObservationFixture(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return mrtrTextResult("stream observed: result frames only, no top-level requests"), nil
}

// xMCPHeaderFixture echoes the header-mirrored argument. By the time it runs,
// the SDK has already enforced that Mcp-Param-Region and the body agree.
func xMCPHeaderFixture(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args struct {
		Region string `json:"region"`
	}
	if len(req.Params.Arguments) > 0 {
		if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
			return nil, fmt.Errorf("x-mcp-header fixture arguments did not parse: %w", err)
		}
	}
	return mrtrTextResult("region=" + args.Region), nil
}

// mrtrPromptFixture is the prompts/get analogue: SEP-2322 applies to prompts
// too, and the suite's non-tool scenario asserts the same two-round shape with
// a GetPromptResult carrying messages at the end.
func mrtrPromptFixture(_ context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	if content := acceptedElicitContent(req.Params.InputResponses, "user_context"); content != nil {
		contextText, _ := content["context"].(string)
		return &mcp.GetPromptResult{
			Description: "A prompt with elicited context",
			Messages: []*mcp.PromptMessage{
				{Role: "user", Content: &mcp.TextContent{Text: "Context: " + contextText}},
			},
		}, nil
	}
	return &mcp.GetPromptResult{
		InputRequests: mcp.InputRequestMap{
			"user_context": &mcp.ElicitParams{
				Message: "Please provide context for the prompt",
				RequestedSchema: map[string]any{
					"type":       "object",
					"properties": map[string]any{"context": map[string]any{"type": "string"}},
					"required":   []any{"context"},
				},
			},
		},
	}, nil
}
