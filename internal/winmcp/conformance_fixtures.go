//go:build windows && (amd64 || arm64) && conformance

package winmcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The conformance suite's server scenarios are written against a fixture server:
// tools/call, resources/read and prompts/get scenarios name the exact tool,
// URI and prompt they invoke, and the exact payload they expect back. Upstream's
// own reference is an "everything-server" (typescript-sdk's
// src/conformance/everything-server.ts). Without these names registered, every
// such scenario fails for want of a fixture and the suite never exercises a
// handler at all.
//
// They are compiled only under the `conformance` build tag and registered only
// when --fixtures is passed, so they cannot reach a released binary or a real
// session. Payloads below are copied from the scenario descriptions verbatim; a
// paraphrase fails the check.
//
// The SEP-2322 (multi-round-trip), SEP-2243 (x-mcp-header) and remaining
// SEP-2575 diagnostics live in conformance_fixtures_mrtr.go. They used to be
// deliberately absent on the grounds that a fixture would fake a protocol
// behaviour; go-sdk v1.7.0 implements all three natively (mcp/mrtr.go,
// mcp/streamable_headers.go), so those fixtures now exercise the SDK's real
// wire machinery through this server's real middleware chain.
//
// Still deliberately NOT implemented, because each would mean advertising a
// feature this server does not have:
//
//   - test_tool_with_logging, test_sampling, test_elicitation and the SEP-1034 /
//     SEP-1330 elicitation fixtures — removed at 2026-07-28 anyway, and roots,
//     sampling and logging are deprecated by SEP-2577.
//   - test_trigger_tool_change / test_trigger_prompt_change — these prove a
//     list-changed-capable server notifies listen streams. pinnedCapabilities
//     pins ListChanged false on purpose, so implementing them would contradict
//     the capability we declare.
//
// Each of those is recorded in the baseline with its reason.
const (
	fixtureSimpleText   = "This is a simple text response for testing."
	fixtureStaticText   = "This is the content of the static text resource."
	fixtureEmbeddedText = "This is an embedded resource content."

	uriStaticText   = "test://static-text"
	uriStaticBinary = "test://static-binary"
	uriEmbedded     = "test://embedded-resource"
	uriMixed        = "test://mixed-content-resource"
	uriTemplate     = "test://template/{id}/data"
)

// A real 1x1 red PNG and a real 44-byte mono WAV. The suite checks the mimeType
// and that the payload is valid base64; using genuine files means a stricter
// future check cannot turn into a mystery failure.
var (
	fixturePNG = mustDecode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAAXNSR0IArs4c6QAAAARn" +
		"QU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAANSURBVBhXY/jPwPAfAAUAAf+mXJtdAAAAAElFTkSuQmCC")
	fixtureWAV = mustDecode("UklGRiUAAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQEAAACA")
)

func mustDecode(b64 string) []byte {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		panic("conformance fixture is not valid base64: " + err.Error())
	}
	return raw
}

// conformanceFixtures reports what was registered, so the rug-pull baselines can
// be pinned over the manifest the server will actually serve.
type conformanceFixtures struct {
	Tools     []*mcp.Tool
	Prompts   []*mcp.Prompt
	Resources []*mcp.Resource
}

// registerConformanceFixtures adds the suite's fixtures when enabled, and
// reports what it added. With enabled false it registers nothing — that is the
// product pass, where the suite measures the manifest this server really ships.
func registerConformanceFixtures(server *mcp.Server, enabled bool) conformanceFixtures {
	if !enabled {
		return conformanceFixtures{}
	}
	var reg conformanceFixtures

	addTool := func(name, description string, handler mcp.ToolHandler) {
		addFixtureTool(server, &reg, name, description, handler)
	}

	addTool("test_simple_text", "Returns a fixed text content block.", textFixture)
	addTool("test_image_content", "Returns a fixed image content block.", imageFixture)
	addTool("test_audio_content", "Returns a fixed audio content block.", audioFixture)
	addTool("test_multiple_content_types", "Returns text, image and resource blocks.", multiFixture)
	addTool("test_embedded_resource", "Returns an embedded resource content block.", embeddedFixture)
	addTool("test_error_handling", "Always fails, to exercise isError reporting.", errorFixture)
	addTool("test_tool_with_progress", "Emits progress notifications when given a token.", progressFixture)

	// SEP-2575 diagnostics. These are structural probes the suite calls to observe
	// how the server behaves, not features it expects the server to have.
	addTool("test_missing_capability",
		"Requires the client to declare the sampling capability; rejects the call when it is absent.",
		missingCapabilityFixture)
	addTool("test_logging_tool",
		"Would log during execution. Used to observe that no notifications/message is emitted "+
			"when the request omits io.modelcontextprotocol/logLevel.",
		loggingFixture)

	// SEP-1613 / SEP-2106 keyword preservation. The schema below is the one the
	// scenario names, verbatim: it checks that $schema, $defs, additionalProperties,
	// allOf/anyOf, if/then/else and $anchor all survive the round trip to
	// tools/list. This is the one fixture whose *schema* is the fixture.
	jsonSchemaTool := &mcp.Tool{
		Name:        "json_schema_2020_12_tool",
		Description: "Tool with JSON Schema 2020-12 features",
		InputSchema: jsonSchema2020_12Schema(),
		Annotations: &mcp.ToolAnnotations{Title: "json_schema_2020_12_tool", ReadOnlyHint: true},
	}
	server.AddTool(jsonSchemaTool, textFixture)
	reg.Tools = append(reg.Tools, jsonSchemaTool)

	staticText := &mcp.Resource{
		URI: uriStaticText, Name: "static-text",
		Description: "Fixed text resource for conformance testing.", MIMEType: "text/plain",
	}
	server.AddResource(
		staticText,
		func(_ context.Context, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{
				{URI: uriStaticText, MIMEType: "text/plain", Text: fixtureStaticText},
			}}, nil
		},
	)
	staticBinary := &mcp.Resource{
		URI: uriStaticBinary, Name: "static-binary",
		Description: "Fixed binary resource for conformance testing.", MIMEType: "image/png",
	}
	server.AddResource(
		staticBinary,
		func(_ context.Context, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{
				{URI: uriStaticBinary, MIMEType: "image/png", Blob: fixturePNG},
			}}, nil
		},
	)
	reg.Resources = append(reg.Resources, staticText, staticBinary)

	// Templates live in a collection disjoint from fixed resources: they surface
	// under resources/templates/list, never resources/list, so this one is not
	// added to reg.Resources.
	server.AddResourceTemplate(&mcp.ResourceTemplate{
		URITemplate: uriTemplate, Name: "template-data",
		Description: "Templated resource for conformance testing.", MIMEType: "application/json",
	}, templateFixture)

	addPrompt := func(prompt *mcp.Prompt, handler mcp.PromptHandler) {
		server.AddPrompt(prompt, handler)
		reg.Prompts = append(reg.Prompts, prompt)
	}
	addPrompt(&mcp.Prompt{Name: "test_simple_prompt", Description: "A simple prompt with no arguments."},
		simplePromptFixture)
	addPrompt(&mcp.Prompt{
		Name:        "test_prompt_with_arguments",
		Description: "A prompt that echoes its arguments.",
		Arguments: []*mcp.PromptArgument{
			{Name: "arg1", Description: "First test argument", Required: true},
			{Name: "arg2", Description: "Second test argument", Required: true},
		},
	}, argsPromptFixture)
	addPrompt(&mcp.Prompt{
		Name:        "test_prompt_with_embedded_resource",
		Description: "A prompt carrying an embedded resource.",
		Arguments: []*mcp.PromptArgument{
			{Name: "resourceUri", Description: "URI of the resource to embed", Required: true},
		},
	}, embeddedPromptFixture)
	addPrompt(&mcp.Prompt{Name: "test_prompt_with_image", Description: "A prompt carrying an image."},
		imagePromptFixture)

	registerMRTRFixtures(server, &reg)

	return reg
}

// addFixtureTool registers a no-argument fixture tool and records it for the
// rug-pull baseline. Shared by this file and conformance_fixtures_mrtr.go.
func addFixtureTool(server *mcp.Server, reg *conformanceFixtures, name, description string, handler mcp.ToolHandler) {
	tool := &mcp.Tool{
		Name:        name,
		Description: description,
		InputSchema: emptyObjectSchema(),
		Annotations: &mcp.ToolAnnotations{Title: name, ReadOnlyHint: true},
	}
	server.AddTool(tool, handler)
	reg.Tools = append(reg.Tools, tool)
}

// emptyObjectSchema is the no-argument input schema. It is written out rather
// than inferred so the fixtures carry the same hand-written schema shape the
// product tools do.
func emptyObjectSchema() any {
	return map[string]any{"type": "object", "properties": map[string]any{}}
}

// jsonSchema2020_12Schema is the schema the SEP-1613 / SEP-2106 scenario names.
//
// It is reproduced exactly as the scenario specifies, because the schema *is*
// the fixture: the checks read it back off tools/list and assert that $schema,
// $defs, additionalProperties, the composition keywords, the conditional
// keywords and $anchor all survived. Any simplification here would test a
// simpler question than the one being asked.
func jsonSchema2020_12Schema() any {
	return map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"type":    "object",
		"$defs": map[string]any{
			"address": map[string]any{
				"$anchor": "addressDef",
				"type":    "object",
				"properties": map[string]any{
					"street": map[string]any{"type": "string"},
					"city":   map[string]any{"type": "string"},
				},
			},
		},
		"properties": map[string]any{
			"name":          map[string]any{"type": "string"},
			"address":       map[string]any{"$ref": "#/$defs/address"},
			"contactMethod": map[string]any{"type": "string", "enum": []any{"phone", "email"}},
			"phone":         map[string]any{"type": "string"},
			"email":         map[string]any{"type": "string"},
		},
		"allOf": []any{
			map[string]any{"anyOf": []any{
				map[string]any{"required": []any{"phone"}},
				map[string]any{"required": []any{"email"}},
			}},
		},
		"if": map[string]any{
			"properties": map[string]any{"contactMethod": map[string]any{"const": "phone"}},
			"required":   []any{"contactMethod"},
		},
		"then":                 map[string]any{"required": []any{"phone"}},
		"else":                 map[string]any{"required": []any{"email"}},
		"additionalProperties": false,
	}
}

// missingCapabilityFixture refuses unless the client declared the sampling
// capability in the per-request _meta.
//
// SEP-2575 gives servers a way to say "this needs something you did not offer",
// and the suite needs a tool that exercises it. The product manifest requires no
// client capability at all — genuinely, not as an omission — so this behaviour
// only exists as a diagnostic, which is exactly what a fixture is for.
func missingCapabilityFixture(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if caps, ok := req.Params.Meta[mcp.MetaKeyClientCapabilities].(map[string]any); ok {
		if _, declared := caps["sampling"]; declared {
			return &mcp.CallToolResult{Content: []mcp.Content{
				&mcp.TextContent{Text: "sampling capability was declared"},
			}}, nil
		}
	}
	return nil, &jsonrpc.Error{
		Code:    mcp.CodeMissingRequiredClientCapabilities,
		Message: "this tool requires the sampling capability",
		Data:    json.RawMessage(`{"requiredCapabilities":{"sampling":{}}}`),
	}
}

// loggingFixture is a tool that would log during execution.
//
// It emits nothing, which is the point: the check watches the response stream
// and fails if a notifications/message appears for a request that did not set
// io.modelcontextprotocol/logLevel. This server never emits one — logging is
// deprecated by SEP-2577 and it logs to stderr or a file instead — so the tool
// only has to exist for the requirement to be observable.
func loggingFixture(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return &mcp.CallToolResult{Content: []mcp.Content{
		&mcp.TextContent{Text: "executed without emitting a log notification"},
	}}, nil
}

func textFixture(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fixtureSimpleText}}}, nil
}

func imageFixture(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return &mcp.CallToolResult{Content: []mcp.Content{
		&mcp.ImageContent{Data: fixturePNG, MIMEType: "image/png"},
	}}, nil
}

func audioFixture(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return &mcp.CallToolResult{Content: []mcp.Content{
		&mcp.AudioContent{Data: fixtureWAV, MIMEType: "audio/wav"},
	}}, nil
}

func multiFixture(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return &mcp.CallToolResult{Content: []mcp.Content{
		&mcp.TextContent{Text: "Multiple content types test:"},
		&mcp.ImageContent{Data: fixturePNG, MIMEType: "image/png"},
		&mcp.EmbeddedResource{Resource: &mcp.ResourceContents{
			URI: uriMixed, MIMEType: "application/json", Text: `{"test":"data","value":123}`,
		}},
	}}, nil
}

func embeddedFixture(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return &mcp.CallToolResult{Content: []mcp.Content{
		&mcp.EmbeddedResource{Resource: &mcp.ResourceContents{
			URI: uriEmbedded, MIMEType: "text/plain", Text: fixtureEmbeddedText,
		}},
	}}, nil
}

// errorFixture returns an IsError result with a nil Go error, which is both this
// project's convention and what the scenario expects: a JSON-RPC *success* whose
// body carries isError true.
func errorFixture(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{
			&mcp.TextContent{Text: "This tool intentionally returns an error for testing"},
		},
	}, nil
}

// progressFixture emits 0/100, 50/100 and 100/100 when the request carries a
// progress token, with the delays the scenario asks for so a client has to handle
// more than one notification arriving during a single call.
func progressFixture(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	token := req.Params.GetProgressToken()
	for _, progress := range []float64{0, 50, 100} {
		if token != nil {
			_ = req.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{
				ProgressToken: token, Progress: progress, Total: 100,
			})
		}
		if progress < 100 {
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("progress fixture interrupted: %w", ctx.Err())
			case <-time.After(50 * time.Millisecond):
			}
		}
	}
	return &mcp.CallToolResult{Content: []mcp.Content{
		&mcp.TextContent{Text: "Progress tool completed"},
	}}, nil
}

// templateFixture substitutes the {id} segment. The URI is parsed rather than
// pattern-matched because the SDK routes the request here only when the template
// already matched, so the id is whatever sits between the fixed segments.
func templateFixture(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	id := templateID(req.Params.URI)
	return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{
		URI:      req.Params.URI,
		MIMEType: "application/json",
		Text:     fmt.Sprintf(`{"id":"%s","templateTest":true,"data":"Data for ID: %s"}`, id, id),
	}}}, nil
}

func templateID(uri string) string {
	const prefix, suffix = "test://template/", "/data"
	if len(uri) > len(prefix)+len(suffix) &&
		uri[:len(prefix)] == prefix && uri[len(uri)-len(suffix):] == suffix {
		return uri[len(prefix) : len(uri)-len(suffix)]
	}
	return ""
}

func simplePromptFixture(context.Context, *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	return &mcp.GetPromptResult{Messages: []*mcp.PromptMessage{
		{Role: "user", Content: &mcp.TextContent{Text: "This is a simple prompt for testing."}},
	}}, nil
}

func argsPromptFixture(_ context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	args := req.Params.Arguments
	return &mcp.GetPromptResult{Messages: []*mcp.PromptMessage{{
		Role: "user",
		Content: &mcp.TextContent{
			Text: fmt.Sprintf("Prompt with arguments: arg1='%s', arg2='%s'", args["arg1"], args["arg2"]),
		},
	}}}, nil
}

func embeddedPromptFixture(_ context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	return &mcp.GetPromptResult{Messages: []*mcp.PromptMessage{
		{Role: "user", Content: &mcp.EmbeddedResource{Resource: &mcp.ResourceContents{
			URI:      req.Params.Arguments["resourceUri"],
			MIMEType: "text/plain",
			Text:     "Embedded resource content for testing.",
		}}},
		{Role: "user", Content: &mcp.TextContent{Text: "Please process the embedded resource above."}},
	}}, nil
}

func imagePromptFixture(context.Context, *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	return &mcp.GetPromptResult{Messages: []*mcp.PromptMessage{
		{Role: "user", Content: &mcp.ImageContent{Data: fixturePNG, MIMEType: "image/png"}},
		{Role: "user", Content: &mcp.TextContent{Text: "Please analyze the image above."}},
	}}, nil
}
