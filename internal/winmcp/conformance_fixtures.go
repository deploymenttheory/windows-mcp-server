//go:build windows && (amd64 || arm64) && conformance

package winmcp

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

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
// Deliberately NOT implemented, because each would mean advertising a feature
// this server does not have:
//
//   - test_tool_with_logging, test_sampling, test_elicitation and the SEP-1034 /
//     SEP-1330 elicitation fixtures — removed at 2026-07-28 anyway, and roots,
//     sampling and logging are deprecated by SEP-2577.
//   - test_trigger_tool_change / test_trigger_prompt_change — these prove a
//     list-changed-capable server notifies listen streams. pinnedCapabilities
//     pins ListChanged false on purpose, so implementing them would contradict
//     the capability we declare.
//   - test_missing_capability — for servers that require a client capability in
//     _meta. This server requires none.
//   - test_input_required_result_* (SEP-2322 MRTR) — this server never returns an
//     InputRequiredResult.
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
		tool := &mcp.Tool{
			Name:        name,
			Description: description,
			InputSchema: emptyObjectSchema(),
			Annotations: &mcp.ToolAnnotations{Title: name, ReadOnlyHint: true},
		}
		server.AddTool(tool, handler)
		reg.Tools = append(reg.Tools, tool)
	}

	addTool("test_simple_text", "Returns a fixed text content block.", textFixture)
	addTool("test_image_content", "Returns a fixed image content block.", imageFixture)
	addTool("test_audio_content", "Returns a fixed audio content block.", audioFixture)
	addTool("test_multiple_content_types", "Returns text, image and resource blocks.", multiFixture)
	addTool("test_embedded_resource", "Returns an embedded resource content block.", embeddedFixture)
	addTool("test_error_handling", "Always fails, to exercise isError reporting.", errorFixture)
	addTool("test_tool_with_progress", "Emits progress notifications when given a token.", progressFixture)

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

	return reg
}

// emptyObjectSchema is the no-argument input schema. It is written out rather
// than inferred so the fixtures carry the same hand-written schema shape the
// product tools do.
func emptyObjectSchema() any {
	return map[string]any{"type": "object", "properties": map[string]any{}}
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
