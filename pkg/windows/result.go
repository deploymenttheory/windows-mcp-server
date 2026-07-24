package windows

import (
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// NewToolResultText returns a successful tool result carrying a single text
// block.
func NewToolResultText(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}
}

// NewToolResultTextf is NewToolResultText with fmt formatting.
func NewToolResultTextf(format string, a ...any) *mcp.CallToolResult {
	return NewToolResultText(fmt.Sprintf(format, a...))
}

// NewToolResultError returns a tool-level error result (IsError set). Per the
// MCP convention, expected/user-facing errors are returned this way — with a
// nil Go error — so the model can see the message and self-correct. Reserve a
// real Go error for infrastructure failures.
func NewToolResultError(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
		IsError: true,
	}
}

// NewToolResultErrorf is NewToolResultError with fmt formatting.
func NewToolResultErrorf(format string, a ...any) *mcp.CallToolResult {
	return NewToolResultError(fmt.Sprintf(format, a...))
}

// NewToolResultErrorFromErr returns a tool-level error result combining a
// message and an underlying error.
func NewToolResultErrorFromErr(msg string, err error) *mcp.CallToolResult {
	if err == nil {
		return NewToolResultError(msg)
	}
	return NewToolResultError(fmt.Sprintf("%s: %s", msg, err))
}

// NewToolResultImage returns a successful tool result carrying a PNG (or other)
// image plus an optional leading text block. Pass empty text to omit it.
func NewToolResultImage(text string, pngData []byte, mimeType string) *mcp.CallToolResult {
	var content []mcp.Content
	if text != "" {
		content = append(content, &mcp.TextContent{Text: text})
	}
	content = append(content, &mcp.ImageContent{Data: pngData, MIMEType: mimeType})
	return &mcp.CallToolResult{Content: content}
}
