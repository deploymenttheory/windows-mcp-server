package inventory

import "github.com/modelcontextprotocol/go-sdk/mcp"

// ServerPrompt pairs a prompt with its toolset metadata.
type ServerPrompt struct {
	Prompt             mcp.Prompt
	Handler            mcp.PromptHandler
	Toolset            ToolsetMetadata
	FeatureFlagEnable  string
	FeatureFlagDisable []string
}

// NewServerPrompt creates a ServerPrompt.
func NewServerPrompt(toolset ToolsetMetadata, prompt mcp.Prompt, handler mcp.PromptHandler) ServerPrompt {
	return ServerPrompt{
		Prompt:  prompt,
		Handler: handler,
		Toolset: toolset,
	}
}
