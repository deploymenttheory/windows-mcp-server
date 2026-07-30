# MCP spec compliance — `2024-11-05`

**Score: 82/100** (over 100 applicable weight)

| | |
|---|---|
| Scored against | `2024-11-05` (http://json-schema.org/draft-07/schema#) |
| Server negotiates | `2025-11-25` |
| Newest published | `2026-07-28` |
| Revisions behind | 1 |

## Dimensions

| Dimension | Weight | Score | Detail |
|---|---:|---:|---|
| Tool definitions conform | 40 | 100 | 30 of 30 tools valid |
| tools/list result conforms | 15 | 100 | validates against ListToolsResult |
| Server method coverage | 15 | 15 | 2 of 13 server methods implemented |
| Handshake result conforms | 10 | 100 | validates against InitializeResult |
| Server capabilities conform | 10 | 100 | validates against ServerCapabilities |
| Protocol revision currency | 10 | 50 | 1 released revision(s) behind 2026-07-28 |

## Server method surface

Coverage **15%** (2 of 13 defined methods).

- Implemented: `tools/call`, `tools/list`
- Not implemented: `completion/complete`, `initialize`, `logging/setLevel`, `ping`, `prompts/get`, `prompts/list`, `resources/list`, `resources/read`, `resources/subscribe`, `resources/templates/list`, `resources/unsubscribe`

## Server capability surface

Coverage **20%** (1 of 5 defined capabilities).

- Implemented: `tools`
- Not implemented: `experimental`, `logging`, `prompts`, `resources`

---

# MCP spec compliance — `2025-03-26`

**Score: 82/100** (over 100 applicable weight)

| | |
|---|---|
| Scored against | `2025-03-26` (http://json-schema.org/draft-07/schema#) |
| Server negotiates | `2025-11-25` |
| Newest published | `2026-07-28` |
| Revisions behind | 1 |

## Dimensions

| Dimension | Weight | Score | Detail |
|---|---:|---:|---|
| Tool definitions conform | 40 | 100 | 30 of 30 tools valid |
| tools/list result conforms | 15 | 100 | validates against ListToolsResult |
| Server method coverage | 15 | 15 | 2 of 13 server methods implemented |
| Handshake result conforms | 10 | 100 | validates against InitializeResult |
| Server capabilities conform | 10 | 100 | validates against ServerCapabilities |
| Protocol revision currency | 10 | 50 | 1 released revision(s) behind 2026-07-28 |

## Server method surface

Coverage **15%** (2 of 13 defined methods).

- Implemented: `tools/call`, `tools/list`
- Not implemented: `completion/complete`, `initialize`, `logging/setLevel`, `ping`, `prompts/get`, `prompts/list`, `resources/list`, `resources/read`, `resources/subscribe`, `resources/templates/list`, `resources/unsubscribe`

## Server capability surface

Coverage **16%** (1 of 6 defined capabilities).

- Implemented: `tools`
- Not implemented: `completions`, `experimental`, `logging`, `prompts`, `resources`

---

# MCP spec compliance — `2025-06-18`

**Score: 82/100** (over 100 applicable weight)

| | |
|---|---|
| Scored against | `2025-06-18` (http://json-schema.org/draft-07/schema#) |
| Server negotiates | `2025-11-25` |
| Newest published | `2026-07-28` |
| Revisions behind | 1 |

## Dimensions

| Dimension | Weight | Score | Detail |
|---|---:|---:|---|
| Tool definitions conform | 40 | 100 | 30 of 30 tools valid |
| tools/list result conforms | 15 | 100 | validates against ListToolsResult |
| Server method coverage | 15 | 15 | 2 of 13 server methods implemented |
| Handshake result conforms | 10 | 100 | validates against InitializeResult |
| Server capabilities conform | 10 | 100 | validates against ServerCapabilities |
| Protocol revision currency | 10 | 50 | 1 released revision(s) behind 2026-07-28 |

## Server method surface

Coverage **15%** (2 of 13 defined methods).

- Implemented: `tools/call`, `tools/list`
- Not implemented: `completion/complete`, `initialize`, `logging/setLevel`, `ping`, `prompts/get`, `prompts/list`, `resources/list`, `resources/read`, `resources/subscribe`, `resources/templates/list`, `resources/unsubscribe`

## Server capability surface

Coverage **16%** (1 of 6 defined capabilities).

- Implemented: `tools`
- Not implemented: `completions`, `experimental`, `logging`, `prompts`, `resources`

---

# MCP spec compliance — `2025-11-25`

**Score: 81/100** (over 100 applicable weight)

| | |
|---|---|
| Scored against | `2025-11-25` (https://json-schema.org/draft/2020-12/schema) |
| Server negotiates | `2025-11-25` |
| Newest published | `2026-07-28` |
| Revisions behind | 1 |

## Dimensions

| Dimension | Weight | Score | Detail |
|---|---:|---:|---|
| Tool definitions conform | 40 | 100 | 30 of 30 tools valid |
| tools/list result conforms | 15 | 100 | validates against ListToolsResult |
| Server method coverage | 15 | 11 | 2 of 17 server methods implemented |
| Handshake result conforms | 10 | 100 | validates against InitializeResult |
| Server capabilities conform | 10 | 100 | validates against ServerCapabilities |
| Protocol revision currency | 10 | 50 | 1 released revision(s) behind 2026-07-28 |

## Server method surface

Coverage **11%** (2 of 17 defined methods).

- Implemented: `tools/call`, `tools/list`
- Not implemented: `completion/complete`, `initialize`, `logging/setLevel`, `ping`, `prompts/get`, `prompts/list`, `resources/list`, `resources/read`, `resources/subscribe`, `resources/templates/list`, `resources/unsubscribe`, `tasks/cancel`, `tasks/get`, `tasks/list`, `tasks/result`

## Server capability surface

Coverage **14%** (1 of 7 defined capabilities).

- Implemented: `tools`
- Not implemented: `completions`, `experimental`, `logging`, `prompts`, `resources`, `tasks`

---

# MCP spec compliance — `2026-07-28`

**Score: 58/100** (over 100 applicable weight)

| | |
|---|---|
| Scored against | `2026-07-28` (https://json-schema.org/draft/2020-12/schema) |
| Server negotiates | `2025-11-25` |
| Newest published | `2026-07-28` |
| Revisions behind | 1 |

## Dimensions

| Dimension | Weight | Score | Detail |
|---|---:|---:|---|
| Tool definitions conform | 40 | 100 | 30 of 30 tools valid |
| tools/list result conforms | 15 | 0 | does not validate against ListToolsResult |
| Server method coverage | 15 | 20 | 2 of 10 server methods implemented |
| Handshake result conforms | 10 | 0 | does not validate against DiscoverResult |
| Server capabilities conform | 10 | 100 | validates against ServerCapabilities |
| Protocol revision currency | 10 | 50 | 1 released revision(s) behind 2026-07-28 |

## Server method surface

Coverage **20%** (2 of 10 defined methods).

- Implemented: `tools/call`, `tools/list`
- Not implemented: `completion/complete`, `prompts/get`, `prompts/list`, `resources/list`, `resources/read`, `resources/templates/list`, `server/discover`, `subscriptions/listen`

## Server capability surface

Coverage **14%** (1 of 7 defined capabilities).

- Implemented: `tools`
- Not implemented: `completions`, `experimental`, `extensions`, `logging`, `prompts`, `resources`

## Findings

| Dimension | Subject | Problem |
|---|---|---|
| list-tools-result | `ListToolsResult` | validating root: validating /$defs/ListToolsResult: required: missing properties: ["cacheScope" "resultType" "ttlMs"] |
| handshake-result | `DiscoverResult` | validating root: validating /$defs/DiscoverResult: required: missing properties: ["cacheScope" "resultType" "supportedVersions" "ttlMs"] |
