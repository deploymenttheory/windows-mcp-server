# MCP spec compliance — `2024-11-05`

**Conformance: 100/100** (over 85 applicable weight) — everything the server serves validates.

**Coverage: 61% of server methods (8/13), 60% of capabilities (3/5)** — informational; MCP does not require prompts, resources or completions.

| | |
|---|---|
| Scored against | `2024-11-05` (http://json-schema.org/draft-07/schema#) |
| Server negotiates | `2026-07-28` |
| Newest published | `2026-07-28` |
| Revisions behind | 0 |

## Dimensions

| Dimension | Kind | Weight | Score | Detail |
|---|---|---:|---:|---|
| Tool definitions conform | conformance | 45 | 100 | 30 of 30 tools valid |
| tools/list result conforms | conformance | 20 | 100 | validates against ListToolsResult |
| Server method coverage | coverage | — | 61 | 8 of 13 server methods implemented |
| Handshake result conforms | conformance | 15 | n/a | skipped — handshake captured under 2026-07-28; not comparable to 2024-11-05 |
| Server capabilities conform | conformance | 10 | 100 | validates against ServerCapabilities |
| Protocol revision currency | conformance | 10 | 100 | negotiating the newest published revision |

## Server method surface

Coverage **61%** (8 of 13 defined methods).

- Implemented: `completion/complete`, `prompts/get`, `prompts/list`, `resources/list`, `resources/read`, `resources/templates/list`, `tools/call`, `tools/list`
- Not implemented: `initialize`, `logging/setLevel`, `ping`, `resources/subscribe`, `resources/unsubscribe`
- Not in this revision: `server/discover`, `subscriptions/listen`

## Server capability surface

Coverage **60%** (3 of 5 defined capabilities).

- Implemented: `prompts`, `resources`, `tools`
- Not implemented: `experimental`, `logging`
- Not in this revision: `completions`

---

# MCP spec compliance — `2025-03-26`

**Conformance: 100/100** (over 85 applicable weight) — everything the server serves validates.

**Coverage: 61% of server methods (8/13), 66% of capabilities (4/6)** — informational; MCP does not require prompts, resources or completions.

| | |
|---|---|
| Scored against | `2025-03-26` (http://json-schema.org/draft-07/schema#) |
| Server negotiates | `2026-07-28` |
| Newest published | `2026-07-28` |
| Revisions behind | 0 |

## Dimensions

| Dimension | Kind | Weight | Score | Detail |
|---|---|---:|---:|---|
| Tool definitions conform | conformance | 45 | 100 | 30 of 30 tools valid |
| tools/list result conforms | conformance | 20 | 100 | validates against ListToolsResult |
| Server method coverage | coverage | — | 61 | 8 of 13 server methods implemented |
| Handshake result conforms | conformance | 15 | n/a | skipped — handshake captured under 2026-07-28; not comparable to 2025-03-26 |
| Server capabilities conform | conformance | 10 | 100 | validates against ServerCapabilities |
| Protocol revision currency | conformance | 10 | 100 | negotiating the newest published revision |

## Server method surface

Coverage **61%** (8 of 13 defined methods).

- Implemented: `completion/complete`, `prompts/get`, `prompts/list`, `resources/list`, `resources/read`, `resources/templates/list`, `tools/call`, `tools/list`
- Not implemented: `initialize`, `logging/setLevel`, `ping`, `resources/subscribe`, `resources/unsubscribe`
- Not in this revision: `server/discover`, `subscriptions/listen`

## Server capability surface

Coverage **66%** (4 of 6 defined capabilities).

- Implemented: `completions`, `prompts`, `resources`, `tools`
- Not implemented: `experimental`, `logging`

---

# MCP spec compliance — `2025-06-18`

**Conformance: 100/100** (over 85 applicable weight) — everything the server serves validates.

**Coverage: 61% of server methods (8/13), 66% of capabilities (4/6)** — informational; MCP does not require prompts, resources or completions.

| | |
|---|---|
| Scored against | `2025-06-18` (http://json-schema.org/draft-07/schema#) |
| Server negotiates | `2026-07-28` |
| Newest published | `2026-07-28` |
| Revisions behind | 0 |

## Dimensions

| Dimension | Kind | Weight | Score | Detail |
|---|---|---:|---:|---|
| Tool definitions conform | conformance | 45 | 100 | 30 of 30 tools valid |
| tools/list result conforms | conformance | 20 | 100 | validates against ListToolsResult |
| Server method coverage | coverage | — | 61 | 8 of 13 server methods implemented |
| Handshake result conforms | conformance | 15 | n/a | skipped — handshake captured under 2026-07-28; not comparable to 2025-06-18 |
| Server capabilities conform | conformance | 10 | 100 | validates against ServerCapabilities |
| Protocol revision currency | conformance | 10 | 100 | negotiating the newest published revision |

## Server method surface

Coverage **61%** (8 of 13 defined methods).

- Implemented: `completion/complete`, `prompts/get`, `prompts/list`, `resources/list`, `resources/read`, `resources/templates/list`, `tools/call`, `tools/list`
- Not implemented: `initialize`, `logging/setLevel`, `ping`, `resources/subscribe`, `resources/unsubscribe`
- Not in this revision: `server/discover`, `subscriptions/listen`

## Server capability surface

Coverage **66%** (4 of 6 defined capabilities).

- Implemented: `completions`, `prompts`, `resources`, `tools`
- Not implemented: `experimental`, `logging`

---

# MCP spec compliance — `2025-11-25`

**Conformance: 100/100** (over 85 applicable weight) — everything the server serves validates.

**Coverage: 47% of server methods (8/17), 57% of capabilities (4/7)** — informational; MCP does not require prompts, resources or completions.

| | |
|---|---|
| Scored against | `2025-11-25` (https://json-schema.org/draft/2020-12/schema) |
| Server negotiates | `2026-07-28` |
| Newest published | `2026-07-28` |
| Revisions behind | 0 |

## Dimensions

| Dimension | Kind | Weight | Score | Detail |
|---|---|---:|---:|---|
| Tool definitions conform | conformance | 45 | 100 | 30 of 30 tools valid |
| tools/list result conforms | conformance | 20 | 100 | validates against ListToolsResult |
| Server method coverage | coverage | — | 47 | 8 of 17 server methods implemented |
| Handshake result conforms | conformance | 15 | n/a | skipped — handshake captured under 2026-07-28; not comparable to 2025-11-25 |
| Server capabilities conform | conformance | 10 | 100 | validates against ServerCapabilities |
| Protocol revision currency | conformance | 10 | 100 | negotiating the newest published revision |

## Server method surface

Coverage **47%** (8 of 17 defined methods).

- Implemented: `completion/complete`, `prompts/get`, `prompts/list`, `resources/list`, `resources/read`, `resources/templates/list`, `tools/call`, `tools/list`
- Not implemented: `initialize`, `logging/setLevel`, `ping`, `resources/subscribe`, `resources/unsubscribe`, `tasks/cancel`, `tasks/get`, `tasks/list`, `tasks/result`
- Not in this revision: `server/discover`, `subscriptions/listen`

## Server capability surface

Coverage **57%** (4 of 7 defined capabilities).

- Implemented: `completions`, `prompts`, `resources`, `tools`
- Not implemented: `experimental`, `logging`, `tasks`

---

# MCP spec compliance — `2026-07-28`

**Conformance: 100/100** (over 100 applicable weight) — everything the server serves validates.

**Coverage: 100% of server methods (10/10), 57% of capabilities (4/7)** — informational; MCP does not require prompts, resources or completions.

| | |
|---|---|
| Scored against | `2026-07-28` (https://json-schema.org/draft/2020-12/schema) |
| Server negotiates | `2026-07-28` |
| Newest published | `2026-07-28` |
| Revisions behind | 0 |

## Dimensions

| Dimension | Kind | Weight | Score | Detail |
|---|---|---:|---:|---|
| Tool definitions conform | conformance | 45 | 100 | 30 of 30 tools valid |
| tools/list result conforms | conformance | 20 | 100 | validates against ListToolsResult |
| Server method coverage | coverage | — | 100 | 10 of 10 server methods implemented |
| Handshake result conforms | conformance | 15 | 100 | validates against DiscoverResult |
| Server capabilities conform | conformance | 10 | 100 | validates against ServerCapabilities |
| Protocol revision currency | conformance | 10 | 100 | negotiating the newest published revision |

## Server method surface

Coverage **100%** (10 of 10 defined methods).

- Implemented: `completion/complete`, `prompts/get`, `prompts/list`, `resources/list`, `resources/read`, `resources/templates/list`, `server/discover`, `subscriptions/listen`, `tools/call`, `tools/list`

## Server capability surface

Coverage **57%** (4 of 7 defined capabilities).

- Implemented: `completions`, `prompts`, `resources`, `tools`
- Not implemented: `experimental`, `extensions`, `logging`
