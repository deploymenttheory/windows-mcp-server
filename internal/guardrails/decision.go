package guardrails

// Decision is the structured policy-decision document produced by the Runner.
// It is the single source of truth surfaced three ways: the audit record, the
// GuardrailStatus / HTTP status payload, and (future) the remote "may-run"
// request body. Modeled on OPA-style input→decision.
type Decision struct {
	Device     DeviceIdentity `json:"device"`
	RunContext RunContext     `json:"run_context"`
	Mode       string         `json:"mode"`
	Results    []Result       `json:"results"`
	// Admit is the raw policy outcome (all required checks passed). Whether the
	// server actually blocks depends on Mode (see Runner.Admit).
	Admit     bool     `json:"admit"`
	Reasons   []string `json:"reasons,omitempty"`
	Timestamp string   `json:"timestamp,omitempty"`
	SessionID string   `json:"session_id,omitempty"`
}

// Failed returns the results that failed or errored.
func (d Decision) Failed() []Result {
	var out []Result
	for _, r := range d.Results {
		if r.Status == Fail || r.Status == Error {
			out = append(out, r)
		}
	}
	return out
}
