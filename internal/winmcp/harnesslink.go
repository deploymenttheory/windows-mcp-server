//go:build windows && (amd64 || arm64)

package winmcp

// harnesslink is the server's side of the agentweave-harness control channel:
// when the harness spawns this server it passes the channel address and a
// bootstrap token in the environment, and this file dials back, authenticates,
// and then serves the harness's requests — evaluating declared signals,
// executing actuation rungs, and pushing liveness and lifecycle events.
//
// Phase 3 scope: the link is additive. The server still wires its full local
// guardrail stack; the harness acks observe mode and drives nothing. What this
// file establishes is the servant contract itself, so Phase 4 can move the
// decision out of process without the server changing again.
//
// Two invariants are structural here, not incidental:
//   - There is no generic execution verb. signal.evaluate runs only guardrail
//     checks already registered by id; an unknown id is reported errored, never
//     run as anything. Actuation is a fixed, injected rung set; an unknown rung
//     is refused and reported, never guessed at. A compromise of the harness
//     therefore cannot become arbitrary code execution on this host.
//   - No secret crosses the channel. Signal results carry posture, credential
//     events carry identifiers; neither carries a secret value, and there is no
//     message that could.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync/atomic"
	"time"

	"github.com/Microsoft/go-winio"

	"github.com/deploymenttheory/agentweave-harness/guardrails/signals"
	"github.com/deploymenttheory/agentweave-harness/wire"
)

// errHarnessChannelLost is the cancel cause when the control channel drops
// mid-session. It is distinct from a graceful stop so RunStdio exits non-zero:
// losing the adjudicator is a failure, not an orderly end.
var errHarnessChannelLost = errors.New("agentweave-harness control channel lost")

// errUnexpectedHelloAck reports a handshake reply that was not hello.ack.
var errUnexpectedHelloAck = errors.New("harness: expected hello.ack")

// rungFunc executes one actuation rung and reports what the OS did. It is
// injected by RunStdio from the same primitives the local kill executor uses,
// so there is one actuation path whether the trip is decided in-process or by
// the harness.
type rungFunc func(params json.RawMessage) wire.ActuateResult

// harnessServant serves the control channel for one session.
type harnessServant struct {
	r      *wire.Reader
	w      *wire.Writer
	conn   io.Closer
	logger *slog.Logger

	reg   *signals.Registry
	envFn func() *signals.Env
	rungs map[string]rungFunc
	alive func() bool

	version int
	seq     atomic.Uint64
	// onLost fires once when the serve loop ends because the channel dropped
	// (as opposed to a requested shutdown). RunStdio wires it to cancel the run
	// context, so the ordinary LIFO teardown — credential cleanup included —
	// runs exactly as on any other exit.
	onLost func(error)
	lost   atomic.Bool
}

// servantDeps is what RunStdio supplies to stand up the servant.
type servantDeps struct {
	Registry   *signals.Registry
	EnvFn      func() *signals.Env
	Rungs      map[string]rungFunc
	Alive      func() bool
	RunContext signals.RunContext
	Elevated   bool
	Logger     *slog.Logger
	OnLost     func(error)
}

// harnessAddress reads the bootstrap contract from the environment. The empty
// string means no harness is present and the server runs standalone.
func harnessAddress() (pipe, token string) {
	return os.Getenv(envHarnessPipe), os.Getenv(envHarnessToken)
}

// The bootstrap environment variables the harness sets on this child. They are
// scrubbed after use so no tool can read the token back.
const (
	envHarnessPipe = "AGENTWEAVE_CONTROL_PIPE"
	// envHarnessToken names the var carrying the bootstrap token, not a secret.
	envHarnessToken = "AGENTWEAVE_CONTROL_TOKEN" //nolint:gosec // G101: env var name
)

// dialHarness connects to the control channel named pipe. Governed servers
// implement their own dialer against the documented bootstrap contract rather
// than importing the harness's internal transport; this is that dialer.
func dialHarness(pipe string) (io.ReadWriteCloser, error) {
	timeout := 10 * time.Second
	conn, err := winio.DialPipe(pipe, &timeout)
	if err != nil {
		return nil, fmt.Errorf("harness: dial %s: %w", pipe, err)
	}
	return conn, nil
}

// attachHarness dials the control channel and completes the handshake. It is
// the real-transport entry point; connectServant underneath is transport-
// agnostic so the protocol is testable over an in-memory pipe.
func attachHarness(
	pipe, token, serverVersion, sessionStamp string,
	deps servantDeps,
) (*harnessServant, wire.HelloAck, error) {
	conn, err := dialHarness(pipe)
	if err != nil {
		return nil, wire.HelloAck{}, err
	}
	s, ack, err := connectServant(conn, token, serverVersion, sessionStamp, deps)
	if err != nil {
		_ = conn.Close()
		return nil, wire.HelloAck{}, err
	}
	return s, ack, nil
}

// heartbeatFromAck resolves the heartbeat cadence, defaulting when the harness
// leaves it unset.
func heartbeatFromAck(ack wire.HelloAck) time.Duration {
	if ms := ack.EffectiveConfig.HeartbeatIntervalMS; ms > 0 {
		return time.Duration(ms) * time.Millisecond
	}
	return 10 * time.Second
}

// installedCredentialNames extracts the identifiers of installed credentials
// for a credential.event. Names only — the never-read invariant means a value
// never reaches this layer to leak.
func installedCredentialNames(creds []installedCredential) []string {
	names := make([]string, 0, len(creds))
	for _, c := range creds {
		names = append(names, c.Name)
	}
	return names
}

// connectServant performs the hello/hello.ack handshake over conn and returns
// the servant plus the harness's ack. It is separated from dialing so the
// protocol is testable over an in-memory pipe.
func connectServant(
	conn io.ReadWriteCloser,
	token, serverVersion, sessionStamp string,
	deps servantDeps,
) (*harnessServant, wire.HelloAck, error) {
	w := wire.NewWriter(conn)
	r := wire.NewReader(conn)

	rungs := make([]string, 0, len(deps.Rungs))
	for name := range deps.Rungs {
		rungs = append(rungs, name)
	}
	hello := wire.Hello{
		ProtoMin:      wire.MinProtocolVersion,
		ProtoMax:      wire.MaxProtocolVersion,
		ServerVersion: serverVersion,
		SessionStamp:  sessionStamp,
		Token:         token,
		Capabilities: wire.Capabilities{
			Signals:    deps.Registry.IDs(),
			Actuators:  rungs,
			Elevated:   deps.Elevated,
			RunContext: describeRunContext(deps.RunContext),
		},
	}
	env, err := wire.Marshal(wire.MaxProtocolVersion, wire.TypeHello, "", "", hello)
	if err != nil {
		return nil, wire.HelloAck{}, fmt.Errorf("harness: marshal hello: %w", err)
	}
	if err := w.Write(env); err != nil {
		return nil, wire.HelloAck{}, fmt.Errorf("harness: sending hello: %w", err)
	}

	ackEnv, err := r.Read()
	if err != nil {
		return nil, wire.HelloAck{}, fmt.Errorf("harness: reading hello.ack: %w", err)
	}
	if ackEnv.Type != wire.TypeHelloAck {
		return nil, wire.HelloAck{}, fmt.Errorf("%w: got %q", errUnexpectedHelloAck, ackEnv.Type)
	}
	var ack wire.HelloAck
	if err := wire.Unmarshal(ackEnv, &ack); err != nil {
		return nil, wire.HelloAck{}, fmt.Errorf("harness: unmarshal hello.ack: %w", err)
	}

	s := &harnessServant{
		r: r, w: w, conn: conn, logger: deps.Logger,
		reg: deps.Registry, envFn: deps.EnvFn, rungs: deps.Rungs, alive: deps.Alive,
		version: ack.Proto, onLost: deps.OnLost,
	}
	return s, ack, nil
}

// describeRunContext renders the process security context for the hello
// capabilities — enough for a policy to reason about session and elevation
// without shipping the whole struct.
func describeRunContext(rc signals.RunContext) string {
	return fmt.Sprintf("session=%d elevated=%t system=%t", rc.SessionID, rc.Elevated, rc.IsSystem)
}

// serve reads control messages until the channel closes or a shutdown is
// requested. Dispatch tolerance mirrors the harness side: an unknown
// notification is ignored, an unknown request is answered with an error rather
// than left to hang.
func (s *harnessServant) serve(ctx context.Context) {
	for {
		env, err := s.r.Read()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) {
				s.fireLost(nil)
			} else {
				s.fireLost(err)
			}
			return
		}
		switch env.Type {
		case wire.TypeSignalEvaluate:
			s.handleSignalEvaluate(ctx, env)
		case wire.TypeActuate:
			s.handleActuate(env)
		case wire.TypeConfigUpdate:
			// Effective-config updates (e.g. a manifest expiry) are Phase 5+;
			// accept and ignore so a forward-looking harness does not error.
			s.logger.Debug("harness: config.update ignored (not yet applied)")
		case wire.TypeShutdown:
			s.handleShutdown(env)
			return
		default:
			if env.ID == "" {
				s.logger.Warn("harness: ignoring unknown notification", "type", env.Type)
				continue
			}
			s.logger.Warn("harness: refusing unknown request", "type", env.Type, "id", env.ID)
			_ = s.send("error", "", env.ID, map[string]string{"error": "unsupported", "type": env.Type})
		}
	}
}

// handleSignalEvaluate evaluates the requested guardrail ids and replies with
// their results. An id the registry does not carry is reported as an errored
// result — it is never dispatched to anything else. This is the whole of what
// the channel can make this host compute: registered posture checks, by id.
func (s *harnessServant) handleSignalEvaluate(ctx context.Context, env wire.Envelope) {
	var req wire.SignalEvaluate
	if err := wire.Unmarshal(env, &req); err != nil {
		s.logger.Warn("harness: bad signal.evaluate payload", "err", err)
		return
	}
	results := make([]json.RawMessage, 0, len(req.IDs))
	for _, id := range req.IDs {
		var res signals.Result
		g, ok := s.reg.Get(id)
		if !ok {
			res = signals.Result{ID: id, Status: signals.Error, Detail: "unknown signal id"}
		} else {
			e := s.envFn()
			e.Arg = req.Args[id]
			res = g.Check(ctx, e)
		}
		if b, err := json.Marshal(res); err == nil {
			results = append(results, b)
		}
	}
	if err := s.send(wire.TypeSignalResult, "", env.ID, wire.SignalResult{Results: results}); err != nil {
		s.logger.Warn("harness: sending signal.result", "err", err)
	}
}

// handleActuate executes one rung and reports what happened. An unknown rung is
// refused, not approximated: a containment command this server does not
// understand must fail loudly.
func (s *harnessServant) handleActuate(env wire.Envelope) {
	var a wire.Actuate
	if err := wire.Unmarshal(env, &a); err != nil {
		s.logger.Warn("harness: bad actuate payload", "err", err)
		return
	}
	fn, ok := s.rungs[a.Rung]
	if !ok {
		s.logger.Warn("harness: refusing unknown actuation rung", "rung", a.Rung)
		_ = s.send(wire.TypeActuateResult, "", env.ID,
			wire.ActuateResult{Rung: a.Rung, OK: false, SkippedReason: "unknown rung"})
		return
	}
	res := fn(a.Params)
	if err := s.send(wire.TypeActuateResult, "", env.ID, res); err != nil {
		s.logger.Warn("harness: sending actuate.result", "err", err)
	}
}

// handleShutdown ends the serve loop on the harness's request. It does not
// itself tear the server down — it is not channel loss — but a graceful
// shutdown request from the harness closes the servant so RunStdio's normal
// exit proceeds.
func (s *harnessServant) handleShutdown(env wire.Envelope) {
	var sh wire.Shutdown
	_ = wire.Unmarshal(env, &sh)
	s.logger.Info("harness: shutdown requested", "reason", sh.Reason, "graceful", sh.Graceful)
}

// PushHeartbeat sends one liveness beat. Its DesktopAlive field is the one
// thing the harness cannot infer from the proxied MCP stream: whether the
// engine's serialized COM thread is still answering.
func (s *harnessServant) PushHeartbeat() error {
	alive := true
	if s.alive != nil {
		alive = s.alive()
	}
	return s.send(wire.TypeHeartbeat, "", "",
		wire.Heartbeat{Seq: s.seq.Add(1), DesktopAlive: alive})
}

// PushCredentialEvent reports a credential lifecycle transition — identifiers
// only, never values.
func (s *harnessServant) PushCredentialEvent(kind string, ids []string) error {
	return s.send(wire.TypeCredentialEvent, "", "", wire.CredentialEvent{Kind: kind, IDs: ids})
}

// PushAuditAnchor reports this server's local chain head so the harness chain
// can pin the pair.
func (s *harnessServant) PushAuditAnchor(seq uint64, head string) error {
	return s.send(wire.TypeAuditAnchor, "", "", wire.AuditAnchor{Seq: seq, Head: head})
}

// StartHeartbeat pushes a beat every interval until ctx ends. A zero or
// negative interval disables it.
func (s *harnessServant) StartHeartbeat(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := s.PushHeartbeat(); err != nil {
					// A failed push means the channel is going; the serve loop
					// will observe the same and fire onLost.
					s.logger.Debug("harness: heartbeat push failed", "err", err)
					return
				}
			}
		}
	}()
}

func (s *harnessServant) send(typ, id, re string, payload any) error {
	env, err := wire.Marshal(s.version, typ, id, re, payload)
	if err != nil {
		return fmt.Errorf("harness: marshal %s: %w", typ, err)
	}
	if err := s.w.Write(env); err != nil {
		return fmt.Errorf("harness: send %s: %w", typ, err)
	}
	return nil
}

func (s *harnessServant) fireLost(err error) {
	if s.lost.Swap(true) {
		return
	}
	if s.onLost != nil {
		s.onLost(err)
	}
}

// Close ends the servant connection. Safe to call more than once.
func (s *harnessServant) Close() error {
	if s.conn == nil {
		return nil
	}
	if err := s.conn.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
		return fmt.Errorf("harness: close servant: %w", err)
	}
	return nil
}
