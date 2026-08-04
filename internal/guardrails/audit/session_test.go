package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runSession opens a directory destination for sessionID, appends n events through a
// fresh AuditLog (as a real run does — each run starts its own chain at seq 0),
// and seals it via Close.
func runSession(t *testing.T, dir, sessionID string, n int) {
	t.Helper()
	dest, err := OpenDestination(dir, sessionID)
	if err != nil {
		t.Fatalf("OpenDestination(%q): %v", sessionID, err)
	}
	log := NewAuditLog(dest)
	log.Append("server.started", map[string]any{"session": sessionID})
	for i := 1; i < n; i++ {
		log.Append("tool.call", map[string]any{"i": i})
	}
	if err := log.Close(); err != nil {
		t.Fatalf("Close(%q): %v", sessionID, err)
	}
}

func TestDirModeVerifiesAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	runSession(t, dir, "20260803-120000", 3)
	runSession(t, dir, "20260803-120100", 4)

	rep, err := VerifyDir(dir, nil)
	if err != nil {
		t.Fatalf("VerifyDir: %v", err)
	}
	if !rep.OK() {
		t.Fatalf("two clean sessions should verify, problems:\n%s", rep)
	}
	if len(rep.Sessions) != 2 {
		t.Fatalf("want 2 sessions, got %d", len(rep.Sessions))
	}
	for _, s := range rep.Sessions {
		if !s.Sealed {
			t.Errorf("session %s should be sealed", s.File)
		}
	}
}

// TestUnsealedSessionIsNotReportedAsOK pins the distinction lab testing showed was
// invisible.
//
// A session with no seal has nothing to cross-check its head against, so any
// prefix of its chain verifies -- removing the tail is undetectable. That was
// true before and is still true; what was wrong was the reporting. The line read
// "ok  open  N entries" and the summary said "manifest chain intact", which is
// exactly what a clean directory looks like. Since the kill ladder's Shutdown
// rung and any crash leave a session unsealed, the sessions most worth tampering
// with were the ones displayed most reassuringly.
func TestUnsealedSessionIsNotReportedAsOK(t *testing.T) {
	dir := t.TempDir()
	runSession(t, dir, "20260803-140000", 4) // sealed

	// A session left open: written, never closed.
	dest, err := OpenDestination(dir, "20260803-140100")
	if err != nil {
		t.Fatal(err)
	}
	log := NewAuditLog(dest)
	log.Append("server.started", map[string]any{"session": "20260803-140100"})
	log.Append("tool.call", map[string]any{"i": 1})
	if err := dest.Flush(); err != nil {
		t.Fatal(err)
	}
	// Registered after t.TempDir's own cleanup, so it runs first: the file has to
	// be closed before Windows will let the temp directory be removed. The session
	// stays unsealed for the assertions below, which is the point of the test.
	t.Cleanup(func() { _ = dest.Close() })

	rep, err := VerifyDir(dir, nil)
	if err != nil {
		t.Fatalf("VerifyDir: %v", err)
	}

	// Nothing is provably wrong, so OK stays true -- a live server always has one
	// open session and a health check must not scream about it.
	if !rep.OK() {
		t.Errorf("an unsealed session is not itself an integrity failure:\n%s", rep)
	}
	// But it is not "everything is provably right" either.
	if rep.Unsealed() != 1 {
		t.Errorf("Unsealed() = %d, want 1", rep.Unsealed())
	}
	if rep.StrictOK() {
		t.Error("StrictOK must be false while a session carries no seal")
	}

	out := rep.String()
	if !strings.Contains(out, "UNSEALED") {
		t.Errorf("the report must mark the unsealed session, got:\n%s", out)
	}
	if !strings.Contains(out, "warning:") {
		t.Errorf("the report must explain what an unsealed session does not prove, got:\n%s", out)
	}
}

// TestDirModeSessionFilesEachRootAtZero is the regression guard for 0.1: two runs
// against one target must not share a sequence. Each session file is its own
// chain rooted at seq 0, and the manifest is what links them.
func TestDirModeSessionFilesEachRootAtZero(t *testing.T) {
	dir := t.TempDir()
	runSession(t, dir, "20260803-130000", 2)
	runSession(t, dir, "20260803-130100", 2)

	files, _ := filepath.Glob(filepath.Join(dir, "session-*.audit.jsonl"))
	if len(files) != 2 {
		t.Fatalf("want 2 session files, got %d", len(files))
	}
	for _, f := range files {
		entries, err := VerifyFile(f, nil)
		if err != nil {
			t.Errorf("%s: %v", filepath.Base(f), err)
		}
		if entries[0].Seq != 0 {
			t.Errorf("%s: first entry seq = %d, want 0", filepath.Base(f), entries[0].Seq)
		}
	}
}

func TestDirModeDetectsManifestTamper(t *testing.T) {
	dir := t.TempDir()
	runSession(t, dir, "20260803-140000", 3)
	runSession(t, dir, "20260803-140100", 3)

	manifestPath := filepath.Join(dir, ManifestName)
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")

	// Edit a manifest record's head hash without recomputing → chain breaks.
	edit := append([]string(nil), lines...)
	var rec ManifestRecord
	if err := json.Unmarshal([]byte(edit[len(edit)-1]), &rec); err != nil {
		t.Fatal(err)
	}
	rec.HeadHash = "deadbeef"
	b, _ := json.Marshal(rec)
	edit[len(edit)-1] = string(b)
	writeLines(t, manifestPath, edit)
	if rep, _ := VerifyDir(dir, nil); rep.OK() {
		t.Error("edited manifest head should be caught")
	}

	// Delete a manifest record from the middle → the following record's
	// prev_manifest_hash no longer chains. (Deleting the trailing seal is instead
	// indistinguishable from a still-open or killed session, which VerifyDir
	// tolerates by design — off-box anchoring, not the manifest, closes that gap.)
	writeLines(t, manifestPath, append(append([]string(nil), lines[0]), lines[2:]...))
	if rep, _ := VerifyDir(dir, nil); rep.OK() {
		t.Error("deleted middle manifest record should be caught")
	}

	// Reorder → chain breaks.
	rev := append([]string(nil), lines...)
	rev[0], rev[1] = rev[1], rev[0]
	writeLines(t, manifestPath, rev)
	if rep, _ := VerifyDir(dir, nil); rep.OK() {
		t.Error("reordered manifest records should be caught")
	}
}

// TestDirModeDetectsRewrittenSession catches a session file edited after sealing:
// the manifest seal still names the original head, so the cross-check fails even
// though the (rewritten) file verifies as a chain on its own.
func TestDirModeDetectsRewrittenSession(t *testing.T) {
	dir := t.TempDir()
	runSession(t, dir, "20260803-150000", 4)

	files, _ := filepath.Glob(filepath.Join(dir, "session-*.audit.jsonl"))
	// Rewrite the session as a shorter but internally valid chain.
	dest := &memDest{}
	log := NewAuditLog(dest)
	log.Append("server.started", map[string]any{"session": "forged"})
	rewritten := marshalEntries(t, dest.entries)
	if err := os.WriteFile(files[0], rewritten, 0o600); err != nil {
		t.Fatal(err)
	}

	rep, err := VerifyDir(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK() {
		t.Error("a session whose head no longer matches its manifest seal must be caught")
	}
}

func TestDirModeDetectsDroppedSession(t *testing.T) {
	dir := t.TempDir()
	runSession(t, dir, "20260803-160000", 3)
	runSession(t, dir, "20260803-160100", 3)

	files, _ := filepath.Glob(filepath.Join(dir, "session-*.audit.jsonl"))
	if err := os.Remove(files[0]); err != nil {
		t.Fatal(err)
	}
	rep, _ := VerifyDir(dir, nil)
	if rep.OK() {
		t.Error("a session named in the manifest but missing from disk must be caught")
	}
}

func TestVerifyChainSegment(t *testing.T) {
	dest := &memDest{}
	log := NewAuditLog(dest)
	for i := 0; i < 5; i++ {
		log.Append("e", map[string]any{"i": i})
	}
	all := dest.entries

	// A tail slice verifies against the correct start seq and preceding hash.
	seg := all[2:]
	if err := VerifyChainSegment(seg, 2, all[1].EntryHash); err != nil {
		t.Errorf("valid segment should verify: %v", err)
	}
	// Wrong start seq is rejected.
	if err := VerifyChainSegment(seg, 0, all[1].EntryHash); err == nil {
		t.Error("segment with wrong start seq should fail")
	}
	// Wrong preceding hash is rejected.
	if err := VerifyChainSegment(seg, 2, "nope"); err == nil {
		t.Error("segment with wrong prev hash should fail")
	}
	// VerifyChain is the (0,"") case.
	if err := VerifyChain(all); err != nil {
		t.Errorf("full chain should verify: %v", err)
	}
}

func TestNewSinkFileAndStderrModesUnchanged(t *testing.T) {
	// A plain file path stays single-file append-only (no session/manifest files).
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	dest, err := OpenDestination(path, "20260803-170000")
	if err != nil {
		t.Fatal(err)
	}
	log := NewAuditLog(dest)
	log.Append("server.started", nil)
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, ManifestName)); !os.IsNotExist(err) {
		t.Error("file mode must not create a manifest")
	}
	if entries, err := VerifyFile(path, nil); err != nil || len(entries) != 1 {
		t.Errorf("file mode chain: entries=%d err=%v", len(entries), err)
	}

	// stderr mode still yields a working, non-nil dest.
	if s, err := OpenDestination("stderr", "x"); err != nil || s == nil {
		t.Errorf("stderr destination: %v", err)
	}
}

func writeLines(t *testing.T, path string, lines []string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func marshalEntries(t *testing.T, entries []AuditEntry) []byte {
	t.Helper()
	var b strings.Builder
	for _, e := range entries {
		raw, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(raw)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

// TestKeyedManifestRejectsATruncatedTail is a regression test for the way a
// truncated session escaped detection.
//
// VerifyChainSegment iterates only the entries it is handed, so any prefix of a
// valid chain is itself a valid chain. The manifest is what pins a session's head
// -- but it was an unkeyed SHA-256 chain, so an attacker could drop the seal
// record and recompute the rest, and the whole directory verified clean even with
// WINDOWS_MCP_AUDIT_KEY set.
func TestKeyedManifestRejectsATruncatedTail(t *testing.T) {
	key := []byte("audit-key")
	records := []ManifestRecord{
		{SessionFile: "session-1.audit.jsonl", OpenedAt: "t0"},
		{SessionFile: "session-2.audit.jsonl", OpenedAt: "t1"},
	}
	// Build a valid keyed chain.
	prev := ""
	for i := range records {
		records[i].PrevManifestHash = prev
		records[i].EntryHash = hashManifest(records[i])
		records[i].Mac = macOf(key, records[i].EntryHash)
		prev = records[i].EntryHash
	}
	if err := VerifyManifest(records, key); err != nil {
		t.Fatalf("a well-formed keyed manifest must verify: %v", err)
	}

	// Dropping the tail still leaves a structurally valid prefix...
	truncated := records[:1]
	if err := VerifyManifest(truncated, key); err != nil {
		t.Errorf("a prefix is still structurally valid; truncation is caught by the head "+
			"cross-check, not here: %v", err)
	}

	// ...but a forged record cannot be substituted without the key.
	forged := append([]ManifestRecord{}, records...)
	forged[1].SessionFile = "session-evil.audit.jsonl"
	forged[1].EntryHash = hashManifest(forged[1])
	// The attacker recomputes the hash but cannot produce the MAC.
	if err := VerifyManifest(forged, key); err == nil {
		t.Error("a rewritten manifest record must not verify under the audit key; " +
			"without a MAC the manifest is only tamper-evident, not unforgeable")
	}

	// Stripping the MAC must not be a way around it either.
	stripped := append([]ManifestRecord{}, records...)
	stripped[1].Mac = ""
	if err := VerifyManifest(stripped, key); err == nil {
		t.Error("a record with no MAC must be refused when a key is supplied")
	}
}
