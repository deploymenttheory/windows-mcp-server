package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// SessionReport is the verification result for one session file.
type SessionReport struct {
	File    string
	Entries int
	Sealed  bool
	// Err is the chain-integrity error, or nil when the file verifies on its own.
	Err error
}

// DirReport is the verification result for a directory of session files linked by
// a manifest. Problems is empty when everything verifies and cross-checks.
type DirReport struct {
	Dir      string
	Sessions []SessionReport
	Problems []string
}

// OK reports whether the directory verified end to end.
func (r DirReport) OK() bool { return len(r.Problems) == 0 }

// Unsealed counts sessions with no sealed manifest record.
func (r DirReport) Unsealed() int {
	n := 0
	for _, s := range r.Sessions {
		if !s.Sealed {
			n++
		}
	}
	return n
}

// StrictOK is OK plus "and every session is sealed".
//
// Separate from OK because the two answer different questions. OK asks whether
// anything is provably wrong; StrictOK asks whether everything is provably right,
// which an unsealed session cannot be — its tail could have been removed and the
// chain would still verify. An operator collecting evidence wants the second; a
// health check on a live server, which always has one session open, wants the
// first.
func (r DirReport) StrictOK() bool { return r.OK() && r.Unsealed() == 0 }

// readEntries loads a session file as a slice of entries.
func readEntries(path string) ([]AuditEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read audit file: %w", err)
	}
	defer func() { _ = f.Close() }()

	var entries []AuditEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var e AuditEntry
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(path), err)
		}
		entries = append(entries, e)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read audit file %q: %w", filepath.Base(path), err)
	}
	return entries, nil
}

// readManifest loads every manifest record from a directory, or nil when the
// manifest does not exist.
func readManifest(dir string) ([]ManifestRecord, error) {
	f, err := os.Open(filepath.Join(dir, ManifestName))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", ManifestName, err)
	}
	defer func() { _ = f.Close() }()

	var records []ManifestRecord
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var r ManifestRecord
		if err := json.Unmarshal(line, &r); err != nil {
			return nil, fmt.Errorf("%s: %w", ManifestName, err)
		}
		records = append(records, r)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", ManifestName, err)
	}
	return records, nil
}

// VerifyFile verifies a single session (or legacy single-file) audit chain rooted
// at seq 0, returning the entries it read. When key is non-nil it also checks that
// every entry carries a valid HMAC under key.
func VerifyFile(path string, key []byte) ([]AuditEntry, error) {
	entries, err := readEntries(path)
	if err != nil {
		return nil, err
	}
	if err := VerifyChain(entries); err != nil {
		return entries, err
	}
	if key != nil {
		return entries, VerifyMAC(entries, key)
	}
	return entries, nil
}

// VerifyDir verifies a directory of per-session audit files: the manifest chain,
// each session file's own chain, and that every sealed manifest record matches
// its session file's head. A session file with no manifest record, or a sealed
// record whose head does not match its file, is a problem — that is how a dropped
// or rewritten session is caught. An unsealed session (open record, no seal) is
// reported but not itself a failure: the process may still be running, or have
// been killed, and the record's presence is the point.
//
// Read that last sentence with care, because it is the weakest part of this
// package and lab testing showed the old rendering hid it. There is no seal to
// cross-check an open session against, so **any prefix of its chain verifies**:
// dropping the tail of an unsealed session is undetectable here. The chain's own
// integrity is intact either way — that is exactly why it cannot help.
//
// It matters more than it sounds. The kill ladder's Shutdown rung, and any crash
// or hard kill, leave a session unsealed as a matter of course — so the sessions
// most likely to be worth tampering with are precisely the ones with no seal.
// String() therefore marks them UNSEALED rather than ok, and Strict() lets a
// caller treat them as failures. Detecting truncation *within* an open session
// needs a periodically checkpointed head in the manifest; see roadmap S12.
//
// The returned error is for I/O failures only; integrity failures are collected
// in DirReport.Problems so a report names every issue at once. When key is
// non-nil, each session file's entries are also MAC-verified under key.
func VerifyDir(dir string, key []byte) (DirReport, error) {
	rep := DirReport{Dir: dir}

	records, err := readManifest(dir)
	if err != nil {
		return rep, err
	}
	if records == nil {
		rep.Problems = append(rep.Problems, "no "+ManifestName+" in directory")
	} else if err := VerifyManifest(records, key); err != nil {
		rep.Problems = append(rep.Problems, err.Error())
	}

	// The last sealed record per session file is the one to cross-check against.
	sealed := map[string]ManifestRecord{}
	known := map[string]bool{}
	for _, r := range records {
		known[r.SessionFile] = true
		if r.SealedAt != "" {
			sealed[r.SessionFile] = r
		}
	}

	files, err := filepath.Glob(filepath.Join(dir, "session-*.audit.jsonl"))
	if err != nil {
		return rep, fmt.Errorf("list session files: %w", err)
	}
	sort.Strings(files)

	seenFile := map[string]bool{}
	for _, path := range files {
		base := filepath.Base(path)
		seenFile[base] = true
		sr := SessionReport{File: base}

		entries, readErr := readEntries(path)
		if readErr != nil {
			return rep, readErr
		}
		sr.Entries = len(entries)
		sr.Err = VerifyChain(entries)
		if sr.Err == nil && key != nil {
			sr.Err = VerifyMAC(entries, key)
		}
		if sr.Err != nil {
			rep.Problems = append(rep.Problems, fmt.Sprintf("%s: %v", base, sr.Err))
		}

		if !known[base] {
			rep.Problems = append(rep.Problems, base+": present on disk but absent from the manifest")
		}
		if rec, ok := sealed[base]; ok {
			sr.Sealed = true
			head := ""
			if n := len(entries); n > 0 {
				head = entries[n-1].EntryHash
			}
			if uint64(len(entries)) != rec.HeadSeq || head != rec.HeadHash {
				rep.Problems = append(rep.Problems, fmt.Sprintf(
					"%s: head does not match its manifest seal (file seq=%d hash=%s, manifest seq=%d hash=%s)",
					base, len(entries), short(head), rec.HeadSeq, short(rec.HeadHash)))
			}
		}
		rep.Sessions = append(rep.Sessions, sr)
	}

	// A manifest record naming a file that is not on disk is a dropped session.
	for _, r := range records {
		if !seenFile[r.SessionFile] {
			rep.Problems = append(rep.Problems, r.SessionFile+": named in the manifest but missing from disk")
		}
	}

	return rep, nil
}

func short(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12]
}

// String renders a directory report for the CLI: one line per session, then any
// problems.
func (r DirReport) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", r.Dir)
	unsealed := 0
	for _, s := range r.Sessions {
		state := "sealed"
		if !s.Sealed {
			state = "open"
			unsealed++
		}
		// An unsealed session is not "ok". Its chain is intact, but there is no
		// seal to cross-check the head against, so a truncated tail verifies just
		// as cleanly -- and printing "ok" beside it read as a clean bill of health.
		mark := "ok"
		switch {
		case s.Err != nil:
			mark = "BROKEN"
		case !s.Sealed:
			mark = "UNSEALED"
		}
		fmt.Fprintf(&b, "  %-8s %-7s %4d entries  %s\n", mark, state, s.Entries, s.File)
	}
	if len(r.Problems) == 0 {
		fmt.Fprintf(&b, "verified: %d session(s), manifest chain intact\n", len(r.Sessions))
		if unsealed > 0 {
			fmt.Fprintf(&b, "warning: %d session(s) carry no seal. Their chains are internally "+
				"consistent, but with no sealed head to compare against, a removed tail cannot be "+
				"detected. A session is unsealed when the process was killed or is still running. "+
				"Use --strict to treat this as a failure.\n", unsealed)
		}
	} else {
		fmt.Fprintf(&b, "%d problem(s):\n", len(r.Problems))
		for _, p := range r.Problems {
			fmt.Fprintf(&b, "  - %s\n", p)
		}
	}
	return b.String()
}
