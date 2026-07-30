// Package ledger implements the hash-chained, append-only record that makes
// Airlock's audit trail tamper-evident.
//
// The full system uses this for agent trajectories: every tool call, policy
// decision and taint transition is appended, so an intruder who deletes the
// evidence of what they did leaves a broken chain behind. That is Phase 3.
//
// It is used here, first, on the project's own benchmark results. If Airlock
// claims to make records tamper-evident, the least it can do is apply that to
// its own published numbers — and it means `make verify-evidence` is a real
// demonstration of the mechanism rather than a description of one.
//
// # Guarantees
//
// The chain detects *any* modification to a recorded file or to the chain
// itself, including reordering and deletion of interior entries, provided the
// verifier knows the expected head hash. Committing the ledger to git supplies
// exactly that: the head hash is in the history, signed by the commit.
//
// It does NOT prevent an author from rewriting the whole chain and
// force-pushing. Tamper-*evidence* is not tamper-*proofing*. What it buys is
// that quiet, selective edits — the realistic failure mode for a benchmark
// someone is embarrassed by — become loud.
package ledger

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// GenesisHash is the predecessor of the first entry. A fixed, non-zero
// constant so that an empty chain and a chain whose first entry was deleted
// are distinguishable.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Entry is one link. Field order in the struct is irrelevant; the hash is
// computed over an explicit canonical encoding (see canonicalBytes) so that
// changing this struct's layout, or the JSON marshaller's behaviour, cannot
// silently change historical hashes.
type Entry struct {
	Seq       uint64 `json:"seq"`
	Timestamp string `json:"timestamp"` // RFC3339 UTC
	Path      string `json:"path"`      // repo-relative
	FileSHA256 string `json:"file_sha256"`
	PrevHash  string `json:"prev_hash"`
	EntryHash string `json:"entry_hash"`
}

// canonicalBytes is the exact preimage of EntryHash.
//
// Deliberately a hand-rolled, unambiguous encoding rather than JSON: two JSON
// encoders can disagree on key order, escaping and whitespace, and a hash
// whose preimage depends on library behaviour is not reproducible across
// versions. The 0x1f separator cannot appear in any field.
func (e Entry) canonicalBytes() []byte {
	const sep = "\x1f"
	return []byte(strings.Join([]string{
		fmt.Sprintf("%d", e.Seq),
		e.Timestamp,
		e.Path,
		e.FileSHA256,
		e.PrevHash,
	}, sep))
}

func (e Entry) computeHash() string {
	sum := sha256.Sum256(e.canonicalBytes())
	return hex.EncodeToString(sum[:])
}

// Chain is an ordered list of entries, persisted as JSON Lines.
type Chain struct {
	Entries []Entry
	path    string
}

// Load reads a chain from disk. A missing file yields an empty chain, so the
// first `anchor` run needs no special case.
func Load(path string) (*Chain, error) {
	c := &Chain{path: path}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(text), &e); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, line, err)
		}
		c.Entries = append(c.Entries, e)
	}
	return c, sc.Err()
}

// Head returns the hash of the last entry, or GenesisHash if empty.
func (c *Chain) Head() string {
	if len(c.Entries) == 0 {
		return GenesisHash
	}
	return c.Entries[len(c.Entries)-1].EntryHash
}

// Append adds a file to the chain, hashing its current contents.
func (c *Chain) Append(repoRoot, path string) (Entry, error) {
	sum, err := HashFile(filepath.Join(repoRoot, path))
	if err != nil {
		return Entry{}, err
	}
	e := Entry{
		Seq:        uint64(len(c.Entries)),
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Path:       filepath.ToSlash(path),
		FileSHA256: sum,
		PrevHash:   c.Head(),
	}
	e.EntryHash = e.computeHash()
	c.Entries = append(c.Entries, e)
	return e, nil
}

// Save writes the chain atomically: a crash mid-write must not truncate the
// evidence.
func (c *Chain) Save() error {
	if err := os.MkdirAll(filepath.Dir(c.path), 0o755); err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	for _, e := range c.Entries {
		b, err := json.Marshal(e)
		if err != nil {
			f.Close()
			return err
		}
		if _, err := w.Write(append(b, '\n')); err != nil {
			f.Close()
			return err
		}
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}

// Problem is a single verification failure. Verification collects all of them
// rather than stopping at the first: when a chain is broken you want the whole
// picture, not a bisect.
type Problem struct {
	Seq  uint64
	Path string
	Kind string
	Detail string
}

func (p Problem) String() string {
	return fmt.Sprintf("seq %d (%s): %s — %s", p.Seq, p.Path, p.Kind, p.Detail)
}

// Verify recomputes the chain and re-hashes every referenced file.
//
// Three independent failures are detected:
//   - a file's contents changed since it was anchored
//   - an entry's own hash does not match its contents (the entry was edited)
//   - an entry's prev_hash does not match its predecessor (reorder or deletion)
func (c *Chain) Verify(repoRoot string) []Problem {
	var problems []Problem
	prev := GenesisHash

	for i, e := range c.Entries {
		if e.Seq != uint64(i) {
			problems = append(problems, Problem{e.Seq, e.Path, "sequence",
				fmt.Sprintf("entry at index %d claims seq %d", i, e.Seq)})
		}
		if e.PrevHash != prev {
			problems = append(problems, Problem{e.Seq, e.Path, "broken-link",
				fmt.Sprintf("prev_hash %s, expected %s — an entry was deleted, reordered or inserted",
					short(e.PrevHash), short(prev))})
		}
		if got := e.computeHash(); got != e.EntryHash {
			problems = append(problems, Problem{e.Seq, e.Path, "entry-tampered",
				fmt.Sprintf("recomputed %s, recorded %s", short(got), short(e.EntryHash))})
		}

		switch sum, err := HashFile(filepath.Join(repoRoot, e.Path)); {
		case errors.Is(err, os.ErrNotExist):
			problems = append(problems, Problem{e.Seq, e.Path, "missing", "anchored file no longer exists"})
		case err != nil:
			problems = append(problems, Problem{e.Seq, e.Path, "unreadable", err.Error()})
		case sum != e.FileSHA256:
			problems = append(problems, Problem{e.Seq, e.Path, "content-changed",
				fmt.Sprintf("file is now %s, was anchored as %s", short(sum), short(e.FileSHA256))})
		}

		prev = e.EntryHash
	}
	return problems
}

// HashFile returns the hex SHA-256 of a file's contents.
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// FindResults lists the evidence files under dir, sorted for determinism —
// two runs over an unchanged directory must produce the same chain.
func FindResults(root, dir string) ([]string, error) {
	var out []string
	full := filepath.Join(root, dir)
	err := filepath.Walk(full, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || strings.HasPrefix(info.Name(), ".") {
			return nil
		}
		// The ledger cannot anchor itself.
		if info.Name() == LedgerFilename {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	sort.Strings(out)
	return out, err
}

// LedgerFilename is the chain file kept alongside the evidence it anchors.
const LedgerFilename = "EVIDENCE.jsonl"

func short(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12]
}
