// Command airlock is the operator CLI.
//
// Today it manages the evidence ledger over benchmark results. As the system
// grows this is where `sandbox`, `policy simulate`, `replay` and `verify-chain`
// will live — the ledger commands are the first slice of that, and they run on
// the project's own published numbers so the tamper-evidence mechanism is
// demonstrated rather than described.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/bhavya/airlock/internal/ledger"
)

const usage = `airlock — operator CLI

Usage:
  airlock anchor-evidence [--dir DIR]   hash every result file into the ledger
  airlock verify-evidence [--dir DIR]   re-verify the ledger and every file
  airlock evidence-head   [--dir DIR]   print the current head hash

The ledger is append-only and hash-chained: altering an anchored result, or
removing or reordering a ledger entry, breaks verification. Commit both the
results and the ledger, and git history pins the head hash.

Flags:
  --dir DIR   directory holding evidence (default: bench/results)
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	dir := fs.String("dir", "bench/results", "directory holding evidence files")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	_ = fs.Parse(os.Args[2:])

	root, err := repoRoot()
	if err != nil {
		fatal("locating repo root: %v", err)
	}

	switch cmd {
	case "anchor-evidence":
		os.Exit(anchor(root, *dir))
	case "verify-evidence":
		os.Exit(verify(root, *dir))
	case "evidence-head":
		os.Exit(head(root, *dir))
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
}

func ledgerPath(root, dir string) string {
	return filepath.Join(root, dir, ledger.LedgerFilename)
}

// anchor adds any not-yet-anchored result file to the chain.
//
// Re-anchoring an already-recorded file whose contents changed is deliberately
// allowed and appends a NEW entry rather than editing the old one: the point
// of an append-only log is that the earlier claim remains visible. A rerun
// that produced different numbers should leave both in the record.
func anchor(root, dir string) int {
	chain, err := ledger.Load(ledgerPath(root, dir))
	if err != nil {
		fatal("loading ledger: %v", err)
	}

	files, err := ledger.FindResults(root, dir)
	if err != nil {
		fatal("scanning %s: %v", dir, err)
	}
	if len(files) == 0 {
		fmt.Printf("no evidence files under %s — nothing to anchor\n", dir)
		return 0
	}

	// Skip files whose current contents are already the most recent anchor.
	latest := map[string]string{}
	for _, e := range chain.Entries {
		latest[e.Path] = e.FileSHA256
	}

	added := 0
	for _, f := range files {
		sum, err := ledger.HashFile(filepath.Join(root, f))
		if err != nil {
			fatal("hashing %s: %v", f, err)
		}
		if latest[f] == sum {
			continue
		}
		e, err := chain.Append(root, f)
		if err != nil {
			fatal("anchoring %s: %v", f, err)
		}
		fmt.Printf("  + seq %-3d %s\n      sha256 %s\n", e.Seq, e.Path, e.FileSHA256)
		added++
	}

	if added == 0 {
		fmt.Printf("all %d evidence file(s) already anchored; head %s\n", len(files), chain.Head()[:12])
		return 0
	}
	if err := chain.Save(); err != nil {
		fatal("saving ledger: %v", err)
	}
	fmt.Printf("\nanchored %d file(s); head is now %s\n", added, chain.Head()[:12])
	fmt.Printf("commit %s/%s together with the results.\n", dir, ledger.LedgerFilename)
	return 0
}

func verify(root, dir string) int {
	chain, err := ledger.Load(ledgerPath(root, dir))
	if err != nil {
		fatal("loading ledger: %v", err)
	}
	if len(chain.Entries) == 0 {
		fmt.Printf("ledger at %s/%s is empty — nothing to verify\n", dir, ledger.LedgerFilename)
		return 0
	}

	problems := chain.Verify(root)
	if len(problems) == 0 {
		fmt.Printf("OK: %d entries verified, head %s\n", len(chain.Entries), chain.Head()[:12])
		fmt.Println("every anchored file matches the hash recorded when it was published.")
		return 0
	}

	fmt.Fprintf(os.Stderr, "FAILED: %d problem(s) in %d entries\n\n", len(problems), len(chain.Entries))
	for _, p := range problems {
		fmt.Fprintf(os.Stderr, "  %s\n", p)
	}
	fmt.Fprintln(os.Stderr, "\nEvidence has been altered since it was anchored, or the ledger itself was edited.")
	return 1
}

func head(root, dir string) int {
	chain, err := ledger.Load(ledgerPath(root, dir))
	if err != nil {
		fatal("loading ledger: %v", err)
	}
	fmt.Println(chain.Head())
	return 0
}

// repoRoot walks up looking for go.mod so the CLI works from any subdirectory.
func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no go.mod found above %s", dir)
		}
		dir = parent
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "airlock: "+format+"\n", args...)
	os.Exit(1)
}
