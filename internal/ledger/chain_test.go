package ledger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The README claims `make verify-evidence` fails if a committed result was
// altered after the fact. These tests are what make that a fact rather than a
// promise — each one performs the specific tamper an embarrassed author would
// actually attempt.

func setup(t *testing.T) (root string, chain *Chain) {
	t.Helper()
	root = t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "bench", "results"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"a.samples.json": `{"benchmark":"decide/allow","median":10.8}`,
		"b.samples.json": `{"benchmark":"decide/deny","median":12.8}`,
	} {
		if err := os.WriteFile(filepath.Join(root, "bench", "results", name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	chain = &Chain{path: filepath.Join(root, "bench", "results", LedgerFilename)}
	files, err := FindResults(root, "bench/results")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if _, err := chain.Append(root, f); err != nil {
			t.Fatal(err)
		}
	}
	return root, chain
}

func TestCleanChainVerifies(t *testing.T) {
	root, chain := setup(t)
	if n := len(chain.Entries); n != 2 {
		t.Fatalf("expected 2 entries, got %d", n)
	}
	if p := chain.Verify(root); len(p) != 0 {
		t.Fatalf("clean chain reported problems: %v", p)
	}
}

func TestDetectsAlteredResultFile(t *testing.T) {
	root, chain := setup(t)

	// The realistic attack: quietly improve a published number.
	path := filepath.Join(root, "bench", "results", "a.samples.json")
	if err := os.WriteFile(path, []byte(`{"benchmark":"decide/allow","median":1.0}`), 0o644); err != nil {
		t.Fatal(err)
	}

	problems := chain.Verify(root)
	if len(problems) == 0 {
		t.Fatal("altered result file was not detected")
	}
	if problems[0].Kind != "content-changed" {
		t.Errorf("expected content-changed, got %q", problems[0].Kind)
	}
}

func TestDetectsEditedLedgerEntry(t *testing.T) {
	root, chain := setup(t)

	// Rewriting the recorded hash to match a doctored file — defeated because
	// the entry hash covers the file hash.
	chain.Entries[0].FileSHA256 = strings.Repeat("f", 64)

	problems := chain.Verify(root)
	var kinds []string
	for _, p := range problems {
		kinds = append(kinds, p.Kind)
	}
	if !contains(kinds, "entry-tampered") {
		t.Errorf("expected entry-tampered, got %v", kinds)
	}
}

func TestDetectsDeletedInteriorEntry(t *testing.T) {
	root, _ := setup(t)

	// Rebuild a 3-entry chain so there is a genuine interior link to remove.
	if err := os.WriteFile(filepath.Join(root, "bench", "results", "c.samples.json"),
		[]byte(`{"benchmark":"taint/observe","median":2.4}`), 0o644); err != nil {
		t.Fatal(err)
	}
	chain := &Chain{path: filepath.Join(root, "bench", "results", LedgerFilename)}
	files, _ := FindResults(root, "bench/results")
	for _, f := range files {
		if _, err := chain.Append(root, f); err != nil {
			t.Fatal(err)
		}
	}
	if len(chain.Entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(chain.Entries))
	}

	// Drop the middle entry — the case a naive "re-hash each file" check misses.
	chain.Entries = append(chain.Entries[:1], chain.Entries[2:]...)

	problems := chain.Verify(root)
	var kinds []string
	for _, p := range problems {
		kinds = append(kinds, p.Kind)
	}
	if !contains(kinds, "broken-link") {
		t.Errorf("expected broken-link after deleting an interior entry, got %v", kinds)
	}
}

func TestDetectsMissingFile(t *testing.T) {
	root, chain := setup(t)
	if err := os.Remove(filepath.Join(root, "bench", "results", "b.samples.json")); err != nil {
		t.Fatal(err)
	}
	problems := chain.Verify(root)
	var kinds []string
	for _, p := range problems {
		kinds = append(kinds, p.Kind)
	}
	if !contains(kinds, "missing") {
		t.Errorf("expected missing, got %v", kinds)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	root, chain := setup(t)
	if err := chain.Save(); err != nil {
		t.Fatal(err)
	}
	reloaded, err := Load(chain.path)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Head() != chain.Head() {
		t.Errorf("head changed across save/load: %s vs %s", reloaded.Head(), chain.Head())
	}
	if p := reloaded.Verify(root); len(p) != 0 {
		t.Errorf("reloaded chain failed verification: %v", p)
	}
}

// The ledger must never anchor itself: doing so would be a hash that depends
// on its own value.
func TestFindResultsExcludesLedger(t *testing.T) {
	root, chain := setup(t)
	if err := chain.Save(); err != nil {
		t.Fatal(err)
	}
	files, err := FindResults(root, "bench/results")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, LedgerFilename) {
			t.Fatalf("FindResults returned the ledger itself: %s", f)
		}
	}
}

func TestEmptyChainHeadIsGenesis(t *testing.T) {
	if (&Chain{}).Head() != GenesisHash {
		t.Error("empty chain head should be GenesisHash")
	}
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
