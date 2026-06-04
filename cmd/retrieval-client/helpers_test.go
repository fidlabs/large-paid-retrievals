package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPromptYesNo(t *testing.T) {
	restore := restoreHooks(t)
	defer restore()

	promptReader = strings.NewReader("yes\n")
	ok, err := promptYesNo("Proceed? ")
	if err != nil || !ok {
		t.Fatalf("yes: ok=%v err=%v", ok, err)
	}

	promptReader = strings.NewReader("n\n")
	ok, err = promptYesNo("Proceed? ")
	if err != nil || ok {
		t.Fatalf("no: ok=%v err=%v", ok, err)
	}

	promptReader = strings.NewReader("Y\n")
	ok, err = promptYesNo("Proceed? ")
	if err != nil || !ok {
		t.Fatalf("Y: ok=%v err=%v", ok, err)
	}
}

func TestGetenv(t *testing.T) {
	const key = "RETRIEVAL_CLIENT_TEST_ENV"
	t.Setenv(key, "  value  ")
	if got := getenv(key, "fallback"); got != "value" {
		t.Fatalf("got %q", got)
	}
	t.Setenv(key, "")
	if got := getenv(key, "fallback"); got != "fallback" {
		t.Fatalf("got %q", got)
	}
}

func TestSumTokenValues(t *testing.T) {
	got, err := sumTokenValues([]string{"0.1", "0.2", "0.3"})
	if err != nil || got != "0.6" {
		t.Fatalf("got %q err=%v", got, err)
	}
	got, err = sumTokenValues([]string{"1", "2.5"})
	if err != nil || got != "3.5" {
		t.Fatalf("got %q err=%v", got, err)
	}
	_, err = sumTokenValues([]string{"bad"})
	if err == nil {
		t.Fatal("expected parse error")
	}
}

func TestSanitizeFilename(t *testing.T) {
	if sanitizeFilename("") != "piece" {
		t.Fatal("empty")
	}
	got := sanitizeFilename("bafkreid/abc:def")
	if got != "bafkreid_abc_def" {
		t.Fatalf("got %q", got)
	}
	if sanitizeFilename("Valid-Name.CID123") != "Valid-Name.CID123" {
		t.Fatal("alphanumeric preserved")
	}
}

func TestTruncateForLog(t *testing.T) {
	if truncateForLog("  hi  ", 10) != "hi" {
		t.Fatal("trim")
	}
	long := strings.Repeat("x", 20)
	got := truncateForLog(long, 5)
	if got != "xxxxx…" {
		t.Fatalf("got %q", got)
	}
}

func TestCollectCIDs(t *testing.T) {
	dir := t.TempDir()
	cidFile := filepath.Join(dir, "cids.txt")
	if err := os.WriteFile(cidFile, []byte("bafy1\nbafy2,bafy3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := collectCIDs([]string{"bafy0"}, cidFile, []string{" bafy4 "})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"bafy0", "bafy4", "bafy1", "bafy2", "bafy3"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Fatalf("index %d: got %q want %q", i, got[i], w)
		}
	}
}

func TestCollectCIDsRejectsDuplicate(t *testing.T) {
	_, err := collectCIDs([]string{"bafy0", "bafy0"}, "", nil)
	if err == nil || !strings.Contains(err.Error(), "duplicate CID") {
		t.Fatalf("got %v", err)
	}
}

func TestCollectCIDsMissingFile(t *testing.T) {
	_, err := collectCIDs(nil, filepath.Join(t.TempDir(), "missing.txt"), nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestExtractPieceCIDsSkipsEmptyPieceCID(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "manifest.json")
	const manifest = `{"pieces":[{"piece_cid":""},{"piece_cid":"baga1"}]}`
	if err := os.WriteFile(p, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	cids, err := extractPieceCIDsFromManifest(p)
	if err != nil || len(cids) != 1 || cids[0] != "baga1" {
		t.Fatalf("got %v err=%v", cids, err)
	}
}
