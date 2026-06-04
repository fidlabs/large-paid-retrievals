package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractPieceCIDsFromManifest(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "manifest.json")
	// contents is irrelevant per requirement; only pieces[].piece_cid matters.
	const manifest = `{
	  "pieces": [
	    {"piece_cid": "baga1", "payload_cid": "bafy1"},
	    {"piece_cid": "baga2", "payload_cid": "bafy2"}
	  ]
	}`
	if err := os.WriteFile(p, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}

	cids, err := extractPieceCIDsFromManifest(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cids) != 2 {
		t.Fatalf("expected 2 piece_cids, got %d: %#v", len(cids), cids)
	}
	if cids[0] != "baga1" || cids[1] != "baga2" {
		t.Fatalf("unexpected cids: %#v", cids)
	}
}

func TestExtractPieceCIDsFromManifestRejectsDuplicate(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "manifest.json")
	const manifest = `{"pieces":[{"piece_cid":"baga1"},{"piece_cid":"baga1"}]}`
	if err := os.WriteFile(p, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := extractPieceCIDsFromManifest(p)
	if err == nil || !strings.Contains(err.Error(), "duplicate CID") {
		t.Fatalf("got %v", err)
	}
}

func TestExtractPieceCIDsFromManifestInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(p, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := extractPieceCIDsFromManifest(p)
	if err == nil {
		t.Fatalf("expected error")
	}
}
