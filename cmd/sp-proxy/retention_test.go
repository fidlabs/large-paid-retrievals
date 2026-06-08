package main

import (
	"bytes"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/fidlabs/paid-retrievals/internal/sqlitestore"
)

func TestStartDBRetentionPrunerDisabled(t *testing.T) {
	s, err := sqlitestore.OpenStore(filepath.Join(t.TempDir(), "sp.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	startDBRetentionPruner(s, 0, logger)
	if !bytes.Contains(buf.Bytes(), []byte("db retention pruning disabled")) {
		t.Fatalf("log: %s", buf.String())
	}
}

func TestStartDBRetentionPrunerRunsOnce(t *testing.T) {
	s, err := sqlitestore.OpenStore(filepath.Join(t.TempDir(), "sp.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
	startDBRetentionPruner(s, 7*24*time.Hour, logger)
	time.Sleep(50 * time.Millisecond)
}
