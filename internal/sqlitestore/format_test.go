package sqlitestore

import (
	"database/sql"
	"testing"
	"time"
)

func TestFormatUnixHelpers(t *testing.T) {
	if formatUnix(0) != "-" || formatUnix(-1) != "-" {
		t.Fatalf("zero ts: %q", formatUnix(0))
	}
	ts := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC).Unix()
	got := formatUnix(ts)
	if got != "2026-01-02T03:04:05Z" {
		t.Fatalf("formatUnix=%q", got)
	}
	if formatNullUnix(sql.NullInt64{}) != "-" {
		t.Fatal("invalid null")
	}
	if formatNullUnix(sql.NullInt64{Int64: ts, Valid: true}) != got {
		t.Fatal("valid null")
	}
}
