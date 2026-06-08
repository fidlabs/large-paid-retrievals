package sqlitestore

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

type failWriter struct {
	writes int
	failAt int
}

func (f *failWriter) Write(p []byte) (int, error) {
	f.writes++
	if f.writes >= f.failAt {
		return 0, errors.New("write failed")
	}
	return len(p), nil
}

func TestDumpStateWriteError(t *testing.T) {
	s, err := OpenStore(filepath.Join(t.TempDir(), "sp.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()

	for _, failAt := range []int{1, 2, 3, 4, 5, 6} {
		if err := s.DumpState(ctx, &failWriter{failAt: failAt}); err == nil {
			t.Fatalf("failAt=%d expected write error", failAt)
		}
	}
}
