package dealstore

import (
	"testing"
	"time"
)

func TestValidateDBRetention(t *testing.T) {
	if err := ValidateDBRetention(0); err != nil {
		t.Fatalf("zero retention: %v", err)
	}
	if err := ValidateDBRetention(PaidAccessTTL); err != nil {
		t.Fatalf("exact ttl: %v", err)
	}
	if err := ValidateDBRetention(7 * 24 * time.Hour); err != nil {
		t.Fatalf("default retention: %v", err)
	}
	if err := ValidateDBRetention(6 * time.Hour); err == nil {
		t.Fatal("expected error for retention shorter than PaidAccessTTL")
	}
}
