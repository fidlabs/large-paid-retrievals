package dealstore

import (
	"fmt"
	"time"
)

// ValidateDBRetention rejects retention values that would prune pool_credits before
// payment txs age past PaidAccessTTL, reopening on-chain payment replay. Use 0 to
// disable pruning. Values >= PaidAccessTTL are accepted.
func ValidateDBRetention(retention time.Duration) error {
	if retention <= 0 {
		return nil
	}
	if retention < PaidAccessTTL {
		return fmt.Errorf("dealstore: db retention %s must be >= %s (paid-access / payment-tx freshness window), or 0 to disable pruning",
			retention, PaidAccessTTL)
	}
	return nil
}
