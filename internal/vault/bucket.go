package vault

import (
	"sync"
	"time"
)

type Bucket struct {
	// ponytail: one global bucket, per-connection buckets if Maple ever opens more than one VM.
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
	now    func() time.Time
	mu     sync.Mutex
}

func NewBucket(rate, burst float64, now func() time.Time) *Bucket {
	return &Bucket{rate: rate, burst: burst, tokens: burst, last: now(), now: now}
}

func (b *Bucket) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	b.tokens = min(b.burst, b.tokens+now.Sub(b.last).Seconds()*b.rate)
	b.last = now

	if b.tokens < 1 {
		return false
	}

	b.tokens--
	return true
}
