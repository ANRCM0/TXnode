//go:build linux

package usagebucket

// NewNativeLoadFaultCoordinator exposes an existing private durability hook only
// in Go's test archive. Production binaries and configuration gain no hook.
func NewNativeLoadFaultCoordinator(dir string, fault func(string) error) (*Coordinator, error) {
	return newAsyncCoordinator(CoordinatorOptions{}, func() (*Store, error) { return openStore(dir, StoreOptions{}, fault) })
}

type NativeLoadQueueDepth struct {
	Meters         int
	RetainedEvents int
	SealedBuckets  int
	EventCapacity  int
	InFlight       bool
	Dropped        uint64
}

// NativeLoadFaultQueueSnapshot reads the real bounded queue without opening a
// production monitoring or fault-injection API.
func NativeLoadFaultQueueSnapshot(c *Coordinator) NativeLoadQueueDepth {
	c.mu.Lock()
	meters := append([]*Meter(nil), c.meters...)
	result := NativeLoadQueueDepth{Meters: len(meters), EventCapacity: c.status.RetainedEventCapacity, InFlight: c.status.InFlight}
	c.mu.Unlock()
	for _, meter := range meters {
		snapshot := meter.Snapshot()
		result.Dropped += snapshot.Status.DroppedEvents
		result.SealedBuckets += len(snapshot.Sealed)
		result.RetainedEvents += len(snapshot.Open.Events)
		for _, bucket := range snapshot.Sealed {
			result.RetainedEvents += len(bucket.Events)
		}
	}
	return result
}
