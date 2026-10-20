package usageinterval

// Meter is the bounded-usage surface a kernel exposes to the usage_v2 runtime.
// The service owns the collector; the kernel owns the per-IO admission that
// charges bytes against it. Keeping this interface here (instead of on a
// concrete kernel type) is what lets TX-Node switch data planes without the
// service importing any kernel implementation.
type Meter interface {
	// EnableEnforcingBounded turns on admission; false means the meter cannot
	// enforce and native usage must stay disabled.
	EnableEnforcingBounded() bool
	// StopBoundedUsageTraffic stops charging new IO; the collector drains.
	StopBoundedUsageTraffic()
}
