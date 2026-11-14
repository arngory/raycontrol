package provision

import "testing"

// The test stand's switch lifts the age rule of a forced switch and
// nothing else; without it the rule is a subscription's lifetime.
func TestUnsafeForceSwitchAtAnyAge(t *testing.T) {
	t.Cleanup(func() { forceAnyAge.Store(false) })
	if got := forceMinAge(); got != SiteKeyMinAge {
		t.Fatalf("the age a forced switch asks of the key in use: %v, want %v", got, SiteKeyMinAge)
	}
	UnsafeForceSwitchAtAnyAge()
	if got := forceMinAge(); got != 0 {
		t.Fatalf("with the stand's switch a forced switch still asks %v of the key in use", got)
	}
	if err := (SiteKeyPolicy{Period: DefaultSiteKeyPeriod, Lead: SiteKeyMinAge - 1}).Check(); err == nil {
		t.Fatal("the stand's switch let a lead under a subscription's lifetime through")
	}
}
