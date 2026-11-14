//go:build race

package naive

// raceDetector: under the race detector sync.Pool drops what is put back
// at random, so a pooled buffer is allocated again and no bound on
// allocations holds (allocBound).
const raceDetector = true
