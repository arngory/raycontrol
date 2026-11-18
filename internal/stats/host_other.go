//go:build !linux

package stats

// HostReader reads nothing off Linux: a node runs on Linux only, and rayctl
// elsewhere asks a node's rayd.
func HostReader(string) func() Host { return func() Host { return Host{} } }
