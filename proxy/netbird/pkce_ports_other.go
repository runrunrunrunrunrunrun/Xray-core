//go:build !windows

package netbird

func getSystemExcludedPortRanges() []excludedPortRange {
	return nil
}
