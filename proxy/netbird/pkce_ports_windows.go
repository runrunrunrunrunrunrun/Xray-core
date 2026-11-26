//go:build windows

package netbird

// Excluded Windows ports are detected directly when net.Listen fails with WSAEACCES,
// avoiding spawning netsh.exe from inside libXray.dll in the GUI process.
func getSystemExcludedPortRanges() []excludedPortRange {
	return nil
}
