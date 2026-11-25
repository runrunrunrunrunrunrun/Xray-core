//go:build windows

package netbird

import "os/exec"

func getSystemExcludedPortRanges() []excludedPortRange {
	cmd := exec.Command("netsh", "interface", "ipv4", "show", "excludedportrange", "protocol=tcp")
	output, err := cmd.Output()
	if err != nil {
		return nil
	}
	return parseExcludedPortRanges(string(output))
}
