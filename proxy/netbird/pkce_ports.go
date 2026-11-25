package netbird

import (
	"bufio"
	"strconv"
	"strings"
)

type excludedPortRange struct {
	start int
	end   int
}

func isPortExcluded(port int, ranges []excludedPortRange) bool {
	if port <= 0 {
		return false
	}
	for _, r := range ranges {
		if port >= r.start && port <= r.end {
			return true
		}
	}
	return false
}

// parseExcludedPortRanges parses `netsh interface ipv4 show excludedportrange protocol=tcp`
// output across Windows locales by detecting either the English header or the dashed rule.
func parseExcludedPortRanges(output string) []excludedPortRange {
	var ranges []excludedPortRange
	scanner := bufio.NewScanner(strings.NewReader(output))

	inTable := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.Contains(line, "---") {
			inTable = true
			continue
		}
		if strings.Contains(line, "Start Port") && strings.Contains(line, "End Port") {
			inTable = true
			continue
		}
		if !inTable {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		startPort, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		endPort, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		if startPort < 1 || endPort < startPort || endPort > 65535 {
			continue
		}
		ranges = append(ranges, excludedPortRange{start: startPort, end: endPort})
	}
	return ranges
}
