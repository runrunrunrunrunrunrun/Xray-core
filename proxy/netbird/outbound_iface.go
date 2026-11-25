package netbird

import (
	"slices"
	"strings"
	"sync"

	nbnet "github.com/netbirdio/netbird/client/net"
)

var (
	outboundIfaceMu     sync.Mutex
	hostOutboundIface   string
	handlerIfaceOrder   []string
	handlerIfaceCounts  = make(map[string]int)
)

// SetOutboundInterface sets a process-wide physical outbound interface override
// (for example, from desktop_bin's -interface flag) for NetBird underlay sockets.
func SetOutboundInterface(name string) {
	outboundIfaceMu.Lock()
	hostOutboundIface = strings.TrimSpace(name)
	syncOutboundInterfaceLocked()
	outboundIfaceMu.Unlock()
}

func acquireHandlerOutboundInterface(name string) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return
	}
	outboundIfaceMu.Lock()
	if handlerIfaceCounts[trimmed] == 0 {
		handlerIfaceOrder = append(handlerIfaceOrder, trimmed)
	}
	handlerIfaceCounts[trimmed]++
	syncOutboundInterfaceLocked()
	outboundIfaceMu.Unlock()
}

func releaseHandlerOutboundInterface(name string) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return
	}
	outboundIfaceMu.Lock()
	if count := handlerIfaceCounts[trimmed]; count <= 1 {
		delete(handlerIfaceCounts, trimmed)
		if idx := slices.Index(handlerIfaceOrder, trimmed); idx >= 0 {
			handlerIfaceOrder = slices.Delete(handlerIfaceOrder, idx, idx+1)
		}
	} else {
		handlerIfaceCounts[trimmed] = count - 1
	}
	syncOutboundInterfaceLocked()
	outboundIfaceMu.Unlock()
}

func syncOutboundInterfaceLocked() {
	effective := hostOutboundIface
	if effective == "" && len(handlerIfaceOrder) > 0 {
		effective = handlerIfaceOrder[len(handlerIfaceOrder)-1]
	}
	nbnet.SetExternalOutboundInterface(effective)
}
