package internet

import (
	"strings"
	"sync"
)

var (
	tunOutboundIfaceMu        sync.RWMutex
	tunOutboundIface          string
	tunOutboundIfaceListeners []func(string)
)

// SetTunOutboundInterface records the physical outbound interface currently
// tracked by the TUN inbound and notifies registered listeners on change.
func SetTunOutboundInterface(name string) {
	trimmed := strings.TrimSpace(name)

	tunOutboundIfaceMu.Lock()
	changed := tunOutboundIface != trimmed
	tunOutboundIface = trimmed
	var listeners []func(string)
	if changed && len(tunOutboundIfaceListeners) > 0 {
		listeners = append([]func(string){}, tunOutboundIfaceListeners...)
	}
	tunOutboundIfaceMu.Unlock()

	for _, fn := range listeners {
		fn(trimmed)
	}
}

// GetTunOutboundInterface returns the physical outbound interface currently
// tracked by the TUN inbound, or an empty string if none is active.
func GetTunOutboundInterface() string {
	tunOutboundIfaceMu.RLock()
	defer tunOutboundIfaceMu.RUnlock()
	return tunOutboundIface
}

// RegisterTunOutboundInterfaceListener registers a callback invoked immediately
// if an interface is already set and whenever it changes thereafter.
func RegisterTunOutboundInterfaceListener(fn func(string)) {
	if fn == nil {
		return
	}
	tunOutboundIfaceMu.Lock()
	tunOutboundIfaceListeners = append(tunOutboundIfaceListeners, fn)
	current := tunOutboundIface
	tunOutboundIfaceMu.Unlock()

	if current != "" {
		fn(current)
	}
}
