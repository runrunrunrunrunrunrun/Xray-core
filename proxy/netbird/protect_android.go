//go:build android

package netbird

import (
	nbnet "github.com/netbirdio/netbird/client/net"
)

func init() {
	// Default no-op before VpnService registers its ProtectFd callback.
	nbnet.SetAndroidProtectSocketFn(func(int32) bool {
		return true
	})
}

// SetAndroidProtectSocket registers the Android VpnService.protect callback
// with NetBird's socket factory.
func SetAndroidProtectSocket(fn func(fd int32) bool) {
	nbnet.SetAndroidProtectSocketFn(fn)
}
