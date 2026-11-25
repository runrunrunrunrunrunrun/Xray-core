NetBird runtime patches are maintained in the fork module configured in `go.mod`:

- Repository: `https://github.com/runrunrunrunrunrunrun/netbird`
- Tag: `v0.83.2-onexray.1` (branch `fix/netstack-outbound-bind`, based on `v0.83.2`)

This patch enables `client/net` external outbound interface binding (`IP_UNICAST_IF` /
`IPV6_UNICAST_IF` on Windows, `SO_BINDTODEVICE` on Linux, `IP_BOUND_IF` on Darwin)
and Android `VpnService.protect` callbacks even when `embed.Client` enables netstack mode.
