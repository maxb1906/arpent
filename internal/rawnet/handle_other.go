//go:build !linux && !windows

package rawnet

// macOS et autres : mode avancé non pris en charge (BPF non implémenté).
func check() Status { return Status{Reason: "advanced.reason.os"} }

func open(Iface) (Handle, error) { return nil, ErrNotSupported }
