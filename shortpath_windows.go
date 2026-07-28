//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

var (
	modkernel32          = syscall.NewLazyDLL("kernel32.dll")
	procGetShortPathName = modkernel32.NewProc("GetShortPathNameW")
)

// toShortPath converts a path to its Windows 8.3 short form (no spaces),
// so it's safe to pass to Tor's ClientTransportPlugin line, which splits
// on whitespace and does not understand quoting.
func toShortPath(path string) (string, error) {
	longPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	buf := make([]uint16, 260)
	n, _, callErr := procGetShortPathName.Call(
		uintptr(unsafe.Pointer(longPtr)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if n == 0 {
		return "", callErr
	}
	if int(n) > len(buf) {
		buf = make([]uint16, n)
		n, _, callErr = procGetShortPathName.Call(
			uintptr(unsafe.Pointer(longPtr)),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
		)
		if n == 0 {
			return "", callErr
		}
	}
	return syscall.UTF16ToString(buf[:n]), nil
}
