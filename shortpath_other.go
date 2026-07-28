//go:build !windows

package main

// toShortPath is a no-op stub for non-Windows builds (this program only
// ships for Windows; this stub exists purely so `go vet`/local dev on
// other platforms still compiles).
func toShortPath(path string) (string, error) {
	return path, nil
}
