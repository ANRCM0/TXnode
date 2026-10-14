//go:build !linux

package authorization

import "os"

func privateOwner(os.FileInfo) bool { return false }
func openPrivateFile(string, int, os.FileMode) (*os.File, error) {
	return nil, refuse("VERIFIED_LINUX_REQUIRED")
}
func verifyDirectory(string) error       { return refuse("VERIFIED_LINUX_REQUIRED") }
func openStore(string) (*os.File, error) { return nil, refuse("VERIFIED_LINUX_REQUIRED") }
func syncDirectory(string) error         { return refuse("VERIFIED_LINUX_REQUIRED") }
