//go:build linux

package authorization

import (
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"syscall"
)

func privateOwner(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uint32(os.Geteuid()) && info.Mode().Perm()&0077 == 0
}
func openPrivateFile(path string, flag int, perm os.FileMode) (*os.File, error) {
	fd, err := unix.Open(path, flag|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(perm))
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
func verifyDirectory(dir string) error {
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return refuse("STATE_DIRECTORY_INVALID")
	}
	for p := absolute; ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return refuse("STATE_DIRECTORY_INVALID")
		}
		parent := filepath.Dir(p)
		if parent == p {
			break
		}
	}
	info, err := os.Lstat(absolute)
	if err != nil || !privateOwner(info) {
		return refuse("STATE_DIRECTORY_OWNER_INVALID")
	}
	return nil
}
func openStore(dir string) (*os.File, error) {
	// Check existing ancestry before creating a private root through it.
	for p := dir; ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err == nil && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0) {
			return nil, refuse("STATE_DIRECTORY_INVALID")
		}
		if err != nil && !os.IsNotExist(err) {
			return nil, refuse("STATE_DIRECTORY_INVALID")
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, refuse("STATE_DIRECTORY_INVALID")
	}
	if err := verifyDirectory(dir); err != nil {
		return nil, err
	}
	f, err := openPrivateFile(filepath.Join(dir, ".authorization.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, refuse("STATE_LOCK_FAILED")
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || !privateOwner(info) {
		f.Close()
		return nil, refuse("STATE_LOCK_FAILED")
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, refuse("STATE_ALREADY_OWNED")
	}
	for p := dir; ; p = filepath.Dir(p) {
		if err := syncDirectory(p); err != nil {
			f.Close()
			return nil, refuse("STATE_PERSISTENCE_FAILED")
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	return f, nil
}
func syncDirectory(dir string) error {
	f, err := openPrivateFile(dir, os.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return err
	}
	err = f.Sync()
	if e := f.Close(); err == nil {
		err = e
	}
	return err
}
