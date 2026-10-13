//go:build !linux

package usageinterval

import "os"

func lockJournal(string) (*os.File, error) { return nil, ErrUnknown }
func unlockJournal(*os.File) error         { return ErrUnknown }
