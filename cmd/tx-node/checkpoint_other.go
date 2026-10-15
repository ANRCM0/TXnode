//go:build !linux

package main

import (
	"errors"
	"os"
)

func checkpointSignal() os.Signal   { return nil }
func writeCheckpointReceipt() error { return errors.New("NODE_RUNTIME_CHECKPOINT_UNSUPPORTED") }
