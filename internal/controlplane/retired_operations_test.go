package controlplane

import (
	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/txboard"
	"testing"
)

func TestRetiredNativeOperationsCannotEnterMailbox(t *testing.T) {
	for _, name := range []string{"ops.kernel.restart", "ops.config.reload", "ops.network.dns", "ops.logs.tail"} {
		event, err := TranslateTXBoardEvent(txboard.Event{Name: name, Data: []byte(`{"request_id":"retired","args":{}}`)}, config.KernelConfig{})
		if err == nil {
			t.Fatalf("retired operation accepted: %s", name)
		}
		if NewNodeMailbox().Apply(event) {
			t.Fatalf("unsupported event accepted: %s", name)
		}
	}
}
