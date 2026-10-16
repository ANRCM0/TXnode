package controlplane

import (
	"context"
	"strings"
	"testing"

	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/txboard"
)

func TestTXBoardPushOnlyRequestsSignedRefresh(t *testing.T) {
	for _, body := range []string{`{"users":[{"id":7,"uuid":"old-credential"}]}`, `{}`, `{"refresh_required":false}`, `{"refresh_required":true,"users":[]}`} {
		if _, err := TranslateTXBoardEvent(txboard.Event{Name: "sync.users", Data: []byte(body)}, config.KernelConfig{}); err == nil {
			t.Fatal("unsigned user push accepted", body)
		}
	}
	event, err := TranslateTXBoardEvent(txboard.Event{Name: "sync.users", Data: []byte(`{"refresh_required":true}`)}, config.KernelConfig{})
	if err != nil || event.Type != EventSyncUsers || event.Users != nil {
		t.Fatal("signed refresh hint rejected", err)
	}
	event, err = TranslateTXBoardEvent(txboard.Event{Name: "sync.users", NodeID: 42, Data: []byte(`{"refresh_required":true,"node_id":42}`)}, config.KernelConfig{})
	if err != nil || event.Type != EventSyncUsers || event.Users != nil {
		t.Fatal("Machine signed refresh hint rejected", err)
	}
	for _, name := range []string{"sync.user.delta", "sync.devices"} {
		if _, err := TranslateTXBoardEvent(txboard.Event{Name: name, Data: []byte(`{}`)}, config.KernelConfig{}); err == nil {
			t.Fatal("retired native event accepted", name)
		}
	}
}

func TestTXBoardUserRefreshRequiresAuthorityManager(t *testing.T) {
	plane := NewTXBoardControlPlane(config.PanelConfig{}, config.WSConfig{}, config.KernelConfig{})
	if _, err := plane.RefreshAuthorization(context.Background()); err == nil || !strings.Contains(err.Error(), "NODE_AUTHORIZATION_MANAGER_REQUIRED") {
		t.Fatal("authority-free refresh accepted", err)
	}
}
