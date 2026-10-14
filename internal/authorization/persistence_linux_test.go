//go:build linux

package authorization

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/config"
)

func managerFixture(t *testing.T) (*Manager, Payload, Trust, func(Payload) Envelope, time.Time) {
	t.Helper()
	p, trust, key, now := signedFixture(t)
	cfg := config.AuthorizationConfig{Enabled: true, StateDir: filepath.Join(t.TempDir(), "private-state"), PublicKey: trust.PublicKey, KeyID: trust.KeyID, KeyEpoch: trust.KeyEpoch, CoreInstanceID: trust.CoreInstanceID, PolicyVersion: p.PolicyVersion, MaxClockSkew: 5, RefreshInterval: 30}
	m, err := NewManager(cfg, Target{NodeID: p.NodeID})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })
	if err := m.SetTrust(trust); err != nil {
		t.Fatal(err)
	}
	return m, p, trust, func(p Payload) Envelope { return signPayload(t, p, key) }, now
}
func TestManagerHighWaterReplayDeadlineAndRestart(t *testing.T) {
	m, p, trust, sign, now := managerFixture(t)
	env := sign(p)
	if _, err := m.Accept(env, p.Users, now); err != nil {
		t.Fatal(err)
	}
	expiry := m.Expiry()
	if remaining := expiry.Sub(now); remaining != 119500*time.Millisecond {
		t.Fatal("deadline did not retain exact fractional wall boundary", remaining)
	}
	snap, err := m.Verify(env, p.Users, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.AcceptVerified(snap, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if !m.Expiry().Equal(expiry) {
		t.Fatal("replay extended lease")
	}
	old := p
	old.Revision = "4"
	if _, err := m.Verify(sign(old), old.Users, now); !IsRefusal(err) {
		t.Fatal("lower revision accepted")
	}
	conflict := p
	conflict.Users = nil
	conflict.Users = cloneUsers(p.Users)
	conflict.Users[0].UUID = "replacement"
	if _, err := m.Verify(sign(conflict), conflict.Users, now); !IsRefusal(err) {
		t.Fatal("same revision mutated")
	}
	cfg := m.Config()
	if _, err := NewManager(cfg, Target{NodeID: p.NodeID}); !IsRefusal(err) {
		t.Fatal("second process owner accepted")
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	fresh, err := NewManager(cfg, Target{NodeID: p.NodeID})
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if err := fresh.SetTrust(trust); err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.Accept(env, p.Users, now); !IsRefusal(err) {
		t.Fatal("old snapshot resumed after process restart")
	}
	p.Revision = "6"
	if _, err := fresh.Accept(sign(p), p.Users, now); err != nil {
		t.Fatal("fresh authority could not recover", err)
	}
}
func TestManagerClockRollbackExpiryAndDTOForgeryFailClosed(t *testing.T) {
	for _, reason := range []string{"wall_rollback", "expiry", "forged_dto", "mutated_dto"} {
		t.Run(reason, func(t *testing.T) {
			m, p, _, sign, now := managerFixture(t)
			snap, err := m.Accept(sign(p), p.Users, now)
			if err != nil {
				t.Fatal(err)
			}
			switch reason {
			case "wall_rollback":
				err = m.Check(now.Add(-time.Nanosecond))
			case "expiry":
				err = m.Check(m.Expiry())
			case "forged_dto":
				fake := *snap
				fake.envelope = Envelope{}
				_, err = m.AcceptVerified(&fake, now)
			case "mutated_dto":
				fake := *snap
				fake.Users = cloneUsers(snap.Users)
				fake.Users[0].UUID = "forged"
				_, err = m.AcceptVerified(&fake, now)
			}
			if !IsRefusal(err) {
				t.Fatal("unsafe authority accepted", err)
			}
		})
	}
}
func TestManagerPrivateStateCorruptionSymlinkAndClosedOwner(t *testing.T) {
	for _, reason := range []string{"corruption", "directory_symlink", "state_symlink", "world_readable", "closed_owner"} {
		t.Run(reason, func(t *testing.T) {
			m, p, _, sign, now := managerFixture(t)
			if _, err := m.Accept(sign(p), p.Users, now); err != nil {
				t.Fatal(err)
			}
			cfg := m.Config()
			if err := m.Close(); err != nil {
				t.Fatal(err)
			}
			if reason == "closed_owner" {
				p.Revision = "6"
				if _, err := m.Accept(sign(p), p.Users, now); !IsRefusal(err) {
					t.Fatal("closed owner reused")
				}
				return
			}
			switch reason {
			case "corruption":
				if err := os.WriteFile(statePath(cfg.StateDir), []byte(`{"state":{}}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "state_symlink":
				if err := os.Remove(statePath(cfg.StateDir)); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(cfg.StateDir, "other"), statePath(cfg.StateDir)); err != nil {
					t.Fatal(err)
				}
			case "directory_symlink":
				link := filepath.Join(t.TempDir(), "linked")
				if err := os.Symlink(cfg.StateDir, link); err != nil {
					t.Fatal(err)
				}
				cfg.StateDir = link
			case "world_readable":
				if err := os.Chmod(statePath(cfg.StateDir), 0644); err != nil {
					t.Fatal(err)
				}
			}
			if next, err := NewManager(cfg, Target{NodeID: p.NodeID}); !IsRefusal(err) {
				if next != nil {
					next.Close()
				}
				t.Fatal("unsafe persistence accepted", err)
			}
		})
	}
}
func TestManagerConcurrentVerifyNeverAppliesBeforeAcceptance(t *testing.T) {
	m, p, _, sign, now := managerFixture(t)
	env := sign(p)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := m.Verify(env, p.Users, now); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if m.Current() != nil || !m.Expiry().IsZero() {
		t.Fatal("background verification renewed authority before apply")
	}
}

func TestVerifyCapturedBeforeAdmissionClockCheckDoesNotFabricateRollback(t *testing.T) {
	m, p, _, sign, now := managerFixture(t)
	if _, err := m.Accept(sign(p), p.Users, now); err != nil {
		t.Fatal(err)
	}
	captured := now.Add(time.Second)
	if err := m.Check(now.Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// Simulate the worker having sampled wall time before a main-loop admission
	// check while signature verification or waiting for the manager mutex.
	p.Revision = "6"
	snap, err := m.Verify(sign(p), p.Users, captured)
	if err != nil {
		t.Fatal("healthy concurrent verification inferred rollback", err)
	}
	if _, err := m.AcceptVerified(snap, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := m.Check(now.Add(2 * time.Second)); !IsRefusal(err) {
		t.Fatal("actual serial wall rollback accepted")
	}
}
