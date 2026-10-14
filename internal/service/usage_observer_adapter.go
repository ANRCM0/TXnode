package service

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/ANRCM0/TX-Node/internal/nlog"
	"github.com/ANRCM0/TX-Node/internal/usageobserver"
)

func (s *Service) usageObserverDirectory() string {
	root := s.cfg.UsageObserver.Directory
	if root == "" {
		root = s.cfg.Kernel.ConfigDir
	}
	if root == "" {
		return ""
	}
	// The hash names a local service stream. No credential or UUID is copied.
	key := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%d|%d|%s", s.cfg.Panel.Provider, s.cfg.Panel.URL, s.cfg.Panel.NodeID, s.cfg.Panel.MachineID, s.cfg.InstanceID)))
	return filepath.Join(root, ".txnode-observations-"+hex.EncodeToString(key[:12]))
}

func (s *Service) initUsageObserver() {
	if s == nil || s.cfg == nil || !s.cfg.UsageObserver.Enabled {
		return
	}
	s.observerMu.Lock()
	defer s.observerMu.Unlock()
	if s.observerState != "" {
		return
	}
	o, err := usageobserver.Open(s.usageObserverDirectory(), usageobserver.Options{MaxBytes: s.cfg.UsageObserver.MaxBytes})
	if err != nil {
		s.observerState = observerErrorCode(err)
		nlog.Core().Warn("local usage observation unavailable; v1 reporting continues", "reason", s.observerState)
		return
	}
	s.observer = o
	s.observerState = "recording"
}

func observerErrorCode(err error) string {
	switch {
	case errors.Is(err, usageobserver.ErrCapacity):
		return "capacity_reached"
	case errors.Is(err, usageobserver.ErrEvidence):
		return "evidence_invalid"
	case errors.Is(err, usageobserver.ErrClosed):
		return "closed"
	default:
		return "storage_unavailable"
	}
}

func (s *Service) observationWriter() *usageobserver.Observer {
	if s == nil {
		return nil
	}
	s.observerMu.Lock()
	defer s.observerMu.Unlock()
	if s.observerState != "recording" {
		return nil
	}
	return s.observer
}

func (s *Service) observationFailed(err error) {
	if err == nil {
		return
	}
	s.observerMu.Lock()
	defer s.observerMu.Unlock()
	if s.observerState != "recording" {
		return
	}
	s.observerState = observerErrorCode(err)
	nlog.Core().Warn("local usage observation stopped; v1 reporting continues", "reason", s.observerState)
}

func (s *Service) observeTraffic(traffic map[int][2]int64) {
	if o := s.observationWriter(); o != nil {
		s.observationFailed(o.Sample(traffic))
	}
}

func (s *Service) observeBoundary(event string, advance bool) {
	s.localEventBoundary(advance)
	if o := s.observationWriter(); o != nil {
		s.observationFailed(o.Boundary(event, advance))
	}
}

func (s *Service) closeUsageObserver() {
	if s == nil {
		return
	}
	s.observerMu.Lock()
	o := s.observer
	s.observerMu.Unlock()
	if o == nil {
		return
	}
	err := o.Close()
	s.observationFailed(err)
	s.observerMu.Lock()
	if s.observerState == "recording" {
		s.observerState = "closed"
	}
	s.observerMu.Unlock()
}

func (s *Service) usageObserverMetrics() map[string]interface{} {
	s.observerMu.Lock()
	defer s.observerMu.Unlock()
	state := s.observerState
	if state == "" {
		state = "not_started"
	}
	m := map[string]interface{}{"state": state, "attribution": "unattributable"}
	if s.observer != nil {
		status := s.observer.Status()
		m["records"] = status.Sequence
		m["observation_generation"] = status.Generation
		m["bytes"] = status.Bytes
	}
	return m
}

func (s *Service) reloadKernelObserved(config *model.NodeSpec, users []model.UserSpec) error {
	if !s.signedUsersAllowed(users) {
		return fmt.Errorf("NODE_AUTHORIZATION_EXPIRED")
	}
	s.observeBoundary("KERNEL_RELOAD_BEGIN", true)
	err := s.kernelLife.Reload(config, users, s.certs.TLSCert())
	if err == nil && !s.signedUsersAllowed(users) {
		s.stopKernelObserved(false)
		err = fmt.Errorf("NODE_AUTHORIZATION_EXPIRED")
	}
	event := "KERNEL_RELOAD_OK"
	if err != nil {
		event = "KERNEL_RELOAD_FAILED"
	}
	s.observeBoundary(event, false)
	return err
}

func (s *Service) stopKernelObserved(noUsers bool) {
	s.observeBoundary("KERNEL_STOP_BEGIN", true)
	if noUsers {
		s.kernelLife.StopForNoUsers()
	} else {
		s.kernelLife.Stop()
	}
	s.observeBoundary("KERNEL_STOP_END", false)
}
