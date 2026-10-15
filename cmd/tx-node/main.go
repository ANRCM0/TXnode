package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ANRCM0/TX-Node/internal/buildinfo"
	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/controlerror"
	"github.com/ANRCM0/TX-Node/internal/machine"
	"github.com/ANRCM0/TX-Node/internal/nlog"
	"github.com/ANRCM0/TX-Node/internal/service"
)

const (
	canonicalContainerConfigPath = "/etc/txnode/config.yml"
	legacyContainerConfigPath    = "/etc/xboard-node/config.yml"
)

func main() {
	requestedConfigPath := flag.String("c", "config.yml", "config file path")
	showVersion := flag.Bool("v", false, "show version")
	showCapabilities := flag.Bool("capabilities", false, "print runtime capabilities without starting services")
	showBackupLayout := flag.Bool("backup-layout", false, "print supported private-free backup layout without starting services")
	flag.Parse()
	if *showCapabilities {
		if err := writeRuntimeCapabilities(os.Stdout); err != nil {
			os.Exit(1)
		}
		return
	}

	if *showVersion {
		fmt.Printf("tx-node %s (built %s)\n", buildinfo.Version, buildinfo.BuildTime)
		os.Exit(0)
	}

	configPath := resolveConfigPath(*requestedConfigPath)
	rootCfg, err := config.LoadRoot(configPath)
	if err != nil {
		if *showBackupLayout {
			fmt.Fprintln(os.Stderr, "NODE_BACKUP_LAYOUT_INVALID_CONFIG")
		} else {
			fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		}
		os.Exit(1)
	}

	instances, err := rootCfg.NormalizeInstances()
	if err != nil {
		if *showBackupLayout {
			fmt.Fprintln(os.Stderr, "NODE_BACKUP_LAYOUT_INVALID_CONFIG")
		} else {
			fmt.Fprintf(os.Stderr, "failed to normalize config: %v\n", err)
		}
		os.Exit(1)
	}
	if *showBackupLayout {
		if err := writeBackupLayout(os.Stdout, rootCfg); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	config.InitLogger(instances[0].Log)

	// Apply runtime memory tuning before anything else allocates.
	applyRuntimeConfig(instances[0].Runtime)

	runWithReload(rootCfg, configPath)
}

// resolveConfigPath keeps the canonical container path authoritative while
// allowing already-generated Compose files to survive a new-image pull.
// The fallback is deliberately narrow: it is considered only when the caller
// requested the canonical container path and that file is absent.
func resolveConfigPath(requested string) string {
	resolved := resolveConfigPathWithFallback(requested, canonicalContainerConfigPath, legacyContainerConfigPath)
	if resolved != requested {
		fmt.Fprintf(os.Stderr, "warning: %s missing; using legacy container config path %s\n", requested, resolved)
	}
	return resolved
}

func resolveConfigPathWithFallback(requested, canonical, legacy string) string {
	if requested != canonical {
		return requested
	}
	if _, err := os.Stat(canonical); err == nil || !os.IsNotExist(err) {
		return canonical
	}
	if _, err := os.Stat(legacy); err == nil {
		return legacy
	}
	return canonical
}

// runWithReload restarts all node services when the config file changes.
func runWithReload(initialRoot *config.RootConfig, configPath string) {
	var healthSrv *http.Server
	var healthPort int
	startHealth := func(port int) {
		if port <= 0 {
			return
		}
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			nlog.Core().Error("failed to start health check listener", "port", port, "error", err)
			os.Exit(1)
		}
		mux := http.NewServeMux()
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			// A machine whose every node failed to start (e.g. port already in
			// use) used to answer 200 here, hiding a completely dead deployment
			// from any supervisor. Report 503 while nodes sit in backoff.
			// Aggregate also reports whether any machine instance exists at all:
			// a plain node-mode deployment has no orchestrator and must not be
			// treated as degraded just because nothing reported in.
			if agg, reported := machine.GlobalHealth().Aggregate(); reported && agg.Failed > 0 {
				w.WriteHeader(http.StatusServiceUnavailable)
				fmt.Fprintf(w, `{"status":"degraded","nodes":%d,"failed":%d}`, agg.Total, agg.Failed)
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok"}`))
		})
		healthSrv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		healthPort = port
		go func() {
			nlog.Core().Debug(fmt.Sprintf("health check listening on :%d", port))
			if err := healthSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
				nlog.Core().Warn("health check server stopped", "error", err)
			}
		}()
	}

	initialInstances, err := initialRoot.NormalizeInstances()
	if err != nil {
		nlog.Core().Error("failed to normalize initial config", "error", err)
		os.Exit(1)
	}
	startHealth(initialInstances[0].HealthPort)
	defer func() {
		if healthSrv != nil {
			healthSrv.Close()
		}
	}()

	for root := initialRoot; ; {
		ctx, cancelCause := context.WithCancelCause(context.Background())
		cancel := func() { cancelCause(nil) }

		_, checkpointLayoutError := makeBackupLayout(root)
		errChSignal := make(chan error, 1)
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		if sig := checkpointSignal(); sig != nil {
			signal.Notify(sigCh, sig)
		}

		reloadCh := make(chan *config.RootConfig, 1)

		watcher, err := config.WatchConfigRoot(ctx, configPath, func(newCfg *config.RootConfig) {
			select {
			case reloadCh <- newCfg:
			default:
			}
		})
		if err != nil {
			nlog.Core().Warn("config watcher unavailable, hot-reload disabled", "error", err)
		}

		go func() {
			select {
			case sig := <-sigCh:
				nlog.Core().Info(fmt.Sprintf("received %v, shutting down...", sig))
				if sig == checkpointSignal() {
					if checkpointLayoutError != nil {
						cancelOnServiceError(errChSignal, cancel, checkpointLayoutError)
					} else {
						cancelCause(controlerror.RuntimeCheckpoint)
					}
				} else {
					cancel()
				}

				select {
				case sig = <-sigCh:
					nlog.Core().Warn("received second signal, forcing exit", "signal", sig)
					os.Exit(1)
				case <-time.After(15 * time.Second):
					nlog.Core().Error("shutdown timed out after 15s, forcing exit")
					os.Exit(2)
				}
			case <-ctx.Done():
			}
		}()

		instances, err := root.NormalizeInstances()
		if err != nil {
			nlog.Core().Error("failed to normalize config", "error", err)
			os.Exit(1)
		}
		if err := config.ValidateStartupLayout(instances); err != nil {
			nlog.Core().Error("startup layout validation failed", "error", err)
			os.Exit(1)
		}

		if instances[0].HealthPort != healthPort {
			if healthSrv != nil {
				healthSrv.Close()
				healthSrv = nil
			}
			startHealth(instances[0].HealthPort)
		}

		errCh := errChSignal
		doneCh := make(chan struct{})
		var wg sync.WaitGroup
		for _, instanceCfg := range instances {
			instanceCfg := instanceCfg
			wg.Add(1)
			go func() {
				defer wg.Done()
				if instanceCfg.IsMachineMode() {
					nlog.Core().Info("starting machine instance", "instance", instanceCfg.InstanceID, "machine_id", instanceCfg.Machine.MachineID, "panel_url", instanceCfg.Panel.URL)
					orch, createErr := machine.NewChecked(instanceCfg)
					if createErr != nil {
						cancelOnServiceError(errCh, cancel, createErr)
						return
					}
					if err := orch.Run(ctx); err != nil {
						nlog.Core().Error("machine instance exited with error", "instance", instanceCfg.InstanceID, "error", err)
						cancelOnServiceError(errCh, cancel, err)
					}
					return
				}
				nodes := instanceCfg.ExpandNodes()
				nlog.Core().Info("starting node instance", "instance", instanceCfg.InstanceID, "nodes", len(nodes), "panel_url", instanceCfg.Panel.URL)
				var instanceWG sync.WaitGroup
				for idx, nodeCfg := range nodes {
					nodeCfg := nodeCfg
					instanceWG.Add(1)
					go func(idx int) {
						defer instanceWG.Done()
						if idx > 0 {
							delay := time.Duration(idx) * 250 * time.Millisecond
							if delay > 2*time.Second {
								delay = 2 * time.Second
							}
							select {
							case <-time.After(delay):
							case <-ctx.Done():
								return
							}
						}
						svc, createErr := service.NewChecked(nodeCfg)
						if createErr != nil {
							cancelOnServiceError(errCh, cancel, createErr)
							return
						}
						if err := svc.Run(ctx); err != nil {
							nlog.Core().Error("node service exited with error", "instance", nodeCfg.InstanceID, "node_id", nodeCfg.Panel.NodeID, "error", err)
							cancelOnServiceError(errCh, cancel, err)
						}
					}(idx)
				}
				instanceWG.Wait()
			}()
		}
		go func() { wg.Wait(); close(doneCh) }()

		var newRoot *config.RootConfig
		select {
		case newRoot = <-reloadCh:
			if controlerror.IsRuntimeCheckpoint(context.Cause(ctx)) {
				newRoot = nil
			}
			nlog.Core().Info("config changed, restarting all services...")
			cancel()
			<-doneCh
		case <-doneCh:
		}

		signal.Stop(sigCh)
		if watcher != nil {
			watcher.Stop()
		}

		if newRoot == nil {
			select {
			case err := <-errCh:
				if err != nil {
					os.Exit(1)
				}
			default:
			}
			if controlerror.IsRuntimeCheckpoint(context.Cause(ctx)) {
				if healthSrv != nil {
					healthSrv.Close()
				}
				if err := writeCheckpointReceipt(); err != nil {
					nlog.Core().Error("runtime checkpoint receipt failed", "error", err)
					os.Exit(1)
				}
			}
			nlog.Core().Info("stopped")
			return
		}

		newInstances, err := newRoot.NormalizeInstances()
		if err != nil {
			nlog.Core().Error("failed to normalize reloaded config", "error", err)
			os.Exit(1)
		}
		config.InitLogger(newInstances[0].Log)
		applyRuntimeConfig(newInstances[0].Runtime)
		root = newRoot
		nlog.Core().Info("reload complete, services restarting with new config")
	}
}

// cancelOnServiceError records only the first fatal error. Several nodes can
// fail simultaneously in one instance; none may block while the parent waits
// for all workers to stop. The caller logs each individual failure.
func cancelOnServiceError(errors chan<- error, cancel context.CancelFunc, err error) {
	if err == nil {
		return
	}
	select {
	case errors <- err:
	default:
	}
	cancel()
}

// applyRuntimeConfig wires up Go runtime memory limits from the config file.
// Both settings can also be overridden by environment variables (GOMEMLIMIT /
// GOGC) — the env vars take precedence because Go's runtime reads them before
// we can call these functions, but we set them here for completeness and so
// the values are logged.
func applyRuntimeConfig(rt config.RuntimeConfig) {
	// GOGC
	if rt.GoGCPercent > 0 {
		prev := debug.SetGCPercent(rt.GoGCPercent)
		nlog.Core().Info("runtime: GOGC set", "gogc", rt.GoGCPercent, "prev", prev)
	}

	// GOMEMLIMIT — parse human-readable size string (e.g. "30MiB")
	if rt.GoMemLimit != "" {
		limit, err := parseMemLimit(rt.GoMemLimit)
		if err != nil {
			nlog.Core().Warn("runtime: invalid gomemlimit, ignoring", "value", rt.GoMemLimit, "error", err)
		} else {
			prev := debug.SetMemoryLimit(limit)
			nlog.Core().Info("runtime: GOMEMLIMIT set",
				"limit", rt.GoMemLimit,
				"bytes", limit,
				"prev_bytes", prev,
			)
		}
	}
}

// parseMemLimit converts a human-readable size string to bytes.
// Supported suffixes: B, KiB, MiB, GiB, TiB (case-insensitive).
func parseMemLimit(s string) (int64, error) {
	s = strings.TrimSpace(s)
	suffixes := []struct {
		suffix string
		mult   int64
	}{
		{"TiB", 1 << 40},
		{"GiB", 1 << 30},
		{"MiB", 1 << 20},
		{"KiB", 1 << 10},
		{"B", 1},
	}
	upper := strings.ToUpper(s)
	for _, sf := range suffixes {
		if strings.HasSuffix(upper, strings.ToUpper(sf.suffix)) {
			numStr := strings.TrimSuffix(upper, strings.ToUpper(sf.suffix))
			numStr = strings.TrimSpace(numStr)
			var n int64
			if _, err := fmt.Sscanf(numStr, "%d", &n); err != nil {
				return 0, fmt.Errorf("parse number %q: %w", numStr, err)
			}
			return n * sf.mult, nil
		}
	}
	// No suffix: treat as raw bytes.
	var n int64
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return 0, fmt.Errorf("unrecognised size format %q", s)
	}
	return n, nil
}
