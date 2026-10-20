package txnode

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

type interopTest interface {
	Helper()
	Name() string
	Fatalf(string, ...any)
	Skipf(string, ...any)
}

type interopGap struct {
	id         string
	reason     string
	diagnostic bool
}

var interopKnownGaps = map[string]interopGap{
	"TestInteropXrayVLESSH2Removed": {id: "H2-REMOVED", reason: "standalone HTTP/2 transport removed by pinned Xray; covered by XHTTP"},
	"TestInteropSingBoxMuxUDP":      {id: "MUX-UDP", reason: "address-header mux UDP is not accepted; Mux.Cool/XUDP is separate"},
	"TestInteropSingBoxMieru":       {id: "SINGBOX-MIERU", reason: "pinned sing-box has no mieru outbound; official mieru covers TCP", diagnostic: true},
	"TestInteropMihomoTUIC":         {id: "TUIC-MIHOMO", reason: "pinned Mihomo TUIC compatibility remains unaccepted", diagnostic: true},
	"TestInteropSingBoxNaive":       {id: "NAIVE-CERT", reason: "pinned sing-box Naive certificate fixture remains unaccepted", diagnostic: true},
}

func interopMode(t interopTest, name string) bool {
	t.Helper()
	switch value := os.Getenv(name); value {
	case "", "0":
		return false
	case "1":
		return true
	default:
		t.Fatalf("%s must be 0 or 1, got %q", name, value)
		return false
	}
}

func interopMissingClient(t interopTest, name string) {
	t.Helper()
	if interopMode(t, "TXNODE_INTEROP_STRICT") {
		t.Fatalf("required interop client %s is not configured", name)
		return
	}
	t.Skipf("INTEROP_DISCOVERY_SKIP:%s client is not configured", name)
}

func interopBinary(t interopTest, name string) string {
	t.Helper()
	path := os.Getenv(name)
	if path == "" {
		interopMissingClient(t, name)
		return ""
	}
	return interopExecutable(t, name, path)
}

func interopExecutable(t interopTest, name, path string) string {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("required interop client %s at %q: %v", name, path, err)
		return ""
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("required interop client %s at %q is not an executable regular file", name, path)
		return ""
	}
	return path
}

func interopCurlBinary(t interopTest) string {
	t.Helper()
	if path := os.Getenv("TXNODE_INTEROP_CURL"); path != "" {
		return interopExecutable(t, "TXNODE_INTEROP_CURL", path)
	}
	path, err := exec.LookPath("curl")
	if err != nil {
		interopMissingClient(t, "TXNODE_INTEROP_CURL")
		return ""
	}
	return interopExecutable(t, "curl", path)
}

// A quarantined case has not executed its transport probe. Diagnostic mode runs
// the existing probes, whose failures are fatal rather than converted to skips.
func skipInteropKnownGap(t interopTest, id string) bool {
	t.Helper()
	gap, ok := interopKnownGaps[t.Name()]
	if !ok || gap.id != id {
		t.Fatalf("unregistered interop gap %q for %s", id, t.Name())
		return true
	}
	if gap.diagnostic && interopMode(t, "TXNODE_INTEROP_DIAGNOSTIC_GAPS") {
		return false
	}
	t.Skipf("INTEROP_KNOWN_GAP:%s %s", gap.id, gap.reason)
	return true
}

type interopPolicyAbort struct{}

type interopPolicyRecorder struct {
	name    string
	failure string
	skip    string
}

func (*interopPolicyRecorder) Helper()        {}
func (r *interopPolicyRecorder) Name() string { return r.name }
func (r *interopPolicyRecorder) Fatalf(format string, args ...any) {
	r.failure = fmt.Sprintf(format, args...)
	panic(interopPolicyAbort{})
}
func (r *interopPolicyRecorder) Skipf(format string, args ...any) {
	r.skip = fmt.Sprintf(format, args...)
	panic(interopPolicyAbort{})
}

func recordInteropPolicy(name string, fn func(interopTest)) (r *interopPolicyRecorder) {
	r = &interopPolicyRecorder{name: name}
	defer func() {
		if recovered := recover(); recovered != nil {
			if _, ok := recovered.(interopPolicyAbort); !ok {
				panic(recovered)
			}
		}
	}()
	fn(r)
	return r
}

func TestStrictInteropBinaryPreflight(t *testing.T) {
	const variable = "TXNODE_INTEROP_POLICY_TEST_BINARY"
	executable := filepath.Join(t.TempDir(), "client")
	if err := os.WriteFile(executable, []byte("fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	nonExecutable := filepath.Join(t.TempDir(), "not-executable")
	if err := os.WriteFile(nonExecutable, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, strict, path string
		fail, skip         bool
	}{
		{name: "discovery-unconfigured", skip: true},
		{name: "strict-unconfigured", strict: "1", fail: true},
		{name: "discovery-configured-missing", path: filepath.Join(t.TempDir(), "absent"), fail: true},
		{name: "strict-configured-missing", strict: "1", path: filepath.Join(t.TempDir(), "absent"), fail: true},
		{name: "directory", path: t.TempDir(), fail: true},
		{name: "not-executable", path: nonExecutable, fail: true},
		{name: "strict-executable", strict: "1", path: executable},
		{name: "invalid-strict-mode", strict: "true", fail: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("TXNODE_INTEROP_STRICT", test.strict)
			t.Setenv(variable, test.path)
			var got string
			r := recordInteropPolicy(t.Name(), func(test interopTest) { got = interopBinary(test, variable) })
			if (r.failure != "") != test.fail || (r.skip != "") != test.skip {
				t.Fatalf("failure=%q skip=%q, want fail=%v skip=%v", r.failure, r.skip, test.fail, test.skip)
			}
			if !test.fail && !test.skip && got != test.path {
				t.Fatalf("binary=%q, want %q", got, test.path)
			}
		})
	}
}

func TestKnownInteropGapPolicy(t *testing.T) {
	for _, test := range []struct {
		name, id, diagnostic string
		fail, skip           bool
	}{
		{name: "TestInteropMihomoTUIC", id: "TUIC-MIHOMO", skip: true},
		{name: "TestInteropMihomoTUIC", id: "TUIC-MIHOMO", diagnostic: "1"},
		{name: "TestInteropXrayVLESSH2Removed", id: "H2-REMOVED", diagnostic: "1", skip: true},
		{name: "TestInteropSingBoxTUIC", id: "TUIC-MIHOMO", fail: true},
		{name: "TestInteropMihomoTUIC", id: "NAIVE-CERT", fail: true},
		{name: "TestInteropMihomoTUIC", id: "TUIC-MIHOMO", diagnostic: "true", fail: true},
	} {
		t.Run(test.name+"/"+test.id+"/"+test.diagnostic, func(t *testing.T) {
			t.Setenv("TXNODE_INTEROP_DIAGNOSTIC_GAPS", test.diagnostic)
			r := recordInteropPolicy(test.name, func(caseTest interopTest) { skipInteropKnownGap(caseTest, test.id) })
			if (r.failure != "") != test.fail || (r.skip != "") != test.skip {
				t.Fatalf("failure=%q skip=%q, want fail=%v skip=%v", r.failure, r.skip, test.fail, test.skip)
			}
			if test.skip {
				gap := interopKnownGaps[test.name]
				want := "INTEROP_KNOWN_GAP:" + gap.id + " " + gap.reason
				if r.skip != want {
					t.Fatalf("skip=%q, want %q", r.skip, want)
				}
			}
		})
	}
}
