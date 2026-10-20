package ctransport

import (
	"fmt"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// helloID maps the client-fingerprint option to a uTLS ClientHelloID.
// Evidence: helloID @0xb63c40 and chromeID @0xb4f0e0
// (notes/rev-round2-transport.md §B1-B4, REPORT.md §7.4/§17.6): names are
// lower-cased and trimmed, "chrome" resolves to {Chrome, 133}
// (0x1796aa0) and is turned into a spec with utlsIdToSpec(Chrome/133) before
// utls.ShuffleChromeTLSExtensions runs per connection; the other names map to
// the utls built-in IDs (name table 0x1796360-0x1796d20).
//
// The validation wording is the sample's:
// "client-fingerprint %q is not known: use chrome, firefox, safari, ios,
// android, edge, 360, qq, random, randomized or none (chrome is Chrome 133;
// the ones before it are chrome-133, chrome-131 and chrome-120)".
//
// UNVERIFIED: the sample's chrome constant prints "155" while the spec it
// builds is Chrome/133 (notes/rev-round2-transport.md §B4 calls 155 a "虚名").
// We follow the spec: Chrome/133.
func helloID(name string) (utls.ClientHelloID, bool, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	switch name {
	case "":
		return utls.ClientHelloID{}, false, nil
	case "none":
		return utls.ClientHelloID{Client: "none"}, false, nil
	case "chrome", "chrome_133", "chrome-133":
		return utls.HelloChrome_133, true, nil
	case "chrome_120", "chrome-120":
		return utls.HelloChrome_120, false, nil
	case "chrome_131", "chrome-131":
		return utls.HelloChrome_131, false, nil
	case "firefox":
		return utls.HelloFirefox_120, false, nil
	case "safari":
		return utls.HelloSafari_16_0, false, nil
	case "ios":
		return utls.HelloIOS_14, false, nil
	case "android":
		return utls.HelloAndroid_11_OkHttp, false, nil
	case "edge":
		return utls.HelloEdge_85, false, nil
	case "360":
		return utls.Hello360_7_5, false, nil
	case "qq":
		return utls.HelloQQ_11_1, false, nil
	case "random":
		return utls.HelloRandomized, false, nil
	case "randomized":
		return utls.HelloRandomizedALPN, false, nil
	}
	// chrome_120 .. chrome_133 numeric aliases outside the three real ids fall
	// back to the nearest utls spec (REPORT.md §17.6: version names are
	// mapping keys).
	if v, ok := chromeVersion(name); ok {
		switch {
		case v <= 120:
			return utls.HelloChrome_120, false, nil
		case v <= 131:
			return utls.HelloChrome_131, false, nil
		default:
			return utls.HelloChrome_133, true, nil
		}
	}
	return utls.ClientHelloID{}, false, fmt.Errorf(
		"client-fingerprint %q is not known: use chrome, firefox, safari, ios, android, edge, 360, qq, random, randomized or none (chrome is Chrome 133; the ones before it are chrome-133, chrome-131 and chrome-120)", name)
}

func chromeVersion(name string) (int, bool) {
	for _, prefix := range []string{"chrome_", "chrome-"} {
		if strings.HasPrefix(name, prefix) {
			v := 0
			digits := name[len(prefix):]
			if digits == "" {
				return 0, false
			}
			for _, c := range digits {
				if c < '0' || c > '9' {
					return 0, false
				}
				v = v*10 + int(c-'0')
			}
			return v, true
		}
	}
	return 0, false
}
