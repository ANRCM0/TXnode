//go:build linux

package main

import "testing"

func TestProcessStartTicksParsesParenthesizedCommAndRejectsMalformedStat(t *testing.T) {
	fields := "R 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 987654 20"
	got, err := processStartTicks("1 (a complicated ) command) " + fields)
	if err != nil || got != "987654" {
		t.Fatal("process identity parser mismatch", got, err)
	}
	for _, body := range []string{"", "1 malformed", "1 (cmd) R 1", "1 (cmd) R 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 invalid"} {
		if _, err := processStartTicks(body); err == nil {
			t.Fatal("malformed process identity admitted")
		}
	}
}
