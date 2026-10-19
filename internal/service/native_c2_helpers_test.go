package service

import (
	"encoding/json"
	"testing"
)

func mustNativeC2JSON(t *testing.T, value any) []byte {
	t.Helper()
	result, err := json.Marshal(value)
	if err != nil {
		t.Fatal("native C2 evidence serialization failed")
	}
	return result
}
