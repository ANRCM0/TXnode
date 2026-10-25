package controlplane

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestConnectionCommandBoundsAndScope(t *testing.T) {
	now := time.Unix(2000, 0)
	valid := ConnectionCommand{NodeID: 7, RequestID: "nco_" + strings.Repeat("a", 32), Action: "list", Deadline: 2015, Limit: 50}
	for _, change := range []func(*ConnectionCommand){
		func(c *ConnectionCommand) { c.NodeID = 8 },
		func(c *ConnectionCommand) { c.RequestID = "unbounded" },
		func(c *ConnectionCommand) { c.Deadline = 2000 },
		func(c *ConnectionCommand) { c.Deadline = 2031 },
		func(c *ConnectionCommand) { c.Limit = 101 },
		func(c *ConnectionCommand) { c.After = "raw-counter-1" },
		func(c *ConnectionCommand) { c.Action = "restart" },
		func(c *ConnectionCommand) { c.ConnectionID = strings.Repeat("a", 32) + ":1" },
	} {
		c := valid
		change(&c)
		data, _ := json.Marshal(c)
		if _, err := ParseConnectionCommand(data, 7, now); err == nil {
			t.Fatalf("accepted invalid command %+v", c)
		}
	}
	data, _ := json.Marshal(valid)
	if _, err := ParseConnectionCommand(data, 7, now); err != nil {
		t.Fatal(err)
	}
	data = append(data[:len(data)-1], []byte(`,"limit":1}`)...)
	if _, err := ParseConnectionCommand(data, 7, now); err == nil {
		t.Fatal("accepted duplicate command field")
	}
	valid.Action, valid.Limit, valid.ConnectionID = "close", 0, strings.Repeat("b", 32)+":18446744073709551615"
	data, _ = json.Marshal(valid)
	if _, err := ParseConnectionCommand(data, 7, now); err != nil {
		t.Fatal(err)
	}
}

func TestConnectionMailboxDoesNotCoalesceCommandsOrBufferBeforeReady(t *testing.T) {
	m := NewNodeMailbox()
	c := ConnectionCommand{NodeID: 7, Action: "close"}
	if m.Apply(Event{Type: EventConnections, Connections: &c}) {
		t.Fatal("buffered a command before child readiness")
	}
	m.MarkReady()
	for i := 0; i < 8; i++ {
		c.RequestID = string(rune('a' + i))
		if !m.Apply(Event{Type: EventConnections, Connections: &c}) {
			t.Fatal("bounded command rejected")
		}
	}
	if m.Apply(Event{Type: EventConnections, Connections: &c}) {
		t.Fatal("overflow accepted")
	}
	state := m.DrainIfReady()
	if len(state.Connections) != 8 || state.Connections[0].RequestID != "a" || state.Connections[7].RequestID != "h" || len(m.DrainIfReady().Connections) != 0 {
		t.Fatal("commands lost order, shared their input, or were replayed")
	}
}
