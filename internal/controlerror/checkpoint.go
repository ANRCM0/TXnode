package controlerror

import "errors"

// RuntimeCheckpoint is an intentional, local durable shutdown, not Core authority.
var RuntimeCheckpoint = errors.New("NODE_RUNTIME_CHECKPOINT_REQUESTED")

func IsRuntimeCheckpoint(err error) bool { return errors.Is(err, RuntimeCheckpoint) }
