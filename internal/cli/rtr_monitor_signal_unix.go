//go:build unix

package cli

import (
	"os"
	"syscall"
)

// listSignals are the signals at which raven rtr monitor writes the full
// list of every compared cache's differences (--divergence-dir). SIGHUP is
// not one: it shuts the monitor down (server.ShutdownSignals).
var listSignals = []os.Signal{syscall.SIGUSR1}
