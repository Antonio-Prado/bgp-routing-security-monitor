//go:build !unix

package cli

import "os"

// listSignals is empty where there is no SIGUSR1.
var listSignals []os.Signal
