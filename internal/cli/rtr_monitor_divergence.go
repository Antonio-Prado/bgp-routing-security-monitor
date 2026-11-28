package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/telemetry"
)

// divergenceQueue is how many lists of differences may wait to be written.
// A list is made with the comparison locked and written by one goroutine,
// so a slow disk delays the files and never the RTR sessions.
const divergenceQueue = 64

// divergenceFiles writes the lists of differences that the comparison of
// several caches makes (--divergence-dir): one file a list, in dir.
type divergenceFiles struct {
	dir string
	log *slog.Logger

	mu     sync.Mutex
	closed bool
	queue  chan divergenceJob
	done   chan struct{}
}

type divergenceJob struct {
	name string
	list *telemetry.DivergenceList
}

// newDivergenceFiles creates dir if it is missing and starts the writer.
func newDivergenceFiles(dir string, log *slog.Logger) (*divergenceFiles, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("--divergence-dir: %w", err)
	}
	d := &divergenceFiles{dir: dir, log: log, queue: make(chan divergenceJob, divergenceQueue), done: make(chan struct{})}
	go func() {
		defer close(d.done)
		for job := range d.queue {
			d.write(job)
		}
	}()
	return d, nil
}

// divergenceFileName names the file of a list: the cache, the time the list
// was made at (UTC, to the second) and why. Characters of the cache that do
// not belong in a file name (the colon before the port, the brackets of an
// IPv6 address) become "_". Two lists of one cache for one reason in one
// second have one name, and the later replaces the earlier.
func divergenceFileName(l *telemetry.DivergenceList) string {
	cache := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-':
			return r
		}
		return '_'
	}, l.Cache)
	return fmt.Sprintf("%s-%s-%s.json", cache, l.Generated.UTC().Format("20060102T150405Z"), l.Reason)
}

// accept takes a list to write and returns the name its file will have, or
// "" when it is not going to be written: telemetry.CrossCache.OnList's
// function, which must not block.
func (d *divergenceFiles) accept(l *telemetry.DivergenceList) string {
	name := divergenceFileName(l)
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return ""
	}
	select {
	case d.queue <- divergenceJob{name: name, list: l}:
		return name
	default:
		d.log.Warn("too many lists of differences wait to be written, this one is dropped",
			"cache", l.Cache, "reason", l.Reason, "items", l.Len(), "dir", d.dir)
		return ""
	}
}

// write writes one list: to a temporary file first, renamed when it is
// whole, so that a reader never finds half a file. A failure is logged and
// nothing else: a full disk must not take the monitor down.
func (d *divergenceFiles) write(job divergenceJob) {
	path := filepath.Join(d.dir, job.name)
	err := func() error {
		f, err := os.CreateTemp(d.dir, "."+job.name+".*")
		if err != nil {
			return err
		}
		defer os.Remove(f.Name()) // gone already when the rename worked
		if err := job.list.Write(f); err != nil {
			f.Close()
			return err
		}
		if err := f.Chmod(0o644); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		return os.Rename(f.Name(), path)
	}()
	if err != nil {
		d.log.Warn("could not write the list of an RTR cache's differences", "file", path, "error", err)
		return
	}
	l := job.list
	d.log.Info("wrote the list of an RTR cache's differences", "file", path, "cache", l.Cache, "reason", l.Reason,
		"items", l.Len(), "counts", l.Counts, "settling", l.Settling)
}

// close writes what is waiting and stops the writer. Lists handed to accept
// after it are dropped.
func (d *divergenceFiles) close() {
	d.mu.Lock()
	if !d.closed {
		d.closed = true
		close(d.queue)
	}
	d.mu.Unlock()
	<-d.done
}

// watchListSignals asks for listSignals (SIGUSR1) and returns the channel
// they arrive on and a function that stops asking. From then on the signal
// no longer ends the process, which is Go's default for it.
func watchListSignals() (<-chan os.Signal, func()) {
	if len(listSignals) == 0 {
		return nil, func() {}
	}
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, listSignals...)
	return ch, func() { signal.Stop(ch) }
}

// listOnSignal makes the full list of every compared cache's differences
// each time a signal arrives on sigs (watchListSignals), until ctx is done.
// cmp is nil with one cache, and files false without --divergence-dir: the
// signal is then answered with a log line.
func listOnSignal(ctx context.Context, sigs <-chan os.Signal, cmp *telemetry.CrossCache, files bool, log *slog.Logger) {
	for {
		select {
		case <-ctx.Done():
			return
		case sig := <-sigs:
			switch {
			case cmp == nil:
				log.Warn("nothing to list: one cache is monitored, so there are no differences between caches", "signal", sig.String())
			case !files:
				log.Warn("nothing to list: no --divergence-dir to write the differences between the caches to", "signal", sig.String())
			default:
				if n := cmp.ListAll(telemetry.ListOnSignal); n == 0 {
					log.Warn("nothing to list: fewer than two caches are compared now", "signal", sig.String())
				} else {
					log.Info("listing the differences of every compared cache", "signal", sig.String(), "caches", n)
				}
			}
		}
	}
}
