package web

import (
	"context"
	"sync"
	"time"
)

// job est un audit en cours d'exécution.
type job struct {
	Site    string
	AuditID int64
	Started time.Time

	mu     sync.Mutex
	Phase  string
	Done   int
	Total  int
	Status string // running, done, failed, cancelled
	Err    string
	cancel context.CancelFunc
}

type jobSnapshot struct {
	Site    string `json:"site"`
	AuditID int64  `json:"audit"`
	Phase   string `json:"phase"`
	Done    int    `json:"done"`
	Total   int    `json:"total"`
	Status  string `json:"status"`
	Error   string `json:"error,omitempty"`
	Elapsed int    `json:"elapsed"` // secondes
}

func (j *job) snapshot() jobSnapshot {
	j.mu.Lock()
	defer j.mu.Unlock()
	return jobSnapshot{Site: j.Site, AuditID: j.AuditID, Phase: j.Phase, Done: j.Done, Total: j.Total,
		Status: j.Status, Error: j.Err, Elapsed: int(time.Since(j.Started).Seconds())}
}

func (j *job) progress(phase string, done, total int) {
	j.mu.Lock()
	j.Phase, j.Done, j.Total = phase, done, total
	j.mu.Unlock()
}

func (j *job) finish(status string, err error) {
	j.mu.Lock()
	j.Status = status
	if err != nil {
		j.Err = err.Error()
	}
	j.mu.Unlock()
}

// jobs : un seul audit à la fois, pour ne jamais cumuler la charge réseau.
type jobs struct {
	mu      sync.Mutex
	current *job
	byKey   map[string]*job
}

func newJobs() *jobs { return &jobs{byKey: map[string]*job{}} }

func key(site string, id int64) string { return site + "#" + itoa64(id) }

// running renvoie l'audit en cours, s'il y en a un.
func (js *jobs) running() *job {
	js.mu.Lock()
	defer js.mu.Unlock()
	if js.current != nil && js.current.snapshot().Status == "running" {
		return js.current
	}
	return nil
}

func (js *jobs) add(j *job) {
	js.mu.Lock()
	defer js.mu.Unlock()
	js.current = j
	js.byKey[key(j.Site, j.AuditID)] = j
}

func (js *jobs) get(site string, id int64) *job {
	js.mu.Lock()
	defer js.mu.Unlock()
	return js.byKey[key(site, id)]
}

func (js *jobs) cancelAll() {
	js.mu.Lock()
	defer js.mu.Unlock()
	for _, j := range js.byKey {
		if j.cancel != nil {
			j.cancel()
		}
	}
}
