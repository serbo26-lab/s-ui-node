package nodeagent

import (
	"math"

	"github.com/gofrs/uuid/v5"
)

// A cumulative sample can be read by multiple controllers without draining
// their data. The process ID distinguishes natural resets after a restart.
type TrafficSample struct {
	Process string `json:"process"`
	Up      int64  `json:"up"`
	Down    int64  `json:"down"`
}

func (r *CoreRuntime) collectTraffic() {
	box := r.core.GetInstance()
	if box == nil || box.SessionTracker() == nil {
		return
	}
	for _, row := range *box.SessionTracker().GetStats() {
		if row.Resource != "inbound" {
			continue
		}
		value := &r.traffic.Down
		if row.Direction {
			value = &r.traffic.Up
		}
		*value += min(row.Traffic, math.MaxInt64-*value)
	}
}

func (r *CoreRuntime) Traffic() *TrafficSample {
	if !r.mu.TryLock() {
		return nil
	}
	defer r.mu.Unlock()
	if r.traffic.Process == "" {
		id, err := uuid.NewV4()
		if err != nil {
			return nil
		}
		r.traffic.Process = id.String()
	}
	r.collectTraffic()
	sample := r.traffic
	return &sample
}
