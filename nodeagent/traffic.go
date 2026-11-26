package nodeagent

import (
	"encoding/json"
	"maps"
	"math"
	"time"

	"github.com/gofrs/uuid/v5"
)

// A cumulative sample can be read by multiple controllers without draining
// their data. The process ID distinguishes natural resets after a restart.
type TrafficSample struct {
	Process  string           `json:"process"`
	Up       int64            `json:"up"`
	Down     int64            `json:"down"`
	Activity map[string]int64 `json:"activity,omitempty"`
}

func (r *CoreRuntime) collectTraffic() {
	box := r.core.GetInstance()
	if box == nil || box.SessionTracker() == nil {
		return
	}
	for _, row := range *box.SessionTracker().GetStats() {
		if row.Resource == "user" && row.Traffic > 0 {
			if r.traffic.Activity == nil {
				r.traffic.Activity = map[string]int64{}
			}
			r.traffic.Activity[row.Tag] = max(r.traffic.Activity[row.Tag], row.DateTime)
		}
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
	sample.Activity = maps.Clone(r.traffic.Activity)
	return &sample
}

// Sample independently of control requests, including while the panel is offline.
func (r *CoreRuntime) SampleTraffic() {
	if !r.mu.TryLock() {
		return
	}
	defer r.mu.Unlock()
	r.collectTraffic()
}

func (r *CoreRuntime) pruneActivity() {
	if len(r.traffic.Activity) == 0 {
		return
	}
	var config struct {
		Inbounds []struct {
			Users []struct {
				Name     string `json:"name"`
				Username string `json:"username"`
			} `json:"users"`
		} `json:"inbounds"`
	}
	if json.Unmarshal(r.config, &config) != nil {
		return
	}
	allowed := map[string]bool{}
	for _, inbound := range config.Inbounds {
		for _, user := range inbound.Users {
			allowed[user.Name], allowed[user.Username] = true, true
		}
	}
	for user, at := range r.traffic.Activity {
		if !allowed[user] || at < time.Now().Add(-7*24*time.Hour).Unix() {
			delete(r.traffic.Activity, user)
		}
	}
}
