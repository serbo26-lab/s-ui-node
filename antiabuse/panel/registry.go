package panel

import (
	"sync/atomic"

	ipmodel "github.com/alireza0/s-ui/antiabuse/model"
)

var active atomic.Pointer[Controller]

func Register(controller *Controller) { active.Store(controller) }
func Current() *Controller            { return active.Load() }
func Unregister(controller *Controller) {
	active.CompareAndSwap(controller, nil)
}

func Notify() {
	if controller := Current(); controller != nil {
		controller.Notify()
	}
}

func (c *Controller) Configuration() (Configuration, error) { return c.store.Configuration() }
func (c *Controller) GroupNames() ([]string, error)         { return c.store.GroupNames() }
func (c *Controller) Events(before uint64, limit int) ([]ipmodel.Event, error) {
	return c.store.Events(before, limit)
}

func (c *Controller) Scope() string {
	if w := c.view.Load(); w != nil {
		return w.scope
	}
	return ""
}
