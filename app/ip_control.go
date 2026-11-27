package app

import (
	"context"

	"github.com/alireza0/s-ui/antiabuse/engine"
	ipcontrol "github.com/alireza0/s-ui/antiabuse/panel"
	ipruntime "github.com/alireza0/s-ui/antiabuse/runtime"
	"github.com/alireza0/s-ui/core"
	"github.com/alireza0/s-ui/core/connectionpolicy"
	"github.com/alireza0/s-ui/database"
	"github.com/alireza0/s-ui/nodes"
)

type ipControlState struct {
	runtime    *ipruntime.Runtime
	controller *ipcontrol.Controller
	cancel     context.CancelFunc
}

func (a *APP) initIPControl() error {
	runtime, err := ipruntime.New(engine.DefaultProfile(), nil)
	if err != nil {
		return err
	}
	a.core = core.NewCoreWithContext(connectionpolicy.WithGuard(context.Background(), runtime))
	a.ipControl = &ipControlState{runtime: runtime}
	return nil
}

func (a *APP) startIPControl() error {
	// Ordinary restore replaces the database handle before restarting APP.
	// Bind a fresh controller to it instead of restarting a closed store.
	return a.ipControl.start(ipcontrol.NewStore(database.GetDB()), a.core.IsRunning)
}

func (state *ipControlState) start(store *ipcontrol.Store, ready func() bool) error {
	controller, err := ipcontrol.NewController(store, state.runtime, nodes.IPTransport{}, ready)
	if err != nil {
		return err
	}
	state.controller = controller
	ipcontrol.Register(controller)
	state.cancel = controller.Start(context.Background())
	return nil
}

func (a *APP) stopIPControl() {
	if a.ipControl != nil {
		a.ipControl.stop()
	}
}

func (state *ipControlState) stop() {
	if state.cancel != nil {
		state.cancel()
		state.cancel = nil
	}
	ipcontrol.Unregister(state.controller)
}
