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

func (a *APP) initIPControl() error {
	runtime, err := ipruntime.New(engine.DefaultProfile(), nil)
	if err != nil {
		return err
	}
	a.core = core.NewCoreWithContext(connectionpolicy.WithGuard(context.Background(), runtime))
	a.ipControl, err = ipcontrol.NewController(ipcontrol.NewStore(database.GetDB()), runtime,
		nodes.IPTransport{}, func() bool { return a.core.IsRunning() })
	if err != nil {
		return err
	}
	ipcontrol.Register(a.ipControl)
	return nil
}
