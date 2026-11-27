package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	ipcontrol "github.com/alireza0/s-ui/antiabuse/panel"
	"github.com/gin-gonic/gin"
)

const ipControlContextKey = "ip_control_controller"

func ipController(ctx *gin.Context) *ipcontrol.Controller {
	return ctx.MustGet(ipControlContextKey).(*ipcontrol.Controller)
}

func registerIPControlRoutes(group *gin.RouterGroup) {
	routes := group.Group("/antiabuse")
	routes.Use(func(ctx *gin.Context) {
		controller := ipcontrol.Current()
		if controller == nil {
			jsonObj(ctx, nil, ipcontrol.ErrUnavailable)
			ctx.Abort()
			return
		}
		ctx.Set(ipControlContextKey, controller)
	})
	routes.GET("/settings", func(ctx *gin.Context) {
		value, err := ipController(ctx).Configuration()
		jsonObj(ctx, value, err)
	})
	routes.POST("/settings", saveIPControlSettings)
	routes.GET("/groups", func(ctx *gin.Context) {
		value, err := ipController(ctx).GroupNames()
		jsonObj(ctx, value, err)
	})
	routes.GET("/clients", ipControlClients)
	routes.GET("/events", ipControlEvents)
}

func saveIPControlSettings(ctx *gin.Context) {
	ctx.Request.Body = http.MaxBytesReader(ctx.Writer, ctx.Request.Body, 1<<20)
	decoder := json.NewDecoder(ctx.Request.Body)
	decoder.DisallowUnknownFields()
	var value ipcontrol.Configuration
	if decoder.Decode(&value) != nil || decoder.Decode(new(any)) != io.EOF {
		jsonObj(ctx, nil, ipcontrol.ErrInvalid)
		return
	}
	saved, err := ipController(ctx).SaveConfiguration(value)
	jsonObj(ctx, saved, err)
}

func ipControlClients(ctx *gin.Context) {
	parts := strings.Split(ctx.Query("ids"), ",")
	if len(parts) > 1000 {
		jsonObj(ctx, nil, ipcontrol.ErrInvalid)
		return
	}
	ids := make([]uint, 0, len(parts))
	for _, part := range parts {
		id, err := strconv.ParseUint(part, 10, 32)
		if err != nil || id == 0 {
			jsonObj(ctx, nil, ipcontrol.ErrInvalid)
			return
		}
		ids = append(ids, uint(id))
	}
	jsonObj(ctx, ipController(ctx).Status(ids), nil)
}

func ipControlEvents(ctx *gin.Context) {
	before, limit := uint64(0), uint64(100)
	var err error
	if raw := ctx.Query("before"); raw != "" {
		before, err = strconv.ParseUint(raw, 10, 64)
		if err != nil {
			jsonObj(ctx, nil, ipcontrol.ErrInvalid)
			return
		}
	}
	if raw := ctx.Query("limit"); raw != "" {
		limit, err = strconv.ParseUint(raw, 10, 32)
		if err != nil || limit == 0 || limit > 200 {
			jsonObj(ctx, nil, ipcontrol.ErrInvalid)
			return
		}
	}
	value, err := ipController(ctx).Events(before, int(limit))
	jsonObj(ctx, value, err)
}
