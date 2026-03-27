package http

import (
	"errors"
	"strings"

	"github.com/infrago/infra"
)

func (ctx *Context) Upgrade(names ...string) error {
	if ctx == nil {
		return errors.New("invalid http context")
	}
	if ctx.upgraded {
		return nil
	}
	if ctx.inst == nil || ctx.inst.connect == nil {
		return errors.New("invalid http connection")
	}

	endpointName := infra.DEFAULT
	if len(names) > 0 && strings.TrimSpace(names[0]) != "" {
		endpointName = strings.ToLower(strings.TrimSpace(names[0]))
	}

	endpoint, ok := module.endpoint(endpointName)
	accept, loaded := infra.LoadUpgradeAcceptor(endpointName)
	if (!ok || endpoint.Accept == nil) && !loaded {
		return errors.New("invalid http upgrade endpoint")
	}

	conn, err := ctx.inst.connect.Upgrade(ctx.writer, ctx.reader)
	if err != nil {
		return err
	}

	ctx.upgraded = true
	ctx.Code = StatusSwitchingProtocols
	ctx.clearBody()
	ctx.Body = nil

	if ok && endpoint.Accept != nil {
		return endpoint.Accept(ctx, conn)
	}
	if loaded {
		return accept(infra.UpgradeAcceptOptions{
			Socket:     conn,
			Meta:       ctx.Meta,
			Name:       ctx.Name,
			Site:       ctx.Site,
			Host:       ctx.Host,
			Domain:     ctx.Domain,
			RootDomain: ctx.RootDomain,
			Path:       ctx.Path,
			Uri:        ctx.Uri,
			Setting:    ctx.Setting,
			Params:     ctx.Params,
			Query:      ctx.Query,
			Form:       ctx.Form,
			Value:      ctx.Value,
			Args:       ctx.Args,
			Locals:     ctx.Locals,
		})
	}
	return errors.New("invalid http upgrade endpoint")
}
