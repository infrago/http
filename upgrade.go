package http

import (
	"errors"

	. "github.com/infrago/base"
	"github.com/infrago/ws"
)

func (ctx *Context) Upgrade() error {
	if ctx == nil {
		return errors.New("invalid http context")
	}
	if ctx.upgraded {
		return nil
	}
	if ctx.inst == nil || ctx.inst.connect == nil {
		return errors.New("invalid http connection")
	}

	conn, err := ctx.inst.connect.Upgrade(ctx.writer, ctx.reader)
	if err != nil {
		return err
	}

	ctx.upgraded = true
	ctx.Code = StatusSwitchingProtocols
	ctx.clearBody()
	ctx.Body = nil

	return ws.Accept(ws.AcceptOptions{
		Conn:       conn,
		Meta:       ctx.Meta,
		Name:       ctx.Name,
		Site:       ctx.Site,
		Host:       ctx.Host,
		Domain:     ctx.Domain,
		RootDomain: ctx.RootDomain,
		Path:       ctx.Path,
		Uri:        ctx.Uri,
		Setting:    cloneContextMap(ctx.Setting),
		Params:     cloneContextMap(ctx.Params),
		Query:      cloneContextMap(ctx.Query),
		Form:       cloneContextMap(ctx.Form),
		Value:      cloneContextMap(ctx.Value),
		Args:       cloneContextMap(ctx.Args),
		Locals:     cloneContextMap(ctx.Locals),
	})
}

func cloneContextMap(src Map) Map {
	if len(src) == 0 {
		return Map{}
	}

	dst := make(Map, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}
