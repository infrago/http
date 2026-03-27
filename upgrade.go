package http

import (
	"errors"
	"strings"

	"github.com/infrago/infra"
	"github.com/infrago/ws"
)

func (ctx *Context) Upgrade(spaces ...string) error {
	if ctx == nil {
		return errors.New("invalid http context")
	}
	if ctx.upgraded {
		return nil
	}
	if ctx.inst == nil || ctx.inst.connect == nil {
		return errors.New("invalid http connection")
	}

	space := strings.TrimSpace(strings.ToLower(ctx.Name))
	if space == "" {
		space = infra.DEFAULT
	}
	if len(spaces) > 0 && strings.TrimSpace(spaces[0]) != "" {
		space = strings.ToLower(strings.TrimSpace(spaces[0]))
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
		Space:      space,
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
