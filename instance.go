package http

import (
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/bamgoo/bamgoo"
	. "github.com/bamgoo/base"
)

func (inst *Instance) newContext() *Context {
	return &Context{
		inst:        inst,
		Meta:        bamgoo.NewMeta(),
		uploadfiles: make([]string, 0),
		headers:     make(map[string]string, 0),
		cookies:     make(map[string]http.Cookie, 0),
		charset:     UTF8,
		Params:      Map{},
		Query:       Map{},
		Form:        Map{},
		Upload:      Map{},
		Value:       Map{},
		Args:        Map{},
		Locals:      Map{},
		Data:        Map{},
		Setting:     Map{},
	}
}

func (inst *Instance) close(ctx *Context) {
	for _, file := range ctx.uploadfiles {
		os.Remove(file)
	}
}

// Serve handles incoming HTTP request.
func (inst *Instance) Serve(name string, params Map, res http.ResponseWriter, req *http.Request) {
	ctx := inst.newContext()

	ctx.reader = req
	ctx.writer = res

	if info, ok := inst.routerInfos[name]; ok {
		ctx.Name = info.Router
		if cfg, ok := inst.routers[ctx.Name]; ok {
			ctx.Config = cfg
			ctx.Setting = cfg.Setting
		}
	}

	ctx.Params = params
	ctx.Method = strings.ToUpper(ctx.reader.Method)
	ctx.Uri = ctx.reader.RequestURI
	ctx.Path = ctx.reader.URL.Path

	if strings.Contains(ctx.reader.Host, ":") {
		host, _, err := net.SplitHostPort(ctx.reader.Host)
		if err == nil {
			ctx.Host = host
		}
	} else {
		ctx.Host = ctx.reader.Host
	}

	inst.open(ctx)
	inst.close(ctx)
}

func (inst *Instance) open(ctx *Context) {
	ctx.clear()

	ctx.next(inst.preprocessing)
	ctx.next(inst.serveFilters...)
	ctx.next(inst.serve)

	ctx.Next()
}

func (inst *Instance) serve(ctx *Context) {
	ctx.clear()

	ctx.next(inst.finding)
	ctx.next(inst.requestFilters...)
	ctx.next(inst.request)

	ctx.Next()

	inst.response(ctx)
}

func (inst *Instance) request(ctx *Context) {
	ctx.clear()

	ctx.next(inst.crossing)
	ctx.next(inst.parsing)
	ctx.next(inst.authorizing)
	ctx.next(inst.arguing)
	ctx.next(inst.execute)

	ctx.Next()
}

func (inst *Instance) execute(ctx *Context) {
	ctx.clear()

	ctx.next(inst.executeFilters...)
	if ctx.Config.Actions != nil && len(ctx.Config.Actions) > 0 {
		ctx.next(ctx.Config.Actions...)
	}
	if ctx.Config.Action != nil {
		ctx.next(ctx.Config.Action)
	}

	ctx.Next()
}

func (inst *Instance) response(ctx *Context) {
	ctx.clear()

	ctx.next(inst.responseFilters...)
	ctx.Next()

	inst.body(ctx)
}

func (inst *Instance) found(ctx *Context) {
	ctx.clear()

	if ctx.Code <= 0 {
		ctx.Code = StatusNotFound
	}

	if ctx.Config.Found != nil {
		ctx.next(ctx.Config.Found)
	}
	ctx.next(inst.foundHandlers...)
	ctx.next(inst.foundDefault)

	ctx.Next()
}

func (inst *Instance) foundDefault(ctx *Context) {
	ctx.Text("Not Found", StatusNotFound)
}

func (inst *Instance) error(ctx *Context) {
	ctx.clear()

	if ctx.Code <= 0 {
		ctx.Code = StatusInternalServerError
	}

	if ctx.Config.Error != nil {
		ctx.next(ctx.Config.Error)
	}
	ctx.next(inst.errorHandlers...)
	ctx.next(inst.errorDefault)

	ctx.Next()
}

func (inst *Instance) errorDefault(ctx *Context) {
	ctx.Text("Internal Server Error", StatusInternalServerError)
}

func (inst *Instance) failed(ctx *Context) {
	ctx.clear()

	if ctx.Code <= 0 {
		ctx.Code = StatusBadRequest
	}

	if ctx.Config.Failed != nil {
		ctx.next(ctx.Config.Failed)
	}
	ctx.next(inst.failedHandlers...)
	ctx.next(inst.failedDefault)

	ctx.Next()
}

func (inst *Instance) failedDefault(ctx *Context) {
	ctx.Text("Bad Request", StatusBadRequest)
}

func (inst *Instance) denied(ctx *Context) {
	ctx.clear()

	if ctx.Code <= 0 {
		ctx.Code = StatusUnauthorized
	}

	if ctx.Config.Denied != nil {
		ctx.next(ctx.Config.Denied)
	}
	ctx.next(inst.deniedHandlers...)
	ctx.next(inst.deniedDefault)

	ctx.Next()
}

func (inst *Instance) deniedDefault(ctx *Context) {
	ctx.Text("Unauthorized", StatusUnauthorized)
}
