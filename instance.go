package http

import (
	"net"
	"net/http"
	"os"
	"strings"

	. "github.com/infrago/base"
	"github.com/infrago/infra"
)

func (inst *Instance) newContext() *Context {
	return &Context{
		inst:        inst,
		Meta:        infra.NewMeta(),
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
	out := wrapResponseWriter(res)

	ctx.reader = req
	ctx.writer = out
	ctx.output = out

	if info, ok := inst.routerInfos[name]; ok {
		if info.Entry != "" {
			ctx.Name = info.Entry
		} else {
			ctx.Name = info.Router
		}
		if cfg, ok := inst.routers[ctx.Name]; ok {
			ctx.Config = cfg
			ctx.Setting = cfg.Setting
		} else if cfg, ok := inst.routers[info.Router]; ok {
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
	ctx.Site = contextSiteName(inst.Name)
	ctx.Domain = contextDomain(ctx.Host)
	ctx.RootDomain = contextRootDomain(ctx.Host)

	span := ctx.Begin("http:"+ctx.Name, infra.TraceAttrs("infrago", infra.TraceKindHTTP, ctx.Name, Map{
		"module":    "http",
		"operation": "serve",
		"method":    ctx.Method,
		"path":      ctx.Path,
		"host":      ctx.Host,
	}))
	ctx.Header("traceparent", ctx.TraceParent())
	defer func() {
		if ctx.Code >= StatusInternalServerError {
			span.End(infra.Fail.With("http status %d", ctx.Code))
			return
		}
		if res := ctx.Result(); res != nil && res.Fail() {
			span.End(res)
			return
		}
		span.End()
	}()

	inst.open(ctx)
	if ctx.output != nil && ctx.output.Committed() {
		ctx.Code = ctx.output.Status()
	}
	inst.close(ctx)
}

func contextSiteName(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	if name == "" || name == strings.ToLower(infra.DEFAULT) {
		return ""
	}
	return name
}

func contextDomain(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return ""
	}
	if strings.Contains(host, ":") {
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		return ""
	}
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return host
	}
	return strings.Join(parts[1:], ".")
}

func contextRootDomain(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return ""
	}
	if strings.Contains(host, ":") {
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		return ""
	}
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return host
	}
	return strings.Join(parts[len(parts)-2:], ".")
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

	ctx.next(inst.crossing)
	ctx.next(inst.finding)
	ctx.next(inst.requestFilters...)
	ctx.next(inst.request)

	ctx.Next()

	inst.handle(ctx)
	inst.response(ctx)
}

func (inst *Instance) handle(ctx *Context) {
	handling := ctx.handling
	ctx.handling = ""
	switch handling {
	case "notfound":
		inst.notFound(ctx)
	case "error":
		inst.error(ctx)
	case "failed":
		inst.failed(ctx)
	case "unsigned":
		inst.unsigned(ctx)
	case "unauthed":
		inst.unauthed(ctx)
	case "denied":
		inst.denied(ctx)
	}
}

func (inst *Instance) request(ctx *Context) {
	ctx.clear()

	ctx.next(inst.parsing)
	ctx.next(inst.authorizing)
	ctx.next(inst.arguing)
	ctx.next(inst.loading)
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
	if ctx.upgraded {
		return
	}

	ctx.clear()

	ctx.next(inst.responseFilters...)
	ctx.next(inst.body)
	ctx.Next()
}

func (inst *Instance) notFound(ctx *Context) {
	ctx.clear()

	if ctx.Code <= 0 {
		ctx.Code = StatusNotFound
	}

	if ctx.Config.NotFound != nil {
		ctx.next(ctx.Config.NotFound)
	}
	ctx.next(inst.notFoundHandlers...)
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

func (inst *Instance) unsigned(ctx *Context) {
	ctx.clear()

	if ctx.Code <= 0 {
		ctx.Code = StatusUnauthorized
	}

	if ctx.Config.Unsigned != nil {
		ctx.next(ctx.Config.Unsigned)
	}
	ctx.next(inst.unsignedHandlers...)
	ctx.next(inst.deniedHandlers...)
	ctx.next(inst.deniedDefault)

	ctx.Next()
}

func (inst *Instance) unauthed(ctx *Context) {
	ctx.clear()

	if ctx.Code <= 0 {
		ctx.Code = StatusUnauthorized
	}

	if ctx.Config.Unauthed != nil {
		ctx.next(ctx.Config.Unauthed)
	}
	ctx.next(inst.unauthedHandlers...)
	ctx.next(inst.deniedHandlers...)
	ctx.next(inst.deniedDefault)

	ctx.Next()
}

func (inst *Instance) deniedDefault(ctx *Context) {
	ctx.Text("Unauthorized", StatusUnauthorized)
}
